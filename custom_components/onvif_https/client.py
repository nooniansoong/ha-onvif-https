"""Minimal async ONVIF-over-HTTPS client (events + device info).

Deliberately does NOT use onvif-zeep: that library (and HA core's ONVIF
integration) talk plain HTTP and blindly follow the device's advertised
XAddrs. This device serves ONVIF only over HTTPS (TLS multiplexed on
port 80) and advertises *http://* XAddrs it then refuses. We therefore
hand-build every SOAP request, always target https://host:port, and
rewrite the subscription reference the device returns.
"""
from __future__ import annotations

import base64
import hashlib
import os
import ssl
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse
from xml.etree import ElementTree as ET

import aiohttp

WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
PWD = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
B64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"

A_GETDEVINFO = "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"
A_GETEVPROPS = "http://www.onvif.org/ver10/events/wsdl/EventPortType/GetEventPropertiesRequest"
A_CREATEPULL = "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest"
A_PULL = "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest"
A_RENEW = "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest"
A_UNSUB = "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest"


class OnvifHttpsError(Exception):
    """Any client-level failure."""


class NotAuthorized(OnvifHttpsError):
    """Bad username/password."""


def _local(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


class OnvifHttpsClient:
    def __init__(self, host, port, username, password, verify_ssl=False):
        self._host = host
        self._port = int(port)
        self._user = username
        self._pass = password
        self._base = f"https://{host}:{self._port}/onvif"
        self._dev = f"{self._base}/device_service"
        self._events = f"{self._base}/events_service"
        self._sub: str | None = None

        if verify_ssl:
            self._ssl: ssl.SSLContext | bool = True
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._ssl = ctx

    # ---- envelope helpers -------------------------------------------------
    def _security(self) -> str:
        nonce = os.urandom(16)
        created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        digest = base64.b64encode(
            hashlib.sha1(nonce + created.encode() + self._pass.encode()).digest()
        ).decode()
        return (
            f'<wsse:Security xmlns:wsse="{WSSE}" xmlns:wsu="{WSU}" s:mustUnderstand="1">'
            f"<wsse:UsernameToken><wsse:Username>{self._user}</wsse:Username>"
            f'<wsse:Password Type="{PWD}">{digest}</wsse:Password>'
            f'<wsse:Nonce EncodingType="{B64}">{base64.b64encode(nonce).decode()}</wsse:Nonce>'
            f"<wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security>"
        )

    def _envelope(self, action: str, to: str, body_inner: str) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:wsa="http://www.w3.org/2005/08/addressing"'
            ' xmlns:tev="http://www.onvif.org/ver10/events/wsdl"'
            ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
            ' xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"'
            ' xmlns:tt="http://www.onvif.org/ver10/schema">'
            f"<s:Header>{self._security()}"
            f"<wsa:Action>{action}</wsa:Action>"
            f"<wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>"
            f"<wsa:To>{to}</wsa:To></s:Header>"
            f"<s:Body>{body_inner}</s:Body></s:Envelope>"
        )

    async def _post(self, session, url, action, body_inner, timeout=30) -> str:
        headers = {"Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"'}
        data = self._envelope(action, url, body_inner).encode("utf-8")
        async with session.post(
            url, data=data, headers=headers, ssl=self._ssl,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            text = await resp.text()
        if "NotAuthorized" in text or "not authorized" in text.lower():
            raise NotAuthorized("ONVIF rejected the credentials")
        return text

    def _normalize_sub(self, addr: str) -> str:
        p = urlparse(addr)
        return urlunparse(("https", f"{self._host}:{self._port}", p.path, p.params, p.query, p.fragment))

    # ---- public operations ------------------------------------------------
    async def async_test(self, session) -> dict:
        """Auth-gated call; raises NotAuthorized on bad creds."""
        text = await self._post(session, self._dev, A_GETDEVINFO, "<tds:GetDeviceInformation/>")
        root = ET.fromstring(text)
        return {
            _local(e.tag): (e.text or "")
            for e in root.iter()
            if _local(e.tag) in ("Manufacturer", "Model", "FirmwareVersion", "SerialNumber")
        }

    async def async_get_topics(self, session) -> list[str]:
        text = await self._post(session, self._events, A_GETEVPROPS, "<tev:GetEventProperties/>")
        root = ET.fromstring(text)
        topics: list[str] = []

        def walk(el, path):
            kids = list(el)
            has_msg = any(_local(k.tag) in ("MessageDescription", "message") for k in kids)
            if has_msg and path:
                topics.append(path)
            for k in kids:
                ln = _local(k.tag)
                if ln in ("MessageDescription", "message"):
                    continue
                walk(k, f"{path}/{ln}" if path else ln)

        for e in root.iter():
            if _local(e.tag) == "TopicSet":
                walk(e, "")
                break
        return sorted(set(topics))

    async def async_create_subscription(self, session) -> str:
        text = await self._post(
            session, self._events, A_CREATEPULL,
            "<tev:CreatePullPointSubscription>"
            "<tev:InitialTerminationTime>PT3600S</tev:InitialTerminationTime>"
            "</tev:CreatePullPointSubscription>",
        )
        root = ET.fromstring(text)
        for e in root.iter():
            if _local(e.tag) == "Address" and e.text and "/onvif/" in e.text:
                self._sub = self._normalize_sub(e.text.strip())
                return self._sub
        raise OnvifHttpsError("no SubscriptionReference in CreatePullPointSubscription response")

    async def async_pull(self, session, timeout_iso="PT25S", limit=100) -> list[dict]:
        """Long-poll one batch of notifications. Returns list of dicts."""
        if not self._sub:
            await self.async_create_subscription(session)
        text = await self._post(
            session, self._sub, A_PULL,
            f"<tev:PullMessages><tev:Timeout>{timeout_iso}</tev:Timeout>"
            f"<tev:MessageLimit>{limit}</tev:MessageLimit></tev:PullMessages>",
            timeout=40,
        )
        return self._parse_notifications(text)

    async def async_renew(self, session, term="PT3600S") -> None:
        if not self._sub:
            return
        await self._post(
            session, self._sub, A_RENEW,
            f'<wsnt:Renew><wsnt:TerminationTime>{term}</wsnt:TerminationTime></wsnt:Renew>',
        )

    async def async_unsubscribe(self, session) -> None:
        if not self._sub:
            return
        try:
            await self._post(session, self._sub, A_UNSUB, "<wsnt:Unsubscribe/>", timeout=10)
        except Exception:  # noqa: BLE001 - best effort on teardown
            pass
        self._sub = None

    def reset_subscription(self) -> None:
        self._sub = None

    @staticmethod
    def _parse_notifications(text: str) -> list[dict]:
        out: list[dict] = []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return out
        for nm in (e for e in root.iter() if _local(e.tag) == "NotificationMessage"):
            topic = ""
            utc = ""
            source: dict[str, str] = {}
            data: dict[str, str] = {}
            in_data = False
            for e in nm.iter():
                ln = _local(e.tag)
                if ln == "Topic" and e.text:
                    topic = e.text.strip()
                elif ln == "Message" and e.attrib.get("UtcTime"):
                    utc = e.attrib["UtcTime"]
                elif ln == "Data":
                    in_data = True
                elif ln == "Source":
                    in_data = False
                elif ln == "SimpleItem":
                    name = e.attrib.get("Name", "")
                    val = e.attrib.get("Value", "")
                    (data if in_data else source)[name] = val
            active = any(str(v).lower() in ("true", "1", "on") for v in data.values()) or (
                not data and bool(topic)
            )
            channel = (
                source.get("VideoSourceConfigurationToken")
                or source.get("VideoSource")
                or source.get("Channel")
                or source.get("Source")
                or next(iter(source.values()), None)
            )
            out.append(
                {
                    "topic": topic,
                    "name": topic.split("/")[-1] if topic else "event",
                    "utc": utc,
                    "channel": channel,
                    "source": source,
                    "data": data,
                    "active": active,
                }
            )
        return out
