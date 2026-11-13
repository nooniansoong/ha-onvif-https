#!/usr/bin/env python3
"""
Standalone ONVIF-over-HTTPS event tester  (pure stdlib, no pip needed).

Proves whether your HTTPS-only NVR/camera emits events (line-crossing,
motion, person...) over ONVIF before you install the HA integration.

Usage:
    python3 test_events.py 192.168.10.150 80 admin 'YOURPASS'
    python3 test_events.py 192.168.10.150 80 admin 'YOURPASS' --topics-only

While it runs, walk across your line / wave at the camera. Each event
prints its Topic and the Name=Value data items. Ctrl-C to stop.
"""

import sys, os, ssl, base64, hashlib, uuid
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# ---------------------------------------------------------------- SOAP plumbing
WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
PWD  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
B64  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"


def local(tag):
    return tag.split("}")[-1] if "}" in tag else tag


def security_header(user, password):
    nonce = os.urandom(16)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = base64.b64encode(
        hashlib.sha1(nonce + created.encode() + password.encode()).digest()
    ).decode()
    return f"""<wsse:Security xmlns:wsse="{WSSE}" xmlns:wsu="{WSU}" s:mustUnderstand="1">
  <wsse:UsernameToken>
    <wsse:Username>{user}</wsse:Username>
    <wsse:Password Type="{PWD}">{digest}</wsse:Password>
    <wsse:Nonce EncodingType="{B64}">{base64.b64encode(nonce).decode()}</wsse:Nonce>
    <wsu:Created>{created}</wsu:Created>
  </wsse:UsernameToken>
</wsse:Security>"""


def envelope(user, password, action, to, body_inner):
    msgid = "urn:uuid:" + str(uuid.uuid4())
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://www.w3.org/2005/08/addressing"
            xmlns:tev="http://www.onvif.org/ver10/events/wsdl"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
            xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Header>
    {security_header(user, password)}
    <wsa:Action>{action}</wsa:Action>
    <wsa:MessageID>{msgid}</wsa:MessageID>
    <wsa:To>{to}</wsa:To>
  </s:Header>
  <s:Body>{body_inner}</s:Body>
</s:Envelope>"""


def post(url, action, xml_body, timeout=40):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url, data=xml_body.encode("utf-8"), method="POST",
        headers={"Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"'},
    )
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read().decode("utf-8", "replace")


def normalize_sub(addr, host, port):
    """Device advertises http://<ip>/onvif/Subscription... but only speaks
    HTTPS on our port. Force scheme=https + our host:port, keep path+query."""
    from urllib.parse import urlparse, urlunparse
    p = urlparse(addr)
    return urlunparse(("https", f"{host}:{port}", p.path, p.params, p.query, p.fragment))


# ---------------------------------------------------------------- main
def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)
    host, port, user, password = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    topics_only = "--topics-only" in sys.argv
    base = f"https://{host}:{port}/onvif"
    dev = f"{base}/device_service"
    ev  = f"{base}/events_service"

    # 1) auth check (GetDeviceInformation IS auth-gated)
    print("=== 1. Auth check (GetDeviceInformation) ===")
    try:
        r = post(dev,
                 "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
                 envelope(user, password,
                          "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
                          dev, "<tds:GetDeviceInformation/>"))
    except Exception as e:
        print(f"  request failed: {e}"); sys.exit(2)
    if "NotAuthorized" in r or "Fault" in r and "GetDeviceInformation" not in r:
        print("  ❌ NotAuthorized — wrong username/password for ONVIF.")
        print("     (raw:", r[:300].replace("\n", " "), ")")
        sys.exit(3)
    root = ET.fromstring(r)
    info = {local(e.tag): (e.text or "") for e in root.iter() if local(e.tag) in
            ("Manufacturer", "Model", "FirmwareVersion", "SerialNumber")}
    print("  ✅ AUTHORIZED:", info if info else "(ok)")

    # 2) topic enumeration
    print("\n=== 2. GetEventProperties (topics this device can emit) ===")
    try:
        r = post(ev,
                 "http://www.onvif.org/ver10/events/wsdl/EventPortType/GetEventPropertiesRequest",
                 envelope(user, password,
                          "http://www.onvif.org/ver10/events/wsdl/EventPortType/GetEventPropertiesRequest",
                          ev, "<tev:GetEventProperties/>"))
        # topics appear as element names under TopicSet; print the tree leaf paths
        root = ET.fromstring(r)
        topics = []
        def walk(el, path):
            kids = list(el)
            tset = [k for k in kids if local(k.tag) not in ("MessageDescription", "message")]
            msg = [k for k in kids if local(k.tag) in ("MessageDescription", "message")]
            if msg and path:
                topics.append(path)
            for k in tset:
                if local(k.tag) == "TopicSet":
                    walk(k, path)
                else:
                    walk(k, path + "/" + local(k.tag) if path else local(k.tag))
        for e in root.iter():
            if local(e.tag) == "TopicSet":
                walk(e, ""); break
        if topics:
            for t in sorted(set(topics)):
                mark = "  ⭐" if any(w in t.lower() for w in
                        ("line", "cross", "field", "intrusion", "people", "person",
                         "human", "object", "tamper", "region")) else "   "
                print(f"{mark} {t}")
        else:
            print("  (no TopicSet parsed; raw head:)", r[:400].replace("\n", " "))
    except Exception as e:
        print(f"  GetEventProperties failed (continuing): {e}")

    if topics_only:
        return

    # 3) create pull-point subscription
    print("\n=== 3. CreatePullPointSubscription ===")
    r = post(ev,
             "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest",
             envelope(user, password,
                      "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest",
                      ev, "<tev:CreatePullPointSubscription>"
                          "<tev:InitialTerminationTime>PT3600S</tev:InitialTerminationTime>"
                          "</tev:CreatePullPointSubscription>"))
    root = ET.fromstring(r)
    sub = None
    for e in root.iter():
        if local(e.tag) == "Address" and e.text and "/onvif/" in e.text:
            sub = e.text.strip(); break
    if not sub:
        print("  ❌ no SubscriptionReference returned. raw:", r[:500].replace("\n", " "))
        sys.exit(4)
    sub = normalize_sub(sub, host, port)
    print("  subscription:", sub)

    # 4) pull loop
    print("\n=== 4. Pulling events — WALK YOUR LINE NOW. Ctrl-C to stop. ===\n")
    pull_action = "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest"
    try:
        while True:
            try:
                r = post(sub, pull_action,
                         envelope(user, password, pull_action, sub,
                                  "<tev:PullMessages><tev:Timeout>PT20S</tev:Timeout>"
                                  "<tev:MessageLimit>100</tev:MessageLimit></tev:PullMessages>"),
                         timeout=30)
            except Exception as e:
                print(f"  pull error ({e}); recreating subscription...")
                r2 = post(ev,
                          "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest",
                          envelope(user, password,
                                   "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest",
                                   ev, "<tev:CreatePullPointSubscription>"
                                       "<tev:InitialTerminationTime>PT3600S</tev:InitialTerminationTime>"
                                       "</tev:CreatePullPointSubscription>"))
                for e in ET.fromstring(r2).iter():
                    if local(e.tag) == "Address" and e.text and "/onvif/" in e.text:
                        sub = normalize_sub(e.text.strip(), host, port); break
                continue

            root = ET.fromstring(r)
            got = False
            for nm in [e for e in root.iter() if local(e.tag) == "NotificationMessage"]:
                got = True
                topic = ""
                items = []
                utc = ""
                for e in nm.iter():
                    ln = local(e.tag)
                    if ln == "Topic" and e.text:
                        topic = e.text.strip()
                    elif ln == "Message" and e.attrib.get("UtcTime"):
                        utc = e.attrib["UtcTime"]
                    elif ln == "SimpleItem":
                        items.append(f"{e.attrib.get('Name','?')}={e.attrib.get('Value','?')}")
                print(f"  [{utc or datetime.now().isoformat(timespec='seconds')}] "
                      f"{topic}  |  {', '.join(items)}")
            if not got:
                print("  . (no events this pull)")
    except KeyboardInterrupt:
        print("\nstopping; unsubscribing...")
        try:
            post(sub, "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest",
                 envelope(user, password,
                          "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest",
                          sub, '<wsnt:Unsubscribe xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"/>'),
                 timeout=10)
        except Exception:
            pass
        print("done.")


if __name__ == "__main__":
    main()
