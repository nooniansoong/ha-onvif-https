"""ONVIF-over-HTTPS integration: background PullPoint loop → HA events + sensors."""
from __future__ import annotations

import asyncio
import logging
import time

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .client import NotAuthorized, OnvifHttpsClient, OnvifHttpsError
from .const import (
    CONF_OFF_DELAY,
    CONF_VERIFY_SSL,
    DEFAULT_OFF_DELAY,
    DEFAULT_PORT,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    EVENT_RECEIVED,
    SIGNAL_EVENT,
)

_LOGGER = logging.getLogger(__name__)
PLATFORMS = ["binary_sensor"]
RENEW_EVERY = 1800  # seconds


class OnvifHttpsRuntime:
    def __init__(self, hass, entry, client):
        self.hass = hass
        self.entry = entry
        self.client = client
        self.off_delay = entry.data.get(CONF_OFF_DELAY, DEFAULT_OFF_DELAY)
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    def start(self):
        self._task = self.entry.async_create_background_task(
            self.hass, self._run(), name=f"{DOMAIN}_pull_{self.entry.entry_id}"
        )

    async def async_stop(self):
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        session = async_get_clientsession(self.hass)
        await self.client.async_unsubscribe(session)

    async def _run(self):
        session = async_get_clientsession(self.hass)
        backoff = 5
        last_renew = 0.0
        while not self._stop.is_set():
            try:
                if self.client._sub is None:  # noqa: SLF001 - internal state check
                    await self.client.async_create_subscription(session)
                    last_renew = time.monotonic()
                    _LOGGER.info("%s: PullPoint subscription established", DOMAIN)

                notifications = await self.client.async_pull(session)
                backoff = 5
                for n in notifications:
                    self._dispatch(n)

                if time.monotonic() - last_renew > RENEW_EVERY:
                    try:
                        await self.client.async_renew(session)
                        last_renew = time.monotonic()
                    except OnvifHttpsError:
                        self.client.reset_subscription()

            except asyncio.CancelledError:
                break
            except NotAuthorized:
                _LOGGER.error("%s: credentials rejected; stopping pull loop", DOMAIN)
                break
            except Exception as err:  # noqa: BLE001 - keep the loop alive
                _LOGGER.warning("%s: pull error (%s); retry in %ss", DOMAIN, err, backoff)
                self.client.reset_subscription()
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, 60)

    def _dispatch(self, n: dict):
        payload = {"entry_id": self.entry.entry_id, **n}
        # 1) HA event bus — automate on this immediately.
        self.hass.bus.async_fire(EVENT_RECEIVED, payload)
        # 2) dispatcher — drives/creates binary_sensor entities.
        async_dispatcher_send(self.hass, f"{SIGNAL_EVENT}_{self.entry.entry_id}", n)
        _LOGGER.debug("%s event: %s", DOMAIN, payload)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    client = OnvifHttpsClient(
        host=entry.data[CONF_HOST],
        port=entry.data.get(CONF_PORT, DEFAULT_PORT),
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        verify_ssl=entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
    )
    session = async_get_clientsession(hass)
    try:
        await client.async_test(session)
    except NotAuthorized as err:
        raise ConfigEntryAuthFailed("ONVIF credentials rejected") from err
    except Exception as err:  # noqa: BLE001
        raise ConfigEntryNotReady(f"Cannot reach ONVIF device: {err}") from err

    runtime = OnvifHttpsRuntime(hass, entry, client)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = runtime

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    runtime.start()
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    runtime: OnvifHttpsRuntime = hass.data[DOMAIN].pop(entry.entry_id, None)
    if runtime:
        await runtime.async_stop()
    return unloaded
