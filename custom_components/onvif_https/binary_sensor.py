"""Dynamic binary_sensors: one per (topic, channel) as events arrive."""
from __future__ import annotations

import logging

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .const import ACTIVE_KEYWORDS, DOMAIN, SIGNAL_EVENT

_LOGGER = logging.getLogger(__name__)


def _slug(topic: str, channel) -> str:
    base = topic.replace("/", "_").replace(":", "_").strip("_").lower() or "event"
    return f"{base}_{channel}" if channel else base


def _device_class(topic: str):
    t = topic.lower()
    if any(k in t for k in ("people", "person", "human", "face")):
        return "occupancy"
    if any(k in t for k in ("motion", "pir")):
        return "motion"
    if "tamper" in t:
        return "tamper"
    if any(k in t for k in ("line", "cross", "field", "intrusion", "region", "object")):
        return "motion"
    return None


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    known: dict[str, "OnvifHttpsEvent"] = {}
    runtime = hass.data[DOMAIN][entry.entry_id]

    @callback
    def _handle(n: dict) -> None:
        topic = n.get("topic") or ""
        # only model topics that look like real events (skip pure heartbeats)
        if topic and not any(k in topic.lower() for k in ACTIVE_KEYWORDS):
            # still allow generic ones that carry boolean data
            if not n.get("data"):
                return
        key = _slug(topic, n.get("channel"))
        ent = known.get(key)
        if ent is None:
            ent = OnvifHttpsEvent(entry, topic, n.get("channel"), runtime.off_delay)
            known[key] = ent
            async_add_entities([ent])
        ent.trigger(bool(n.get("active", True)))

    entry.async_on_unload(
        async_dispatcher_connect(hass, f"{SIGNAL_EVENT}_{entry.entry_id}", _handle)
    )


class OnvifHttpsEvent(BinarySensorEntity):
    _attr_should_poll = False

    def __init__(self, entry: ConfigEntry, topic: str, channel, off_delay: int):
        self._entry = entry
        self._topic = topic
        self._channel = channel
        self._off_delay = off_delay
        self._state = False
        self._cancel = None
        name = topic.split("/")[-1] if topic else "event"
        if channel:
            name = f"{name} ch{channel}"
        self._attr_name = f"ONVIF {name}"
        self._attr_unique_id = f"{entry.entry_id}_{_slug(topic, channel)}"
        self._attr_device_class = _device_class(topic)
        self._attr_extra_state_attributes = {"topic": topic, "channel": channel}
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": entry.title,
            "manufacturer": "ONVIF (HTTPS)",
        }

    @property
    def is_on(self) -> bool:
        return self._state

    @callback
    def trigger(self, active: bool) -> None:
        if self._cancel:
            self._cancel()
            self._cancel = None
        self._state = active
        self.async_write_ha_state()
        if active and self._off_delay:
            @callback
            def _off(_now):
                self._state = False
                self._cancel = None
                self.async_write_ha_state()

            self._cancel = async_call_later(self.hass, self._off_delay, _off)
