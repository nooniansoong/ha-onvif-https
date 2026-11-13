"""Config flow for ONVIF over HTTPS."""
from __future__ import annotations

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .client import NotAuthorized, OnvifHttpsClient
from .const import (
    CONF_OFF_DELAY,
    CONF_VERIFY_SSL,
    DEFAULT_OFF_DELAY,
    DEFAULT_PORT,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)


class OnvifHttpsConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors: dict[str, str] = {}
        if user_input is not None:
            await self.async_set_unique_id(
                f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}"
            )
            self._abort_if_unique_id_configured()
            client = OnvifHttpsClient(
                host=user_input[CONF_HOST],
                port=user_input[CONF_PORT],
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                verify_ssl=user_input[CONF_VERIFY_SSL],
            )
            session = async_get_clientsession(self.hass)
            try:
                info = await client.async_test(session)
            except NotAuthorized:
                errors["base"] = "invalid_auth"
            except Exception:  # noqa: BLE001
                errors["base"] = "cannot_connect"
            else:
                title = info.get("Model") or f"ONVIF {user_input[CONF_HOST]}"
                return self.async_create_entry(title=title, data=user_input)

        schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Required(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
                vol.Required(CONF_OFF_DELAY, default=DEFAULT_OFF_DELAY): int,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
