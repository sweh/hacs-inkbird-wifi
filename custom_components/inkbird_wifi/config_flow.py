"""Config flow for INKBIRD WiFi."""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from .const import (
    CONF_COUNTRY_CODE, CONF_DEVICE_ID, CONF_EMAIL, CONF_GOOGLE_SUB,
    CONF_HOST, CONF_LOCAL_KEY, CONF_PASSWORD as CFG_PASSWORD,
    CONF_PRODUCT_ID, CONF_REGION, CONF_VERSION, DEFAULT_VERSION, DOMAIN,
)
from .products import PRODUCTS, is_supported
from .tuya_cloud import (
    DEFAULT_REGION, REGIONS, TuyaCloudError, TuyaDevice, login_and_list_devices,
)

_LOGGER = logging.getLogger(__name__)

REGION_OPTIONS = {k: k.upper() for k in REGIONS}

STEP_CLOUD_SCHEMA = vol.Schema({
    vol.Required(CONF_USERNAME): str,
    vol.Required(CONF_PASSWORD): str,
    vol.Required("country_code", default="49"): str,
    vol.Required("region", default=DEFAULT_REGION): vol.In(REGION_OPTIONS),
})


def _find_lan_ip(dev_id: str) -> str | None:
    """Broadcast scan for the device's LAN IP. Returns None if unreachable."""
    try:
        import tinytuya
        r = tinytuya.find_device(dev_id=dev_id)
        if r and isinstance(r, dict):
            ip = r.get("ip")
            if ip and ip != "0.0.0.0":
                return ip
    except Exception as err:  # noqa: BLE001
        _LOGGER.debug("LAN scan for %s failed: %s", dev_id, err)
    return None


class InkbirdWifiConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._devices: list[TuyaDevice] = []
        self._selected: TuyaDevice | None = None
        # Captured login params used to populate the entry data later
        self._auth_data: dict[str, Any] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        return await self.async_step_cloud()

    async def _finish_login(self, devices: list[TuyaDevice]) -> ConfigFlowResult:
        # Filter to products we have a decoder for. Surface unknown ones in the
        # log so users can ask for support without needing to dig into Tuya cloud.
        supported, unsupported = [], []
        for d in devices:
            (supported if is_supported(d.product_id) else unsupported).append(d)
        for d in unsupported:
            _LOGGER.warning(
                "Skipping device %r (%s): unsupported productId %r. "
                "Open a GitHub issue with this productId to request support.",
                d.name, d.dev_id, d.product_id,
            )
        self._devices = supported
        if not self._devices:
            if unsupported:
                return self.async_abort(reason="unsupported_product")
            return self.async_abort(reason="no_devices")
        if len(self._devices) == 1:
            self._selected = self._devices[0]
            return await self.async_step_confirm()
        return await self.async_step_pick_device()

    async def async_step_cloud(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            session = aiohttp.ClientSession()
            try:
                _, devices = await login_and_list_devices(
                    session,
                    user_input[CONF_USERNAME],
                    password=user_input[CONF_PASSWORD],
                    region=user_input["region"],
                    country_code=user_input["country_code"],
                )
                self._auth_data = {
                    CONF_EMAIL:        user_input[CONF_USERNAME],
                    CFG_PASSWORD:      user_input[CONF_PASSWORD],
                    CONF_GOOGLE_SUB:   "",
                    CONF_REGION:       user_input["region"],
                    CONF_COUNTRY_CODE: user_input["country_code"],
                }
                return await self._finish_login(devices)
            except TuyaCloudError as err:
                _LOGGER.warning("Cloud login failed: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during cloud login")
                errors["base"] = "unknown"
            finally:
                await session.close()

        return self.async_show_form(
            step_id="cloud",
            data_schema=STEP_CLOUD_SCHEMA,
            errors=errors,
        )

    async def async_step_google(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        return self.async_abort(reason="no_devices")

    async def async_step_pick_device(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            dev_id = user_input["device"]
            self._selected = next(d for d in self._devices if d.dev_id == dev_id)
            return await self.async_step_confirm()

        options = {d.dev_id: f"{d.name} ({d.dev_id[-6:]})" for d in self._devices}
        return self.async_show_form(
            step_id="pick_device",
            data_schema=vol.Schema({vol.Required("device"): vol.In(options)}),
        )

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        dev = self._selected
        assert dev is not None

        # Attempt LAN broadcast discovery so we can use direct LAN at runtime.
        # If the device isn't reachable on HA's broadcast domain, we fall back
        # to cloud polling — both paths get saved to the entry.
        lan_ip = await self.hass.async_add_executor_job(_find_lan_ip, dev.dev_id)
        _LOGGER.info(
            "Device %s: cloud_ip=%s lan_scan=%s", dev.dev_id, dev.ip, lan_ip,
        )

        if user_input is not None:
            await self.async_set_unique_id(dev.dev_id)
            self._abort_if_unique_id_configured()
            return self.async_create_entry(
                title=f"Inkbird Wifi ({dev.name})",
                data={
                    CONF_DEVICE_ID: dev.dev_id,
                    CONF_PRODUCT_ID: dev.product_id,
                    CONF_HOST:      lan_ip or "",        # empty → coordinator uses cloud
                    CONF_LOCAL_KEY: dev.local_key,
                    CONF_VERSION:   DEFAULT_VERSION,
                    **self._auth_data,
                },
            )

        return self.async_show_form(
            step_id="confirm",
            description_placeholders={
                "name":      dev.name,
                "device_id": dev.dev_id,
                "online":    "online" if dev.online else "currently offline",
                "lan_status": (
                    f"LAN: {lan_ip} (direct connection)"
                    if lan_ip else
                    "LAN: not found on broadcast — will use Tuya cloud as fallback"
                ),
            },
            data_schema=vol.Schema({}),
        )
