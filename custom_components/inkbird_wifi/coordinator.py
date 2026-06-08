"""DataUpdateCoordinator for the inkbird_wifi integration.

LAN-first, cloud-fallback design:

  1. Try direct LAN connection (tinytuya, AES protocol v3.4) using cached host.
     This is the happy path — low latency, no cloud round-trip, works without
     internet.
  2. If LAN connect fails:
     - Try a UDP broadcast scan to find the device's current LAN IP (handles
       DHCP changes); if found, update the entry and retry LAN.
     - Else fall back to Tuya cloud: poll `tuya.m.device.get` and decode the
       cached sensor-data DP (same blob the device pushes to LAN, just slower).
       Works regardless of network topology — useful when HA is on a different
       subnet/VLAN than the gateway, or behind a firewall that blocks UDP 6667.
  3. Whichever path worked is sticky for the session — we don't keep trying
     the broken path on every refresh.

Per-product DP IDs + decoders live in `products.py` (`PRODUCTS` registry).
This module is product-agnostic; it dispatches to whatever `ProductSpec`
the entry was created with.
"""

from __future__ import annotations

import logging
import time
from datetime import timedelta
from typing import Any

import aiohttp
import tinytuya

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, SCAN_INTERVAL
from .products import CoordinatorData, ProductSpec, SensorReading
from .tuya_cloud import (
    DEFAULT_REGION,
    TuyaCloud,
    TuyaCloudError,
)

_LOGGER = logging.getLogger(__name__)


# ------------------------------------------------------------------
# LAN path (direct TCP to the gateway, tinytuya v3.4 protocol)
# ------------------------------------------------------------------

def _find_lan_ip(device_id: str) -> str | None:
    """Broadcast scan for the device's current LAN IP. Returns None if not seen."""
    try:
        r = tinytuya.find_device(dev_id=device_id)
        if r and isinstance(r, dict):
            ip = r.get("ip")
            if ip and ip != "0.0.0.0":
                return ip
    except Exception as err:  # noqa: BLE001
        _LOGGER.debug("UDP broadcast scan for %s failed: %s", device_id, err)
    return None


def _fetch_lan(
    host: str, device_id: str, local_key: str, version: str, spec: ProductSpec,
) -> CoordinatorData:
    """Direct LAN poll. Returns CoordinatorData(readings, dps).

    `dps` always carries the latest device DPs that we observed during the
    poll (so control entities can show current state). `readings` is empty
    if the data DP didn't arrive within the deadline.
    """
    d = tinytuya.Device(dev_id=device_id, address=host, local_key=local_key, version=float(version))
    d.set_socketPersistent(True)
    d.set_socketTimeout(2)

    last_dps: dict[str, Any] = {}

    def _capture(msg: Any) -> list[SensorReading] | None:
        nonlocal last_dps
        if not msg or msg.get("Error"):
            return None
        dps = msg.get("dps") or (msg.get("data") or {}).get("dps") or {}
        if dps:
            last_dps.update(dps)
        if spec.current_data_dp in dps:
            return spec.decoder(str(dps[spec.current_data_dp]))
        return None

    try:
        status = d.status()
        if status and status.get("Error"):
            raise UpdateFailed(f"LAN: {status.get('Error')}")
        result = _capture(status)
        if result:
            return CoordinatorData(readings=result, dps=last_dps)

        if spec.scan_trigger_dp:
            d.set_value(spec.scan_trigger_dp, True, nowait=True)
        next_retry = time.monotonic() + 8
        # 25s deadline: gateway typically pushes the data DP within ~10-20 s of trigger.
        # Anything longer means the sub-sensor is offline — let the cloud path
        # supply the last cached blob.
        deadline = time.monotonic() + 25
        consecutive_errors = 0
        while time.monotonic() < deadline:
            msg = d.receive()
            result = _capture(msg)
            if result is not None:
                return CoordinatorData(readings=result, dps=last_dps)
            if msg and msg.get("Error"):
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    raise UpdateFailed(f"LAN: {msg.get('Error')}")
            else:
                consecutive_errors = 0
            if not msg:
                time.sleep(0.05)
            if time.monotonic() >= next_retry and spec.scan_trigger_dp:
                d.set_value(spec.scan_trigger_dp, True, nowait=True)
                next_retry = time.monotonic() + 12
        return CoordinatorData(readings=[], dps=last_dps)
    finally:
        try:
            d.close()
        except Exception:
            pass


# ------------------------------------------------------------------
# Coordinator
# ------------------------------------------------------------------

class InkbirdWifiCoordinator(DataUpdateCoordinator[CoordinatorData]):
    """LAN-first, cloud-fallback coordinator. Product-agnostic."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        *,
        spec: ProductSpec,
        device_id: str,
        host: str = "",
        local_key: str = "",
        version: str = "3.4",
        # Cloud fallback
        email: str = "",
        google_sub: str = "",
        password: str = "",
        region: str = DEFAULT_REGION,
        country_code: str = "1",
    ) -> None:
        super().__init__(
            hass, _LOGGER, name=DOMAIN,
            update_interval=timedelta(seconds=SCAN_INTERVAL),
        )
        self._entry = entry
        self._spec = spec
        self._device_id = device_id
        self._host = host
        self._local_key = local_key
        self._version = version
        # Cloud creds (set when configured via cloud login flow)
        self._email = email
        self._google_sub = google_sub
        self._password = password
        self._region = region
        self._country_code = country_code
        self._cloud: TuyaCloud | None = None
        self._session: aiohttp.ClientSession | None = None
        # Sticky preference — set to "lan" or "cloud" once one works
        self._preferred: str | None = None
        # Shared DeviceInfo for every entity created against this coordinator.
        self.device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.title,
            manufacturer="Inkbird",
            model=spec.model,
        )

    @property
    def spec(self) -> ProductSpec:
        return self._spec

    @property
    def device_id(self) -> str:
        return self._device_id

    def _has_lan_creds(self) -> bool:
        return bool(self._host and self._local_key)

    def _has_cloud_creds(self) -> bool:
        return bool(self._email and self._password)

    # --- LAN ---
    async def _try_lan(self) -> CoordinatorData | None:
        """Returns CoordinatorData or None to signal cloud path should be tried.

        An empty `readings` list means the TCP connection worked but no DP
        arrived within the deadline. Treat that as a soft failure so the cloud
        path can supply the cached blob.
        """
        if not self._has_lan_creds():
            return None
        try:
            result = await self.hass.async_add_executor_job(
                _fetch_lan, self._host, self._device_id, self._local_key, self._version, self._spec,
            )
            if result.readings:
                return result
            _LOGGER.debug("LAN poll at %s: connected but no DP %s within deadline",
                          self._host, self._spec.current_data_dp)
            return None
        except UpdateFailed as err:
            _LOGGER.debug("LAN poll at %s failed: %s", self._host, err)
            new_host = await self.hass.async_add_executor_job(_find_lan_ip, self._device_id)
            if new_host and new_host != self._host:
                _LOGGER.info("Device %s moved to %s on LAN", self._device_id, new_host)
                await self._persist_host(new_host)
                try:
                    result = await self.hass.async_add_executor_job(
                        _fetch_lan, new_host, self._device_id, self._local_key, self._version, self._spec,
                    )
                    if result.readings:
                        return result
                except UpdateFailed as err2:
                    _LOGGER.debug("LAN retry at %s failed: %s", new_host, err2)
            return None
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("LAN poll threw: %s", err)
            return None

    async def _persist_host(self, new_host: str) -> None:
        self._host = new_host
        self.hass.config_entries.async_update_entry(
            self._entry,
            data={**self._entry.data, CONF_HOST: new_host},
        )

    # --- Cloud ---
    async def _ensure_logged_in(self) -> TuyaCloud:
        if self._cloud and getattr(self._cloud, "_sid", None):
            return self._cloud
        if self._session is None:
            self._session = async_get_clientsession(self.hass)
        
        # Use the new direct Inkbird login flow with password
        cloud = TuyaCloud(self._session, region=self._region)
        await cloud.login_with_inkbird(
            self._email, self._password, self._country_code
        )
        self._cloud = cloud
        return cloud

    async def _try_cloud(self) -> CoordinatorData | None:
        if not self._has_cloud_creds():
            return None
        try:
            cloud = await self._ensure_logged_in()
            if self._spec.scan_trigger_dp:
                try:
                    await cloud._call(  # noqa: SLF001
                        "tuya.m.device.dp.publish", "1.0",
                        {"devId": self._device_id,
                         "dps": {self._spec.scan_trigger_dp: True}},
                    )
                except TuyaCloudError as err:
                    _LOGGER.debug("Cloud dp.publish trigger failed: %s", err)
            r = await cloud._call(  # noqa: SLF001
                "tuya.m.device.get", "1.0", {"devId": self._device_id},
            )
        except TuyaCloudError as err:
            self._cloud = None
            _LOGGER.debug("Cloud poll failed: %s", err)
            return None

        dps = dict(r.get("dps") or {})
        raw = dps.get(self._spec.current_data_dp, "")
        readings = self._spec.decoder(str(raw)) if raw else []
        return CoordinatorData(readings=readings, dps=dps)

    # --- Main loop ---
    async def _async_update_data(self) -> CoordinatorData:
        order = ("lan", "cloud") if self._preferred != "cloud" else ("cloud", "lan")
        for path in order:
            if path == "lan":
                result = await self._try_lan()
            else:
                result = await self._try_cloud()
            if not result:
                continue
            if self._preferred != path:
                _LOGGER.info("Sensor data now coming via %s", path)
                self._preferred = path
            # The LAN status() response doesn't always echo back every DP —
            # in particular, the bool feature toggles (buzzer / backlight /
            # alarm reminders) are silent over LAN even after the app
            # changes them. Always pull the full DP snapshot from cloud
            # alongside, so the diagnostic + control entities reflect reality.
            if path == "lan" and self._has_cloud_creds():
                merged_dps = await self._fetch_cloud_dps()
                if merged_dps:
                    result = CoordinatorData(
                        readings=result.readings,
                        dps={**result.dps, **merged_dps},
                    )
            return result

        if self.data:
            _LOGGER.debug("No fresh data from LAN or cloud; retaining last refresh")
            return self.data
        raise UpdateFailed(
            f"Couldn't reach device {self._device_id} via LAN or cloud "
            f"(lan_creds={self._has_lan_creds()}, cloud_creds={self._has_cloud_creds()})"
        )

    async def _fetch_cloud_dps(self) -> dict[str, Any] | None:
        """Side-channel cloud poll just to refresh the full DP map. No scan trigger."""
        try:
            cloud = await self._ensure_logged_in()
            r = await cloud._call(  # noqa: SLF001
                "tuya.m.device.get", "1.0", {"devId": self._device_id},
            )
            return dict(r.get("dps") or {})
        except TuyaCloudError as err:
            _LOGGER.debug("Side-channel cloud DPs fetch failed: %s", err)
            self._cloud = None
            return None

    # ------------------------------------------------------------------
    # Writes — used by button / select / switch / number platforms.
    # Goes through whichever path is sticky-preferred; falls back to the
    # other if that one fails. After a successful write we schedule a
    # refresh so entities reflect the new state without waiting 120 s.
    # ------------------------------------------------------------------
    async def write_dp(self, dp_id: str, value: Any) -> None:
        order = ("lan", "cloud") if self._preferred != "cloud" else ("cloud", "lan")
        last_err: Exception | None = None
        for path in order:
            try:
                if path == "lan" and self._has_lan_creds():
                    await self.hass.async_add_executor_job(
                        _write_lan, self._host, self._device_id,
                        self._local_key, self._version, dp_id, value,
                    )
                    self.hass.async_create_task(self.async_request_refresh())
                    return
                if path == "cloud" and self._has_cloud_creds():
                    cloud = await self._ensure_logged_in()
                    await cloud._call(  # noqa: SLF001
                        "tuya.m.device.dp.publish", "1.0",
                        {"devId": self._device_id, "dps": {dp_id: value}},
                    )
                    self.hass.async_create_task(self.async_request_refresh())
                    return
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("write_dp %s=%r via %s failed: %s", dp_id, value, path, err)
                last_err = err
                if path == "cloud":
                    self._cloud = None  # force re-auth next try
        raise UpdateFailed(
            f"Failed to write DP {dp_id}={value!r} to {self._device_id} via LAN or cloud: {last_err}"
        )


def _write_lan(
    host: str, device_id: str, local_key: str, version: str, dp_id: str, value: Any,
) -> None:
    """Blocking LAN write through tinytuya."""
    d = tinytuya.Device(dev_id=device_id, address=host, local_key=local_key, version=float(version))
    d.set_socketPersistent(False)
    d.set_socketTimeout(3)
    try:
        result = d.set_value(dp_id, value)
        if result and result.get("Error"):
            raise RuntimeError(f"LAN set_value: {result['Error']}")
    finally:
        try:
            d.close()
        except Exception:
            pass
