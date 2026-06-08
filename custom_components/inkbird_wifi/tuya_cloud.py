"""Tuya consumer-cloud client for the INKBIRD app (com.inkbird.inkbirdapp).

End-to-end verified flow:
  1. INKBIRD backend (api-inkbird.com) login → returns user record (uid, tuyaUid).
  2. Tuya `smartlife.m.user.username.token.get` v2.0 → returns RSA public key + token.
  3. RSA-encrypt MD5(input password) with that public key.
  4. Tuya `smartlife.m.user.uid.password.login.reg` v1.0 → returns Tuya session.
  5. Call single Tuya APIs to get device list and DP102 (temperature) data.

Crypto (all verified against live emulator hooks):
  - Sign: HMAC-SHA256(SIGN_KEY, sorted-joined-params) — see findings.md
  - postData encryption: AES-128-GCM with random 12-byte nonce, AAD=null, output
    is base64(nonce || ct || tag); key derived per-request as
    HMAC-SHA256(requestId, SIGN_KEY).hex()[:16] when ecode is None.
  - Response decryption: same scheme + optional gunzip.
"""
from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

import aiohttp
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

_LOGGER = logging.getLogger(__name__)

# === INKBIRD app constants (com.inkbird.inkbirdapp v2.1.6.3) ===
PACKAGE = "com.inkbird.inkbirdapp"
APP_KEY = "nyfyxycreykp7jp4e593"
APP_SECRET = "vupma4jwux4e7m3jry7sspcqhvw3gwet"
BMP_TOKEN = "sehhffxhxks3q7ukmc8u9hymp73n9wt9"
PROD_CERT_HEX = "60DE240C7AA9EFD8CE05D57FC92E58142BB1990722EC980D257623A970FFD898"
PROD_CERT_COLON = ":".join(
    PROD_CERT_HEX[i : i + 2] for i in range(0, len(PROD_CERT_HEX), 2)
)

SIGN_KEY = f"{PACKAGE}_{PROD_CERT_COLON}_{BMP_TOKEN}_{APP_SECRET}"

SIGN_FIELDS = frozenset({
    "a", "v", "lat", "lon", "lang", "deviceId", "appVersion", "ttid",
    "isH5", "h5Token", "os", "clientId", "postData", "time",
    "requestId", "et", "n4h5", "sid", "chKey", "sp",
})

APP_USER_AGENT = "Thing-UA=APP/Android/2.1.6.3/SDK/6.7.0/6.7.0/SDK/6.7.0"
DEFAULT_DEVICE_ID = "e5a1220d600384ea01c6c709a79a4260e2cf2bc0c0e7"

REGIONS: dict[str, str] = {
    "us": "https://a1.tuyaus.com/api.json",
    "eu": "https://a1.tuyaeu.com/api.json",
    "cn": "https://a1.tuyacn.com/api.json",
    "in": "https://a1.tuyain.com/api.json",
}
DEFAULT_REGION = "us"

# The OEM "password" the SDK uses to bridge from INKBIRD-issued uid to Tuya.
# Sent as RSA-encrypted MD5 (hex) of this string.
TUYA_OEM_PASSWORD = "BCBA4D3530EA7980F3743C338999D61C"

INKBIRD_BASE = "https://api-inkbird.com/api"
INKBIRD_HEADERS = {
    "API-KEY":        "8V073Jrc4H",
    "API-SECRET-KEY": "9HbzOuNhQlkESVW7PqxQ",
    "Accept":         "application/json",
}


class TuyaCloudError(Exception):
    """Cloud authentication / API error."""


# ------------------------------------------------------------------
# Crypto primitives
# ------------------------------------------------------------------

def _post_data_hash(post_data: str) -> str:
    """Tuya's rearranged-md5 transform applied to postData before signing."""
    h = hashlib.md5(post_data.encode()).hexdigest()
    return h[8:16] + h[0:8] + h[24:32] + h[16:24]


def _chkey_for(input_bytes: bytes) -> str:
    msg = f"{PACKAGE}_{PROD_CERT_COLON}".encode()
    return hmac.new(input_bytes, msg, hashlib.sha256).hexdigest()[8:16]


CHKEY = _chkey_for(APP_KEY.encode())  # "4e7cfd49"


def _aes_key_for(request_id: str, ecode: str | None) -> bytes:
    msg = SIGN_KEY if ecode is None else f"{SIGN_KEY}_{ecode}"
    return hmac.new(
        request_id.encode(), msg.encode(), hashlib.sha256
    ).hexdigest()[:16].encode()


def _build_joined(params: dict[str, str]) -> str:
    parts: list[str] = []
    for key in sorted(params):
        if key not in SIGN_FIELDS or key == "sign":
            continue
        value = params[key]
        if not value:
            continue
        if key == "postData":
            value = _post_data_hash(value)
        parts.append(f"{key}={value}")
    return "||".join(parts)


def _sign_params(params: dict[str, str]) -> str:
    return hmac.new(
        SIGN_KEY.encode(), _build_joined(params).encode(), hashlib.sha256
    ).hexdigest()


def _encrypt_post_data(raw: str, request_id: str, ecode: str | None) -> str:
    """AES-128-GCM encrypt the request body. Format: base64(nonce||ct||tag), AAD=null."""
    key = _aes_key_for(request_id, ecode)
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(raw.encode())
    return base64.b64encode(nonce + ct + tag).decode()


def _decrypt_response(result_b64: str, request_id: str, ecode: str | None) -> Any:
    key = _aes_key_for(request_id, ecode)
    blob = base64.b64decode(result_b64)
    nonce, ct_tag = blob[:12], blob[12:]
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(ct, tag)
    if plain[:2] == b"\x1f\x8b":
        plain = gzip.decompress(plain)
    return json.loads(plain.decode())


def _rsa_encrypt(plaintext: bytes, modulus: int, exponent: int) -> str:
    """RSA-PKCS1-v1.5 encrypt; returns lowercase hex of the ciphertext."""
    key = RSA.construct((modulus, exponent))
    return PKCS1_v1_5.new(key).encrypt(plaintext).hex()


def _recursive_find_dp102(node: Any) -> Iterable[str]:
    """Recursively find DP 102 data (temperature readings) in device list."""
    if isinstance(node, dict):
        # common Tuya shapes
        dps = node.get("dps")
        if isinstance(dps, dict) and "102" in dps and isinstance(dps["102"], str):
            yield dps["102"]
        data_point_info = node.get("dataPointInfo")
        if isinstance(data_point_info, dict):
            dps2 = data_point_info.get("dps")
            if isinstance(dps2, dict) and "102" in dps2 and isinstance(dps2["102"], str):
                yield dps2["102"]
        for value in node.values():
            yield from _recursive_find_dp102(value)
    elif isinstance(node, list):
        for item in node:
            yield from _recursive_find_dp102(item)


@dataclass
class Reading:
    """Temperature and humidity reading from a sensor."""
    name: str
    temperature_c: float | None
    humidity_percent: float | None
    raw: bytes


def decode_dp102(dp102_b64: str) -> list[Reading]:
    """Decode DP 102 base64 blob containing 51-byte sensor records."""
    blob = base64.b64decode(dp102_b64)
    records: list[Reading] = []
    size = 51
    for offset in range(0, len(blob), size):
        rec = blob[offset:offset + size]
        if len(rec) < size:
            continue
        temp_raw = int.from_bytes(rec[9:11], "little", signed=True)
        hum_raw = int.from_bytes(rec[11:13], "little", signed=True)
        name = rec[36:51].split(b"\x00", 1)[0].decode("utf-8", errors="ignore") or f"sensor_{offset//size}"
        # The app uses /10 for temperature and humidity.
        records.append(Reading(
            name=name,
            temperature_c=temp_raw / 10.0,
            humidity_percent=hum_raw / 10.0,
            raw=rec,
        ))
    return records




# ------------------------------------------------------------------
# Tuya HTTP client
# ------------------------------------------------------------------

@dataclass
class TuyaDevice:
    dev_id:      str
    local_key:   str
    ip:          str
    name:        str
    product_id:  str
    online:      bool


class TuyaCloud:
    """Authenticated Tuya cloud session producing signed API calls."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        region: str = DEFAULT_REGION,
    ) -> None:
        self._session = session
        self._url = REGIONS.get(region, REGIONS[DEFAULT_REGION])
        self._sid: str | None = None
        self._ecode: str | None = None
        self._gid: str | None = None
        self._uid: str | None = None

    async def _call(
        self,
        action: str,
        version: str,
        post_body: dict[str, Any] | None = None,
        *,
        extra_signed: dict[str, str] | None = None,
        require_session: bool = False,
    ) -> Any:
        if require_session and not self._sid:
            raise TuyaCloudError("Not logged in")

        request_id = str(uuid.uuid4())
        encrypted = ""
        if post_body is not None:
            encrypted = _encrypt_post_data(
                json.dumps(post_body, separators=(",", ":")),
                request_id,
                self._ecode,
            )

        params: dict[str, str] = {
            "a":                  action,
            "v":                  version,
            "appVersion":         "6.7.0",
            "chKey":              CHKEY,
            "clientId":           APP_KEY,
            "deviceId":           DEFAULT_DEVICE_ID,
            "et":                 "3",
            "lang":               "en_US",
            "os":                 "Android",
            "postData":           encrypted,
            "requestId":          request_id,
            "time":               str(int(time.time())),
            "ttid":               "android",
            "appRnVersion":       "5.97",
            "bizBaseVersion":     "6.7.0",
            "bizData":            '{"bizBaseVersion":"6.7.0","brand":"google","customDomainSupport":"1","nd":"1","sdkInt":"34"}',
            "channel":            "sdk",
            "cp":                 "gzip",
            "deviceCoreVersion":  "6.7.0",
            "nd":                 "1",
            "osSystem":           "14",
            "platform":           "sdk_gphone64_x86_64",
            "sdkVersion":         "6.7.0",
            "timeZoneId":         "Europe/Lisbon",
        }
        if self._sid:
            params["sid"] = self._sid
        if extra_signed:
            params.update(extra_signed)
        params["sign"] = _sign_params(params)

        headers = {
            "User-Agent":   APP_USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        async with self._session.post(
            self._url, data=params, headers=headers,
            timeout=aiohttp.ClientTimeout(total=20)
        ) as resp:
            text = await resp.text()
            if resp.status != 200 or "SING_VALIDATE_FALED" in text:
                raise TuyaCloudError(f"HTTP {resp.status}: {text[:300]}")

        envelope = json.loads(text)
        # Encrypted responses have `result` as a base64 string — decrypt it to get
        # the real envelope with success/errorCode/result.
        result = envelope.get("result")
        if isinstance(result, str):
            envelope = _decrypt_response(result, request_id, self._ecode)
            result = envelope.get("result")

        if envelope.get("success") is False or envelope.get("errorCode"):
            raise TuyaCloudError(
                f"{envelope.get('errorCode')}: {envelope.get('errorMsg', envelope)}"
            )
        return result

    # ------------- session lifecycle (new flow) -------------

    async def login_with_inkbird(self, username: str, password: str, country_code: str) -> None:
        """Login using Inkbird credentials directly.

        Flow:
          1. Inkbird login
          2. Tuya token.get
          3. Tuya login.reg with RSA(MD5(input password))
        """
        # Step 1: Inkbird login
        body = {
            "countryCode": country_code,
            "deviceType": 2,
            "password": password,
            "registerType": 1,
            "username": username,
        }
        async with self._session.post(
            f"{INKBIRD_BASE}/smartAgent/user/login",
            json=body,
            headers=INKBIRD_HEADERS,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            envelope = await resp.json(content_type=None)

        if envelope.get("code") != 200:
            raise TuyaCloudError(
                f"INKBIRD login failed ({envelope.get('code')}): "
                f"{envelope.get('message') or envelope.get('msg') or envelope}"
            )

        _LOGGER.info("Inkbird login ok")

        # Step 2: Tuya token.get
        token_info = await self._call(
            "smartlife.m.user.username.token.get",
            "2.0",
            {"countryCode": country_code, "isUid": True, "username": username},
        )

        # Step 3: Tuya login.reg with RSA-encrypted password
        md5_pw = hashlib.md5(password.encode()).hexdigest().encode()
        enc_pw = _rsa_encrypt(md5_pw, int(token_info["publicKey"]), int(token_info["exponent"]))

        login_result = await self._call(
            "smartlife.m.user.uid.password.login.reg",
            "1.0",
            {
                "countryCode": country_code,
                "createGroup": True,
                "ifencrypt": 1,
                "options": '{"group": 1}',
                "passwd": enc_pw,
                "token": token_info["token"],
                "uid": username,
            },
        )
        self._sid = login_result["sid"]
        self._ecode = login_result["ecode"]
        self._gid = str(login_result["gid"])
        self._uid = login_result["uid"]
        _LOGGER.info("Tuya login ok: uid=%s gid=%s", self._uid, self._gid)

    # ------------- device discovery (new flow) -------------

    async def call_single_device_actions(self) -> list[dict[str, Any]]:
        """Call the APIs as normal single Tuya requests instead of batch.

        Returns list of results with device data.
        """
        if not self._gid:
            raise TuyaCloudError("Not logged in")

        body = {"gid": int(self._gid)}
        calls = [
            ("m.life.my.group.device.list", "2.2"),
        ]
        results: list[dict[str, Any]] = []
        for action, version in calls:
            try:
                result = await self._call(action, version, body, require_session=True)
                _LOGGER.info("Single call %s v%s succeeded", action, version)
                _LOGGER.debug("Single call %s v%s result=%s", action, version, json.dumps(result, ensure_ascii=False)[:5000])
                results.append({"a": action, "v": version, "success": True, "result": result})
            except TuyaCloudError as exc:
                _LOGGER.info("Single call %s v%s failed: %s", action, version, exc)
                results.append({"a": action, "v": version, "success": False, "error": str(exc)})
        return results

    async def get_readings(self) -> list[Reading]:
        """Get temperature readings from all sensors."""
        results = await self.call_single_device_actions()
        all_readings: list[Reading] = []
        for response in results:
            for dp102 in _recursive_find_dp102(response):
                all_readings.extend(decode_dp102(dp102))
        if not all_readings:
            _LOGGER.warning("No DP102 found in single-call responses")
        return all_readings

    # ------------- legacy session lifecycle (kept for compatibility) -------------

    async def login_with_tuya_uid(self, country_code: str, tuya_uid: str) -> None:
        """Bridge a Tuya-side uid (e.g. "1_<google_sub>") into a Tuya cloud session.

        Replicates the SDK's loginOrRegisterWithUid flow:
          1. token.get  → returns RSA pubkey + token
          2. RSA-encrypt MD5(TUYA_OEM_PASSWORD) with pubkey
          3. uid.password.login.reg with encrypted password + token
        """
        token_info = await self._call(
            "smartlife.m.user.username.token.get", "2.0",
            {"countryCode": country_code, "isUid": True, "username": tuya_uid},
        )
        modulus = int(token_info["publicKey"])
        exponent = int(token_info["exponent"])
        token = token_info["token"]

        # Tuya stores passwords as MD5 hashes; encrypt the MD5(OEM_PASSWORD).
        md5_pw = hashlib.md5(TUYA_OEM_PASSWORD.encode()).hexdigest().encode()
        enc_pw = _rsa_encrypt(md5_pw, modulus, exponent)

        result = await self._call(
            "smartlife.m.user.uid.password.login.reg", "1.0",
            {
                "countryCode": country_code,
                "createGroup": True,
                "ifencrypt":   1,
                "options":     '{"group": 1}',
                "passwd":      enc_pw,
                "token":       token,
                "uid":         tuya_uid,
            },
        )
        self._sid = result.get("sid")
        self._ecode = result.get("ecode")
        if not self._sid:
            raise TuyaCloudError(f"Login returned no sid: {result}")
        # Log the user object + domain so we can see actual region URLs
        _LOGGER.info(
            "Logged in: uid=%s regionCode=%s",
            result.get("uid"),
            (result.get("domain") or {}).get("regionCode"),
        )
        _LOGGER.debug("Full login response: %s", json.dumps(result)[:2000])

    # ------------- device discovery -------------

    async def list_devices(self) -> list[TuyaDevice]:
        """Enumerate all devices across all homes.

        For each home, queries the same endpoints the SDK calls on login:
          - m.life.my.group.device.list       (top-level direct devices)
          - m.life.my.group.device.sort.list  (devices with their display order)
          - m.life.my.group.mesh.list         (BLE-mesh subdevices)
          - m.life.my.group.device.group.list (subdevices inside device-groups)
        Plus the older `tuya.m.my.group.device.list` as a last-resort fallback.
        Results are de-duplicated by devId. Subdevices without their own
        localKey (e.g. BLE sensors bound to a gateway) are still returned —
        the gateway's localKey is what's needed for LAN access.
        """
        locs = await self._call("tuya.m.location.list", "2.1", require_session=True)
        _LOGGER.info("Tuya locations: %d", len(locs or []))
        _LOGGER.debug("Full location.list response: %s", json.dumps(locs)[:2000])
        # Also try alternative location-listing endpoints in case the user's
        # home isn't returned by the v2.1 endpoint.
        for alt_action, alt_ver in [
            ("smartlife.m.location.list", "1.0"),
            ("smartlife.m.location.list", "2.1"),
            ("smartlife.m.location.list", "3.0"),
            ("tuya.m.location.list", "1.0"),
            ("tuya.m.location.list", "3.0"),
        ]:
            try:
                alt = await self._call(alt_action, alt_ver, require_session=True)
                if alt:
                    _LOGGER.debug("Alt %s v%s: %s", alt_action, alt_ver, json.dumps(alt)[:2000])
                    # Merge any new locations
                    existing_ids = {(l.get("groupId") or l.get("gid") or l.get("id")) for l in (locs or [])}
                    for entry in (alt if isinstance(alt, list) else [alt]):
                        if isinstance(entry, dict):
                            new_id = entry.get("groupId") or entry.get("gid") or entry.get("id")
                            if new_id and new_id not in existing_ids:
                                _LOGGER.info("Found extra location from %s: gid=%s name=%r", alt_action, new_id, entry.get("name"))
                                if locs is None: locs = []
                                locs.append(entry)
                                existing_ids.add(new_id)
            except TuyaCloudError as err:
                _LOGGER.debug("Alt %s v%s: %s", alt_action, alt_ver, err)
        seen: dict[str, TuyaDevice] = {}
        # (action, version, gid_in_query_else_body, extra_body)
        # Tuya namespaces all the same family of device-list endpoints under three
        # prefixes — we hit all variants because OEM apps inconsistently use them.
        endpoints: list[tuple[str, str, bool, dict[str, Any] | None]] = [
            ("smartlife.m.my.group.device.list",       "1.0", True, None),
            ("smartlife.m.my.group.device.list",       "2.0", True, None),
            ("smartlife.m.my.group.device.sort.list",  "1.0", True, None),
            ("smartlife.m.my.group.mesh.list",         "1.0", True, None),
            ("smartlife.m.my.group.device.group.list", "1.0", True, None),
            ("tuya.m.my.group.device.list",            "1.0", True, None),
            ("thing.m.my.group.device.list",           "1.0", True, None),
            ("thing.m.my.group.device.list",           "2.0", True, None),
            ("thing.m.my.shared.device.list",          "1.0", False, None),
            ("thing.m.my.rule.device.list",            "1.0", True, None),
        ]
        for loc in locs or []:
            gid = loc.get("groupId") or loc.get("gid") or loc.get("id")
            name = loc.get("name", "?")
            _LOGGER.info("Querying location gid=%s name=%r", gid, name)
            if gid is None:
                continue
            for action, ver, use_query, extra_body in endpoints:
                try:
                    body = dict(extra_body or {})
                    if not use_query:
                        body["gid"] = str(gid)
                    devs = await self._call(
                        action, ver,
                        body if body else None,
                        extra_signed={"gid": str(gid)} if use_query else None,
                        require_session=True,
                    )
                except TuyaCloudError as err:
                    _LOGGER.info("  %s v%s -> %s", action, ver, err)
                    continue
                # Log the raw response shape at debug for diagnosis
                preview = json.dumps(devs)[:500] if devs is not None else "None"
                _LOGGER.debug("  %s v%s raw: %s", action, ver, preview)
                records = list(_iter_device_records(devs))
                _LOGGER.info("  %s v%s -> %d records", action, ver, len(records))
                for d in records:
                    dev_id = d.get("devId") or d.get("id")
                    if not dev_id:
                        continue
                    _LOGGER.info(
                        "    dev_id=%s name=%r product=%s has_local_key=%s",
                        dev_id, d.get("name"), d.get("productId"),
                        bool(d.get("localKey")),
                    )
                    if dev_id in seen:
                        continue
                    seen[dev_id] = _parse_device(d)
        _LOGGER.info("Discovered %d unique devices total", len(seen))
        return list(seen.values())


def _iter_device_records(node: Any) -> Any:
    """Yield flat device dicts from any of the mesh/group/device list shapes.

    The endpoints return either a flat list, or a dict like
    `{"devices":[...], "deviceGroupList":[...], "meshList":[...]}` with
    nested device arrays. Walk recursively and yield every dict that has a
    `devId` (or `id`) field.
    """
    if isinstance(node, list):
        for item in node:
            yield from _iter_device_records(item)
    elif isinstance(node, dict):
        if "devId" in node or "id" in node and any(
            k in node for k in ("localKey", "productId", "name", "uuid")
        ):
            yield node
        # Recurse into common nested keys
        for key in (
            "devices", "deviceList", "deviceGroupList", "meshList",
            "subDeviceList", "subDevs", "children", "list",
        ):
            if key in node:
                yield from _iter_device_records(node[key])


def _parse_device(d: dict[str, Any]) -> TuyaDevice:
    return TuyaDevice(
        dev_id=     d.get("devId", ""),
        local_key=  d.get("localKey", ""),
        ip=         d.get("ip", ""),
        name=       d.get("name") or d.get("devId", ""),
        product_id= d.get("productId", ""),
        online=     bool(d.get("isOnline", False)),
    )


# ------------------------------------------------------------------
# Top-level convenience
# ------------------------------------------------------------------

async def login_and_list_devices(
    session: aiohttp.ClientSession,
    email: str,
    password: str = "",
    google_sub: str = "",
    *,
    region: str = DEFAULT_REGION,
    country_code: str = "1",
) -> tuple[TuyaCloud, list[TuyaDevice]]:
    """End-to-end:
      INKBIRD backend login → Tuya login → list devices.

    For email/password accounts, pass `password`. Google login is no longer supported.
    """
    if password:
        # New flow: direct Inkbird login with password
        cloud = TuyaCloud(session, region=region)
        await cloud.login_with_inkbird(email, password, country_code)
        
        # Try to get device list using the legacy path first
        try:
            devices = await cloud.list_devices()
            if devices:
                return cloud, devices
        except Exception as err:
            _LOGGER.debug("Legacy device list failed, falling back to readings: %s", err)
        
        # Fallback: get readings to detect sensors
        readings = await cloud.get_readings()
        if not readings:
            raise TuyaCloudError("No devices or sensors found")
        
        # Create virtual TuyaDevice entries for each sensor
        devices = []
        for i, reading in enumerate(readings):
            # Create a virtual device for each sensor
            device = TuyaDevice(
                dev_id=f"inkbird_sensor_{i}",
                local_key="",
                ip="",
                name=reading.name,
                product_id="inkbird_sensor",
                online=True,
            )
            devices.append(device)
        
        return cloud, devices
    else:
        raise TuyaCloudError("Only email+password authentication is supported")
