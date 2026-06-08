#!/usr/bin/env python3
"""Inkbird IM-03-W / IBS-P03R pool temperature reader via observed Inkbird + Tuya flow.

This variant does NOT use smartlife.m.api.batch.invoke. After login it calls the
three actions that appeared inside the batch as normal single Tuya calls.

Flow:
  1. Inkbird login
  2. Tuya token.get
  3. Tuya login.reg with RSA(MD5(input password))
  4. Single calls:
     - m.life.product.ext.prop.list v1.1 body={"gid": <gid>}
     - m.life.device.ext.prop.list v1.2 body={"gid": <gid>}
     - m.life.my.group.device.relation.list v3.2 body={"gid": <gid>}
  5. Recursively find DP 102 and decode 51-byte P03R records

Known from mitmproxy:
  - token.get uses username=email and isUid=True
  - login.reg uid=email and passwd=RSA(MD5(input_password))
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import hmac
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

LOG = logging.getLogger("inkbird_pool_single_calls")

PACKAGE = "com.inkbird.inkbirdapp"
APP_KEY = "nyfyxycreykp7jp4e593"
APP_SECRET = "vupma4jwux4e7m3jry7sspcqhvw3gwet"
BMP_TOKEN = "sehhffxhxks3q7ukmc8u9hymp73n9wt9"
PROD_CERT_HEX = "60DE240C7AA9EFD8CE05D57FC92E58142BB1990722EC980D257623A970FFD898"
PROD_CERT_COLON = ":".join(PROD_CERT_HEX[i:i+2] for i in range(0, len(PROD_CERT_HEX), 2))
SIGN_KEY = f"{PACKAGE}_{PROD_CERT_COLON}_{BMP_TOKEN}_{APP_SECRET}"

INKBIRD_BASE = "https://eu.api-inkbird.com/api"
TUYA_URL = "https://a1.tuyaeu.com/api.json"
INKBIRD_HEADERS = {
    "API-KEY": "8V073Jrc4H",
    "API-SECRET-KEY": "9HbzOuNhQlkESVW7PqxQ",
    "Accept": "application/json",
    "User-Agent": "okhttp/5.0.0-alpha.12",
}

APP_USER_AGENT = "Thing-UA=APP/Android/2.1.6.2/SDK/6.7.0/6.7.0/SDK/6.7.0/6.7.0/SDK/6.7.0"
DEFAULT_DEVICE_ID = "8534c8ec0ed0f09d098d5d23245f2886b10b88cf98d8"
CHKEY = "4e7cfd49"

SIGN_FIELDS = frozenset({
    "a", "v", "lat", "lon", "lang", "deviceId", "appVersion", "ttid",
    "isH5", "h5Token", "os", "clientId", "postData", "time",
    "requestId", "et", "n4h5", "sid", "chKey", "sp",
})

BIZ_DATA = json.dumps({
    "bizBaseVersion": "6.7.0",
    "brand": "google",
    "customDomainSupport": "1",
    "miniappVersion": json.dumps({
        "AIKit": "1.3.3",
        "AIStreamKit": "1.0.1",
        "BaseKit": "3.23.6",
        "BizKit": "4.18.5",
        "CategoryCommonBizKit": "6.4.1",
        "DeviceKit": "4.19.8",
        "HealthKit": "6.6.0",
        "HomeKit": "3.9.0",
        "IPCKit": "6.7.1",
        "LightKit": "1.0.10",
        "MapKit": "6.4.3",
        "MediaKit": "3.6.2",
        "MiniKit": "3.20.3",
        "P2PKit": "6.4.2",
        "PlayNetKit": "1.3.28",
        "SweeperKit": "2.0.0",
        "ThirdPartyDeviceKit": "1.0.0-rc.4",
        "WearKit": "1.1.7",
        "basicLib": "2.30.20",
        "container": "3.30.51",
    }, separators=(",", ":")),
    "nd": "1",
    "sdkInt": "31",
}, separators=(",", ":"))


class InkbirdPoolError(Exception):
    pass


@dataclass
class Reading:
    name: str
    temperature_c: float | None
    humidity_percent: float | None
    raw: bytes


def _post_data_hash(post_data: str) -> str:
    h = hashlib.md5(post_data.encode()).hexdigest()
    return h[8:16] + h[0:8] + h[24:32] + h[16:24]


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
    return hmac.new(SIGN_KEY.encode(), _build_joined(params).encode(), hashlib.sha256).hexdigest()


def _aes_key_for(request_id: str, ecode: str | None) -> bytes:
    msg = SIGN_KEY if ecode is None else f"{SIGN_KEY}_{ecode}"
    return hmac.new(request_id.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16].encode()


def _encrypt_json(raw_obj: Any, request_id: str, ecode: str | None) -> str:
    raw = json.dumps(raw_obj, separators=(",", ":"), ensure_ascii=False)
    key = _aes_key_for(request_id, ecode)
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(raw.encode())
    return base64.b64encode(nonce + ct + tag).decode()


def _decrypt_result(result_b64: str, request_id: str, ecode: str | None) -> Any:
    key = _aes_key_for(request_id, ecode)
    blob = base64.b64decode(result_b64)
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(ct, tag)
    if plain[:2] == b"\x1f\x8b":
        plain = gzip.decompress(plain)
    return json.loads(plain.decode())


def _rsa_encrypt_hex(plaintext: bytes, public_key_decimal: str, exponent: str) -> str:
    key = RSA.construct((int(public_key_decimal), int(exponent)))
    return PKCS1_v1_5.new(key).encrypt(plaintext).hex()


def _recursive_find_dp102(node: Any) -> Iterable[str]:
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


def decode_dp102(dp102_b64: str) -> list[Reading]:
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
        records.append(Reading(name=name, temperature_c=temp_raw / 10.0, humidity_percent=hum_raw / 10.0, raw=rec))
    return records


class InkbirdPoolClient:
    def __init__(self, username: str, password: str, country_code: str = "49") -> None:
        self.username = username
        self.password = password
        self.country_code = country_code
        self.session = requests.Session()
        self.sid: str | None = None
        self.ecode: str | None = None
        self.gid: str | None = None
        self.uid: str | None = None

    def inkbird_login(self) -> dict[str, Any]:
        body = {
            "countryCode": self.country_code,
            "deviceType": 2,
            "password": self.password,
            "registerType": 1,
            "username": self.username,
        }
        resp = self.session.post(f"{INKBIRD_BASE}/smartAgent/user/login", json=body, headers=INKBIRD_HEADERS, timeout=20)
        resp.raise_for_status()
        envelope = resp.json()
        if envelope.get("code") != 200:
            raise InkbirdPoolError(f"Inkbird login failed: {envelope}")
        data = envelope["data"]
        LOG.info("Inkbird login ok: tuyaUid=%s", data.get("user", {}).get("tuyaUid"))
        return data

    def tuya_call(self, action: str, version: str, body: dict[str, Any] | None = None, *, extra: dict[str, str] | None = None, require_session: bool = False) -> Any:
        if require_session and not self.sid:
            raise InkbirdPoolError("Not logged in")
        request_id = str(uuid.uuid4())
        post_data = ""
        if body is not None:
            post_data = _encrypt_json(body, request_id, self.ecode)
        params: dict[str, str] = {
            "appVersion": "6.7.0",
            "appRnVersion": "5.97",
            "channel": "sdk",
            "deviceId": DEFAULT_DEVICE_ID,
            "chKey": CHKEY,
            "osSystem": "12",
            "ttid": "android",
            "et": "3",
            "nd": "1",
            "sdkVersion": "6.7.0",
            "platform": "sdk_gphone64_arm64",
            "requestId": request_id,
            "lang": "en_US",
            "a": action,
            "clientId": APP_KEY,
            "os": "Android",
            "timeZoneId": "Europe/Berlin",
            "cp": "gzip",
            "bizBaseVersion": "6.7.0",
            "v": version,
            "deviceCoreVersion": "6.7.0",
            "bizData": BIZ_DATA,
            "time": str(int(time.time())),
            "postData": post_data,
        }
        if self.sid:
            params["sid"] = self.sid
        if extra:
            params.update(extra)
        params["sign"] = _sign_params(params)
        LOG.debug("Tuya call %s v%s body=%s extra=%s", action, version, body, extra)
        resp = self.session.post(TUYA_URL, data=params, headers={"User-Agent": APP_USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"}, timeout=20)
        resp.raise_for_status()
        envelope = resp.json()
        result = envelope.get("result")
        if isinstance(result, str):
            envelope = _decrypt_result(result, request_id, self.ecode)
        if envelope.get("success") is False or envelope.get("errorCode"):
            raise InkbirdPoolError(f"Tuya {action} failed: {envelope}")
        return envelope.get("result")

    def login(self) -> None:
        self.inkbird_login()
        token_info = self.tuya_call(
            "smartlife.m.user.username.token.get",
            "2.0",
            {"countryCode": self.country_code, "isUid": True, "username": self.username},
        )
        md5_pw = hashlib.md5(self.password.encode()).hexdigest().encode()
        enc_pw = _rsa_encrypt_hex(md5_pw, token_info["publicKey"], token_info["exponent"])
        login_result = self.tuya_call(
            "smartlife.m.user.uid.password.login.reg",
            "1.0",
            {
                "countryCode": self.country_code,
                "createGroup": True,
                "ifencrypt": 1,
                "options": '{"group": 1}',
                "passwd": enc_pw,
                "token": token_info["token"],
                "uid": self.username,
            },
        )
        self.sid = login_result["sid"]
        self.ecode = login_result["ecode"]
        self.gid = str(login_result["gid"])
        self.uid = login_result["uid"]
        LOG.info("Tuya login ok: uid=%s gid=%s ecode=%s", self.uid, self.gid, self.ecode)

    def call_observed_single_actions(self) -> list[dict[str, Any]]:
        """Call the APIs observed inside the app batches as normal single calls.

        The app sends these via smartlife.m.api.batch.invoke, but the encrypted
        params for each inner API decrypted to {"gid": <gid>}. Calling them as
        single Tuya requests with that body works for at least the small batch and
        should expose the large-batch device list containing DP102.
        """
        if not self.gid:
            raise InkbirdPoolError("Not logged in")

        body = {"gid": int(self.gid)}
        calls = [
            # Small batch observed first
            #("m.life.product.ext.prop.list", "1.1"),
            #("m.life.device.ext.prop.list", "1.2"),
            #("m.life.my.group.device.relation.list", "3.2"),

            # Large batch observed in inkbird.flows. The important one for DP102
            # is m.life.my.group.device.list v2.2; keep the surrounding calls too
            # so the script mirrors the app flow as closely as possible.
            #("m.life.my.group.device.sort.list", "2.1"),
            ("m.life.my.group.device.list", "2.2"),
            #("m.life.my.group.mesh.list", "3.1"),
            #("m.life.my.group.device.group.list", "4.3"),
            #("m.life.location.get", "3.4"),
            #("m.life.device.ref.info.my.list", "7.2"),
            #("smartlife.m.my.shared.device.list", "3.2"),
            #("smartlife.m.my.shared.device.group.list", "3.0"),
        ]
        results: list[dict[str, Any]] = []
        for action, version in calls:
            try:
                result = self.tuya_call(action, version, body, require_session=True)
                LOG.info("Single call %s v%s succeeded", action, version)
                LOG.debug("Single call %s v%s result=%s", action, version, json.dumps(result, ensure_ascii=False)[:5000])
                results.append({"a": action, "v": version, "success": True, "result": result})
            except InkbirdPoolError as exc:
                LOG.info("Single call %s v%s failed: %s", action, version, exc)
                results.append({"a": action, "v": version, "success": False, "error": str(exc)})
        return results

    def get_readings(self) -> list[Reading]:
        self.login()
        results = self.call_observed_single_actions()
        LOG.debug("Single-call aggregate result=%s", json.dumps(results, ensure_ascii=False)[:30000])
        all_readings: list[Reading] = []
        for response in results:
            for dp102 in _recursive_find_dp102(response):
                all_readings.extend(decode_dp102(dp102))
        if not all_readings:
            raise InkbirdPoolError("No DP102 found in single-call responses")
        return all_readings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--country-code", default="49")
    parser.add_argument("--sensor", default="P03R_OUT")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--dump-readings", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    client = InkbirdPoolClient(args.username, args.password, args.country_code)
    readings = client.get_readings()
    if args.dump_readings:
        for r in readings:
            print(f"{r.name}: {r.temperature_c:.1f} °C, {r.humidity_percent:.1f} %")
    wanted = next((r for r in readings if r.name == args.sensor), readings[0])
    print(f"{wanted.name}: {wanted.temperature_c:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
