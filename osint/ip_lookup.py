"""IP address lookup: reverse DNS, registry (RDAP) ownership and approximate geolocation.

Only public addresses are accepted (see validate.normalize_ip). Each data source is
independent: if one fails, the others are still shown.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from .http import get_json


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _rdap(session, ip: str) -> dict:
    status, data = get_json(session, f"https://rdap.org/ip/{ip}", accept="application/rdap+json")
    if status != 200 or not isinstance(data, dict):
        raise RuntimeError(f"HTTP {status}")
    org = None
    for ent in data.get("entities", []) or []:
        card = ent.get("vcardArray")
        if isinstance(card, list) and len(card) == 2:
            for item in card[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    org = org or item[3]
    return {
        "network_name": data.get("name"),
        "handle": data.get("handle"),
        "range": f"{data.get('startAddress')} - {data.get('endAddress')}" if data.get("startAddress") else None,
        "country": data.get("country"),
        "type": data.get("type"),
        "organization": org if isinstance(org, str) else None,
    }


def _geo(session, ip: str) -> dict:
    status, data = get_json(session, f"https://ipwho.is/{ip}")
    if status != 200 or not isinstance(data, dict) or data.get("success") is False:
        raise RuntimeError(f"HTTP {status}" if status != 200 else str(data.get("message") if isinstance(data, dict) else "bad reply"))
    conn = data.get("connection") or {}
    return {
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "timezone": (data.get("timezone") or {}).get("id"),
        "asn": conn.get("asn"),
        "isp": conn.get("isp"),
        "org": conn.get("org"),
        "domain": conn.get("domain"),
    }


def lookup(ip: str, *, session, rdns=_reverse_dns) -> dict:
    """Look up a validated public IP. Returns partial results plus an errors dict."""
    errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_rdns = pool.submit(rdns, ip)
        f_rdap = pool.submit(_rdap, session, ip)
        f_geo = pool.submit(_geo, session, ip)
        try:
            hostname = f_rdns.result(timeout=6)
        except (FutureTimeout, Exception):
            hostname = None
            errors["reverse_dns"] = "timed out or failed"
        out = {}
        for key, fut in (("registry", f_rdap), ("geolocation", f_geo)):
            try:
                out[key] = fut.result(timeout=15)
            except Exception as exc:
                out[key] = None
                msg = str(exc) or type(exc).__name__
                # keep it short and free of internal URLs/paths
                errors[key] = msg if len(msg) <= 60 and "://" not in msg else f"lookup failed ({type(exc).__name__})"
    result = {"ip": ip, "version": 6 if ":" in ip else 4, "reverse_dns": hostname,
              "registry": out["registry"], "geolocation": out["geolocation"], "errors": errors}
    result["observations"] = observations(result)
    return result


def observations(r: dict) -> list[dict]:
    out = []
    if r.get("reverse_dns") is None and "reverse_dns" not in r.get("errors", {}):
        out.append({"level": "info", "text": "No reverse DNS (PTR) record."})
    if r.get("registry") is None and r.get("geolocation") is None:
        out.append({"level": "warn", "text": "No registry or geolocation data could be retrieved."})
    else:
        out.append({"level": "info", "text": "Geolocation is approximate and often shows the provider's location, not the user's."})
    reg, geo = r.get("registry") or {}, r.get("geolocation") or {}
    if reg.get("country") and geo.get("country_code") and reg["country"].upper() != geo["country_code"].upper():
        out.append({"level": "info", "text": f"Registry country ({reg['country']}) differs from geolocation country ({geo['country_code']})."})
    return out
