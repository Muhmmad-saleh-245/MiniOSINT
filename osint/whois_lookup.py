"""Domain registration lookup.

Order of attempts:
1. the `python-whois` library (classic WHOIS, port 43), if installed;
2. RDAP (the modern JSON replacement for WHOIS, over HTTPS) as a fallback.

Registrant details are usually redacted since GDPR. We report that honestly
("privacy protected") instead of showing an empty field.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

from .http import get_json

_PRIVACY_WORDS = ("redacted", "privacy", "proxy", "whoisguard", "withheld", "data protected", "not disclosed")


def _import_whois():
    try:
        import whois  # the python-whois package
        return whois if hasattr(whois, "whois") else None
    except Exception:
        return None


def _to_date(value) -> date | None:
    if isinstance(value, (list, tuple)):
        dates = [d for d in (_to_date(v) for v in value) if d]
        return min(dates) if dates else None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        for candidate in (text, text[:10]):
            try:
                return datetime.fromisoformat(candidate).date()
            except ValueError:
                continue
    return None


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = [value]
    out = []
    for item in items:
        text = str(item).strip()
        if text and text.lower() not in (x.lower() for x in out):
            out.append(text)
    return out


def _looks_private(*texts) -> bool:
    joined = " ".join(str(t) for t in texts if t).lower()
    return any(w in joined for w in _PRIVACY_WORDS)


def _finish(result: dict, today: date) -> dict:
    created, expires = _to_date(result.get("created")), _to_date(result.get("expires"))
    result["created"] = created.isoformat() if created else None
    result["expires"] = expires.isoformat() if expires else None
    updated = _to_date(result.get("updated"))
    result["updated"] = updated.isoformat() if updated else None
    result["age_days"] = (today - created).days if created else None
    result["days_to_expiry"] = (expires - today).days if expires else None
    result["nameservers"] = sorted({n.lower().rstrip(".") for n in result.get("nameservers", []) if n})
    result["observations"] = observations(result)
    return result


def observations(r: dict) -> list[dict]:
    out = []
    if r.get("found") is False:
        out.append({"level": "info", "text": "No registration record found. The domain may be unregistered."})
        return out
    d = r.get("days_to_expiry")
    if d is not None:
        if d < 0:
            out.append({"level": "high", "text": f"The domain expired {-d} days ago."})
        elif d <= 30:
            out.append({"level": "warn", "text": f"The domain expires in {d} days."})
    a = r.get("age_days")
    if a is not None and a < 30:
        out.append({"level": "warn", "text": f"Newly registered domain ({a} days old)."})
    if r.get("privacy_protected"):
        out.append({"level": "info", "text": "Registrant details are hidden by privacy protection or GDPR redaction."})
    if len(r.get("nameservers", [])) == 0:
        out.append({"level": "info", "text": "No name servers were listed in the record."})
    return out


def _from_whois_lib(domain: str, lib, today: date) -> dict | None:
    raw = lib.whois(domain)
    get = (lambda k: raw.get(k)) if hasattr(raw, "get") else (lambda k: getattr(raw, k, None))
    if not any(get(k) for k in ("domain_name", "registrar", "creation_date", "expiration_date")):
        return None
    org = get("org") or get("registrant_organization") or get("name")
    result = {
        "domain": domain,
        "source": "whois",
        "found": True,
        "registrar": (_as_list(get("registrar")) or [None])[0],
        "created": get("creation_date"),
        "expires": get("expiration_date"),
        "updated": get("updated_date"),
        "nameservers": _as_list(get("name_servers")),
        "status": [s.split(" ")[0] for s in _as_list(get("status"))],
        "org": org if isinstance(org, str) else None,
        "country": get("country") if isinstance(get("country"), str) else None,
        "emails": _as_list(get("emails")),
        "dnssec": get("dnssec") if isinstance(get("dnssec"), str) else None,
    }
    result["privacy_protected"] = _looks_private(result["org"], get("name"), " ".join(result["emails"]))
    return _finish(result, today)


def _vcard_value(entity: dict, field: str):
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return None
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            return item[3]
    return None


def _from_rdap(domain: str, data: dict, today: date) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in (data.get("events") or []) if isinstance(e, dict)}
    registrar = registrant_org = country = None
    emails: list[str] = []
    texts_for_privacy = []
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles", []) or []
        if "registrar" in roles and not registrar:
            registrar = _vcard_value(ent, "fn")
        if "registrant" in roles:
            registrant_org = _vcard_value(ent, "org") or _vcard_value(ent, "fn")
            if isinstance(registrant_org, list):
                registrant_org = " ".join(map(str, registrant_org))
            adr = _vcard_value(ent, "adr")
            if isinstance(adr, list) and len(adr) >= 7 and isinstance(adr[6], str):
                country = adr[6] or None
            texts_for_privacy.append(registrant_org)
            if ent.get("remarks"):
                texts_for_privacy.append(str(ent["remarks"]))
    for ent in data.get("entities", []) or []:
        for sub in ent.get("entities", []) or []:
            mail = _vcard_value(sub, "email")
            if isinstance(mail, str) and mail and "redacted" not in mail.lower():
                emails.append(mail)
    privacy = bool(texts_for_privacy) and (
        _looks_private(*texts_for_privacy) or not any(texts_for_privacy)
    )
    if not any(e.get("roles") and "registrant" in e["roles"] for e in data.get("entities", []) or []):
        privacy = True  # no registrant entity published at all
    result = {
        "domain": domain,
        "source": "rdap",
        "found": True,
        "registrar": registrar,
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed"),
        "nameservers": [n.get("ldhName") for n in data.get("nameservers", []) or [] if isinstance(n, dict)],
        "status": _as_list(data.get("status")),
        "org": registrant_org if isinstance(registrant_org, str) and not _looks_private(registrant_org) else None,
        "country": country,
        "emails": _as_list(emails),
        "dnssec": "signed" if (data.get("secureDNS") or {}).get("delegationSigned") else "unsigned",
        "privacy_protected": privacy,
    }
    return _finish(result, today)


def lookup(domain: str, *, session=None, whois_module=None, use_whois_lib: bool = True, today: date | None = None) -> dict:
    """Look up a validated domain. Never raises for lookup problems: returns an `errors` list."""
    today = today or datetime.now(timezone.utc).date()
    errors: list[str] = []
    lib = whois_module if whois_module is not None else (_import_whois() if use_whois_lib else None)
    if lib is not None:
        try:
            res = _from_whois_lib(domain, lib, today)
            if res:
                res["errors"] = errors
                return res
            errors.append("WHOIS returned no usable data; trying RDAP.")
        except Exception as exc:  # the library raises many different errors
            errors.append(f"WHOIS failed ({type(exc).__name__}); trying RDAP.")
    if session is None:
        errors.append("No HTTP session available for RDAP.")
        return {"domain": domain, "source": None, "found": None, "errors": errors, "observations": [], "nameservers": [], "status": [], "emails": []}
    try:
        status, data = get_json(session, f"https://rdap.org/domain/{domain}", accept="application/rdap+json")
    except Exception as exc:
        errors.append(f"RDAP request failed ({type(exc).__name__}).")
        return {"domain": domain, "source": None, "found": None, "errors": errors, "observations": [], "nameservers": [], "status": [], "emails": []}
    if status == 404:
        res = {"domain": domain, "source": "rdap", "found": False, "nameservers": [], "status": [], "emails": []}
        res = _finish(res, today)
        res["errors"] = errors
        return res
    if status != 200 or not isinstance(data, dict):
        errors.append(f"RDAP answered with HTTP {status}.")
        return {"domain": domain, "source": None, "found": None, "errors": errors, "observations": [], "nameservers": [], "status": [], "emails": []}
    res = _from_rdap(domain, data, today)
    res["errors"] = errors
    return res
