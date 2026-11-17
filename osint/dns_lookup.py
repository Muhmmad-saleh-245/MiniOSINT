"""DNS records plus a simple email-security check (SPF, DMARC, common DKIM selectors).

Uses `dnspython` when installed. If it is missing, falls back to DNS-over-HTTPS
(Cloudflare's JSON endpoint) so the tool still works.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from .http import get_json

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "s1", "dkim", "mail"]
_DOH_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


class DnsError(Exception):
    """Lookup failed for a reason other than 'no such record'."""


class NoRecord(Exception):
    pass


class NoDomain(Exception):
    pass


def txt_clean(text: str) -> str:
    """dnspython returns TXT as '"part1" "part2"'. Join the parts."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    return "".join(parts) if parts else text


class DnspythonBackend:
    name = "dnspython"

    def __init__(self, resolver=None):
        if resolver is None:
            import dns.resolver  # noqa: PLC0415
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
        self.resolver = resolver

    def query(self, name: str, rtype: str) -> list[str]:
        try:
            answer = self.resolver.resolve(name, rtype)
        except Exception as exc:
            kind = type(exc).__name__  # avoids importing dns exception classes
            if kind == "NXDOMAIN":
                raise NoDomain() from None
            if kind in ("NoAnswer", "NoRootSOA"):
                raise NoRecord() from None
            if kind in ("Timeout", "LifetimeTimeout"):
                raise DnsError("timed out") from None
            raise DnsError(kind) from None
        return [rdata.to_text() for rdata in answer]


class DohBackend:
    name = "doh-cloudflare"

    def __init__(self, session):
        self.session = session

    def query(self, name: str, rtype: str) -> list[str]:
        url = f"https://cloudflare-dns.com/dns-query?name={name}&type={rtype}"
        try:
            status, data = get_json(self.session, url, accept="application/dns-json", timeout=6)
        except Exception as exc:
            raise DnsError(type(exc).__name__) from None
        if status != 200 or not isinstance(data, dict):
            raise DnsError(f"HTTP {status}")
        rcode = data.get("Status")
        if rcode == 3:
            raise NoDomain()
        if rcode != 0:
            raise DnsError(f"rcode {rcode}")
        want = _DOH_TYPES[rtype]
        answers = [a.get("data", "") for a in data.get("Answer", []) or [] if a.get("type") == want]
        if not answers:
            raise NoRecord()
        return answers


def default_backend(session=None):
    try:
        return DnspythonBackend()
    except Exception:
        if session is None:
            raise DnsError("dnspython is not installed and no HTTP session is available") from None
        return DohBackend(session)


def _spf(txts: list[str]) -> dict:
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        return {"present": False, "record": None, "policy": None}
    rec = spf[0]
    m = re.search(r"\s([+\-~?]?)all\b", rec)
    policy = {"-": "strict (-all)", "~": "soft fail (~all)", "?": "neutral (?all)", "+": "allow everyone (+all)", "": "allow everyone (+all)"}
    return {
        "present": True,
        "record": rec,
        "policy": policy[m.group(1)] if m else "no 'all' mechanism",
        "multiple": len(spf) > 1,
        "dangerous": bool(m and m.group(1) in ("+", "")),
    }


def _dmarc(txts: list[str]) -> dict:
    found = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not found:
        return {"present": False, "record": None, "policy": None}
    tags = {}
    for part in found[0].split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return {"present": True, "record": found[0], "policy": tags.get("p"), "reports_to": tags.get("rua")}


def lookup(domain: str, *, backend=None, session=None, check_dkim: bool = True) -> dict:
    """Query DNS for a validated domain. Returns data plus observations; never raises."""
    try:
        backend = backend or default_backend(session)
    except DnsError as exc:
        return {"domain": domain, "resolver": None, "records": {}, "errors": {"all": str(exc)},
                "nxdomain": False, "email_security": None,
                "observations": [{"level": "warn", "text": f"DNS lookup was not possible: {exc}."}]}

    jobs = [(domain, t) for t in RECORD_TYPES]
    jobs.append((f"_dmarc.{domain}", "TXT"))
    if check_dkim:
        jobs += [(f"{s}._domainkey.{domain}", "TXT") for s in DKIM_SELECTORS]

    def run(job):
        name, rtype = job
        try:
            return job, backend.query(name, rtype), None
        except NoRecord:
            return job, [], None
        except NoDomain:
            return job, [], "NXDOMAIN"
        except DnsError as exc:
            return job, [], str(exc)
        except Exception as exc:  # a broken backend must not crash the page
            return job, [], type(exc).__name__

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(run, jobs))

    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    extra: dict[tuple[str, str], list[str]] = {}
    nxdomain = False
    for (name, rtype), values, err in outcomes:
        if name == domain:
            if err == "NXDOMAIN":
                nxdomain = True
            elif err:
                errors[rtype] = err
            records[rtype] = [txt_clean(v) if rtype == "TXT" else v for v in values]
        else:
            extra[(name, rtype)] = [txt_clean(v) for v in values]

    result = {"domain": domain, "resolver": backend.name, "records": records, "errors": errors,
              "nxdomain": nxdomain, "email_security": None}
    if nxdomain:
        result["records"] = {}
        result["observations"] = [{"level": "info", "text": "The domain does not exist in DNS (NXDOMAIN)."}]
        return result

    dkim = [s for s in DKIM_SELECTORS if any("p=" in t or "v=dkim1" in t.lower() for t in extra.get((f"{s}._domainkey.{domain}", "TXT"), []))]
    result["email_security"] = {
        "spf": _spf(records.get("TXT", [])),
        "dmarc": _dmarc(extra.get((f"_dmarc.{domain}", "TXT"), [])),
        "dkim_selectors_found": dkim,
        "dkim_checked": check_dkim,
    }
    result["observations"] = observations(result)
    return result


def observations(r: dict) -> list[dict]:
    out = []
    recs, errs = r.get("records", {}), r.get("errors", {})
    if len(errs) >= len(RECORD_TYPES):
        out.append({"level": "warn", "text": "Every DNS query failed. Check your internet connection or DNS settings."})
        return out
    if not recs.get("A") and not recs.get("AAAA") and not recs.get("CNAME"):
        out.append({"level": "info", "text": "The domain has no address (A/AAAA) record."})
    if len(recs.get("NS", [])) == 1:
        out.append({"level": "warn", "text": "Only one name server is published (no redundancy)."})
    es = r.get("email_security")
    has_mail = bool(recs.get("MX"))
    if es:
        spf, dmarc = es["spf"], es["dmarc"]
        if not spf["present"]:
            out.append({"level": "warn" if has_mail else "info", "text": "No SPF record found."})
        else:
            if spf.get("multiple"):
                out.append({"level": "warn", "text": "More than one SPF record exists (SPF requires exactly one)."})
            if spf.get("dangerous"):
                out.append({"level": "high", "text": "SPF allows every sender (+all)."})
        if not dmarc["present"]:
            out.append({"level": "warn" if has_mail else "info", "text": "No DMARC record found."})
        elif (dmarc.get("policy") or "").lower() == "none":
            out.append({"level": "info", "text": "DMARC policy is 'none' (monitoring only, no enforcement)."})
    if not recs.get("CAA"):
        out.append({"level": "info", "text": "No CAA record (any certificate authority may issue certificates)."})
    return out
