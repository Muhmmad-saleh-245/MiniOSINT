"""Investigation report: one context dict feeds both the HTML and Markdown outputs."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from . import __version__

LEVEL_ORDER = {"high": 0, "warn": 1, "info": 2}
LEVEL_LABEL = {"high": "High", "warn": "Warning", "info": "Note"}
KIND_LABEL = {"whois": "Domain registration (WHOIS/RDAP)", "dns": "DNS records", "ip": "IP address", "username": "Username check"}

DISCLAIMER = (
    "This report contains only publicly available information gathered passively for an authorized "
    "purpose. Results come from third-party services, may be incomplete or out of date, and must be "
    "verified before any decision is made. A matching username or name does not prove identity."
)


def build_context(case: dict, results: list[dict]) -> dict:
    items, observations = [], []
    for r in results:
        obs = list(r["data"].get("observations", []))
        items.append({"id": r["id"], "kind": r["kind"], "label": KIND_LABEL.get(r["kind"], r["kind"]),
                      "target": r["target"], "retrieved": r["data"].get("retrieved_at", r["created"]), "data": r["data"], "observations": obs})
        for o in obs:
            observations.append({"level": o["level"], "text": o["text"], "target": r["target"], "kind": r["kind"]})
    observations.sort(key=lambda o: LEVEL_ORDER.get(o["level"], 9))
    counts = {k: sum(1 for o in observations if o["level"] == k) for k in LEVEL_ORDER}
    return {
        "tool": f"Mini OSINT Toolkit v{__version__}",
        "case": case,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "items": items,
        "observations": observations,
        "counts": counts,
        "targets": sorted({(i["kind"], i["target"]) for i in items}),
        "disclaimer": DISCLAIMER,
        "level_label": LEVEL_LABEL,
    }


def md(text) -> str:
    """Escape text for safe inclusion in Markdown (also neutralises HTML and table breaks)."""
    s = "" if text is None else str(text)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", s)
    s = s.replace("\\", "\\\\").replace("\r", " ").replace("\n", " ")
    s = re.sub(r"([`*_{}\[\]<>|#!~])", r"\\\1", s)
    return s


def _kv(rows) -> list[str]:
    out = ["| Field | Value |", "|---|---|"]
    out += [f"| {md(k)} | {md(v)} |" for k, v in rows if v not in (None, "", [])]
    return out


def to_markdown(ctx: dict) -> str:
    c = ctx["case"]
    L = [f"# Investigation report: {md(c['title'])}", "",
         f"- **Analyst:** {md(c['analyst'])}",
         f"- **Authorization / purpose:** {md(c['authorization'])}",
         f"- **Case created:** {md(c['created'])}",
         f"- **Report generated:** {md(ctx['generated'])}",
         f"- **Tool:** {md(ctx['tool'])}", "",
         "## Summary", "",
         f"{len(ctx['items'])} lookup(s) on {len(ctx['targets'])} target(s). "
         f"Observations: {ctx['counts']['high']} high, {ctx['counts']['warn']} warning, {ctx['counts']['info']} note.", ""]
    if ctx["observations"]:
        L += ["| Level | Target | Observation |", "|---|---|---|"]
        L += [f"| {ctx['level_label'][o['level']]} | {md(o['target'])} | {md(o['text'])} |" for o in ctx["observations"]]
        L.append("")
    if c.get("notes"):
        L += ["## Analyst notes", "", md(c["notes"]), ""]
    for it in ctx["items"]:
        d = it["data"]
        L += [f"## {md(it['label'])}: {md(it['target'])}", "", f"_Retrieved {md(it['retrieved'])}_", ""]
        if it["kind"] == "whois":
            L += _kv([("Source", d.get("source")), ("Registered", d.get("found")), ("Registrar", d.get("registrar")),
                      ("Created", d.get("created")), ("Expires", d.get("expires")), ("Updated", d.get("updated")),
                      ("Age (days)", d.get("age_days")), ("Days to expiry", d.get("days_to_expiry")),
                      ("Name servers", ", ".join(d.get("nameservers", []))), ("Status", ", ".join(d.get("status", []))),
                      ("Organization", d.get("org")), ("Country", d.get("country")), ("DNSSEC", d.get("dnssec")),
                      ("Privacy protected", d.get("privacy_protected"))])
        elif it["kind"] == "dns":
            L += ["| Type | Value |", "|---|---|"]
            for t, vals in d.get("records", {}).items():
                for v in vals:
                    L.append(f"| {md(t)} | {md(v)} |")
            es = d.get("email_security")
            if es:
                L += ["", "**Email security**", ""]
                L += _kv([("SPF", es["spf"].get("record") or "missing"), ("SPF policy", es["spf"].get("policy")),
                          ("DMARC", es["dmarc"].get("record") or "missing"),
                          ("DKIM selectors found", ", ".join(es.get("dkim_selectors_found", [])) or "none of the common ones")])
        elif it["kind"] == "ip":
            reg, geo = d.get("registry") or {}, d.get("geolocation") or {}
            L += _kv([("Reverse DNS", d.get("reverse_dns")), ("Network", reg.get("network_name")), ("Range", reg.get("range")),
                      ("Registry organization", reg.get("organization")), ("Registry country", reg.get("country")),
                      ("Country", geo.get("country")), ("Region", geo.get("region")), ("City", geo.get("city")),
                      ("ASN", geo.get("asn")), ("ISP", geo.get("isp")), ("Organization", geo.get("org")), ("Timezone", geo.get("timezone"))])
        elif it["kind"] == "username":
            L += ["| Platform | Result | Detail | Link |", "|---|---|---|---|"]
            for r in d.get("results", []):
                L.append(f"| {md(r['platform'])} | {md(r['status'])} | {md(r['detail'])} | {md(r['url'])} |")
        if d.get("errors"):
            errs = d["errors"] if isinstance(d["errors"], list) else [f"{k}: {v}" for k, v in d["errors"].items()]
            L += ["", "**Problems during lookup:** " + md("; ".join(errs))]
        L.append("")
    L += ["## Limitations", "", md(ctx["disclaimer"]), ""]
    return "\n".join(L)
