"""`python app.py selftest`: run each lookup once against safe, well-known public targets.

Use it on your own computer to confirm that WHOIS, DNS, IP and username checks work
with your internet connection. It does not save anything.
"""

from __future__ import annotations

import time

from . import dns_lookup, ip_lookup, username_check, whois_lookup
from .http import make_session


def _step(name, fn, check):
    start = time.time()
    try:
        data = fn()
        ok, note = check(data)
    except Exception as exc:
        ok, note = False, f"crashed: {type(exc).__name__}: {exc}"
    print(f"[{'PASS' if ok else 'FAIL'}] {name:<28} {note}  ({time.time() - start:.1f}s)")
    return ok


def run(domain: str = "example.com") -> int:
    session = make_session()
    ok = []
    ok.append(_step(f"WHOIS/RDAP {domain}", lambda: whois_lookup.lookup(domain, session=session),
                    lambda d: (d.get("found") is True, f"source={d.get('source')} registrar={d.get('registrar')} errors={d.get('errors')}")))
    ok.append(_step("RDAP only (fallback path)", lambda: whois_lookup.lookup(domain, session=session, use_whois_lib=False),
                    lambda d: (d.get("found") is True, f"created={d.get('created')} ns={len(d.get('nameservers', []))}")))
    ok.append(_step(f"DNS {domain}", lambda: dns_lookup.lookup(domain, session=session),
                    lambda d: (bool(d["records"].get("A")), f"resolver={d.get('resolver')} A={d['records'].get('A')} errors={d.get('errors')}")))
    ok.append(_step("IP 1.1.1.1", lambda: ip_lookup.lookup("1.1.1.1", session=session),
                    lambda d: (bool(d.get("registry") or d.get("geolocation")), f"rdns={d.get('reverse_dns')} errors={d.get('errors')}")))

    def users():
        return username_check.check_username("github", session=session)
    ok.append(_step("Username 'github'", users,
                    lambda d: (d["counts"]["found"] >= 1, f"counts={d['counts']}")))
    print("\nUsername detail (verify a few by hand; websites change):")
    try:
        for r in users()["results"]:
            print(f"   {r['platform']:<12} {r['status']:<10} {r['detail']}")
    except Exception as exc:
        print("   could not run:", exc)
    # Control test: a random name that should exist nowhere. Any "found" here is a false positive.
    import secrets
    ghost = "zq" + secrets.token_hex(5)
    print(f"\nControl test with a random name ({ghost}); every platform should say not_found or unsure:")
    try:
        bad = [r for r in username_check.check_username(ghost, session=session)["results"] if r["status"] == "found"]
        for r in bad:
            print(f"   FALSE POSITIVE: {r['platform']} says found ({r['detail']})")
        print("   none, good" if not bad else "   Tell the author which platforms are listed above.")
        ok.append(not bad)
    except Exception as exc:
        print("   could not run:", exc)
        ok.append(False)
    print("\nAll passed." if all(ok) else "\nSome checks failed. Read the notes above (firewall, VPN, or a website change).")
    return 0 if all(ok) else 1
