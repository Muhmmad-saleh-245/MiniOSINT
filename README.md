# Mini OSINT Toolkit

A beginner-friendly web dashboard (Python + Flask) for **passive OSINT** on **authorized targets**:

| Lookup | What you get |
|---|---|
| Domain (WHOIS) | registrar, dates, name servers, status, privacy flag. Uses `python-whois`, falls back to RDAP |
| DNS | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA + SPF / DMARC / DKIM-selector check. Uses `dnspython` (DNS-over-HTTPS fallback) |
| IP address | reverse DNS, registry owner (RDAP), approximate geolocation, ASN. Public IPs only |
| Username | exists / not found / unsure on 16 public sites (account name only, no profile content) |
| Report | per-investigation report with observations, as HTML (print to PDF) or Markdown |

Investigations ("cases") store the authorization statement, the lookups and your notes in a local SQLite file.

## Run
```bash
pip install -r requirements.txt
python app.py            # then open http://127.0.0.1:5000
python app.py selftest   # checks every lookup once on your internet connection
python -m unittest discover -s tests -t .
```
Windows: double-click `start_windows.bat`. Mac/Linux: `./start.sh`.

## Safety rules built in
- Authorization text + confirmation tick required to create an investigation.
- Private / loopback / link-local / reserved IPs and internal names (`localhost`, `.local`, `.internal` ...) are refused, so it cannot probe your own network.
- Rate limits, timeouts, caching. No port scanning, no vulnerability scanning, no subdomain guessing, no profile scraping.
- Server listens on 127.0.0.1 only; CSRF tokens, Host check, strict Content-Security-Policy, all output escaped.

## Known limits (honest list)
- Built and unit-tested (50 tests) with **simulated network replies** and checked in a real browser. The live WHOIS, DNS, IP and platform requests were **not** tested by the author (no internet in the build sandbox). Run `python app.py selftest` first.
- `python-whois` and `dnspython` code paths are tested through stand-ins, not the real packages. The DoH fallback is tested the same way.
- Username-check endpoints and the free IP API (`ipwho.is`) can change or rate-limit; sites often block bots, which shows as **unsure**. Always confirm a hit by hand. A matching name is not proof of identity.
- WHOIS owner details are usually hidden by privacy rules. The tool says so instead of guessing.
- Single user, local use only. Do not expose it to a network.

Only investigate your own assets, authorized clients, or lab targets.
