import re
import tempfile
import unittest
from html.parser import HTMLParser

from app import create_app
from osint import report, username_check
from tests.fakes import FakeResponse, FakeSession

XSS = '<script>alert(1)</script><img src=x onerror=alert(2)>'


def fake_services(calls=None):
    calls = calls if calls is not None else []

    def whois(d):
        calls.append(("whois", d))
        return {"domain": d, "source": "rdap", "found": True, "registrar": XSS, "created": "2020-01-01", "expires": "2027-01-01",
                "updated": None, "age_days": 2000, "days_to_expiry": 100, "nameservers": ["ns1.x.test"], "status": [],
                "emails": [], "org": None, "country": None, "dnssec": "unsigned", "privacy_protected": True, "errors": [],
                "observations": [{"level": "info", "text": "Registrant details are hidden " + XSS}]}

    def dns(d):
        calls.append(("dns", d))
        return {"domain": d, "resolver": "dnspython", "records": {"A": ["1.2.3.4"], "TXT": [XSS]}, "errors": {}, "nxdomain": False,
                "email_security": {"spf": {"present": False, "record": None, "policy": None},
                                   "dmarc": {"present": False, "record": None, "policy": None},
                                   "dkim_selectors_found": [], "dkim_checked": True},
                "observations": [{"level": "warn", "text": "No SPF record found."}, {"level": "high", "text": "SPF allows every sender (+all)."}]}

    def ip(i):
        calls.append(("ip", i))
        return {"ip": i, "version": 4, "reverse_dns": "h.example.test", "registry": {"network_name": "NET", "country": "US"},
                "geolocation": {"country": "United States", "city": XSS}, "errors": {"geolocation": "partial"},
                "observations": [{"level": "info", "text": "approx"}]}

    def user(u):
        calls.append(("username", u))
        s = FakeSession({"api.github.com": FakeResponse(200)})
        return username_check.check_username(u, session=s)

    return {"whois": whois, "dns": dns, "ip": ip, "username": user}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.calls = []
        self.app = create_app({"DATABASE": f"{self.tmp.name}/t.db", "SECRET_KEY": "test", "TESTING": True},
                              services=fake_services(self.calls))
        self.c = self.app.test_client()

    def token(self, path="/"):
        html = self.c.get(path).get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def post(self, path, data=None, token=None, **kw):
        data = dict(data or {})
        data["csrf"] = token if token is not None else self.token()
        return self.c.post(path, data=data, **kw)

    def make_case(self, **over):
        form = {"title": "Acme review", "analyst": "Sam", "authorization": "Written permission from Acme, ref SOW-1", "notes": "n", "confirm": "yes"}
        form.update(over)
        r = self.post("/cases", form)
        return r

    def case_id(self):
        r = self.make_case()
        self.assertEqual(r.status_code, 302)
        return int(r.headers["Location"].rstrip("/").split("/")[-1].split("?")[0])


class SecurityTests(Base):
    def test_post_without_csrf_rejected(self):
        self.c.get("/")
        r = self.c.post("/cases", data={"title": "x"})
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/cases", data={"title": "x", "csrf": "wrong"})
        self.assertEqual(r.status_code, 400)

    def test_unexpected_host_rejected(self):
        r = self.c.get("/", headers={"Host": "evil.example.com"})
        self.assertEqual(r.status_code, 400)
        for host in ("127.0.0.1:5000", "localhost:5000", "127.0.0.1"):
            self.assertEqual(self.c.get("/", headers={"Host": host}).status_code, 200, host)

    def test_security_headers(self):
        r = self.c.get("/")
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_no_inline_script_or_style_in_pages(self):
        cid = self.case_id()
        self.post(f"/case/{cid}/run/whois", {"target": "example.com"})
        for path in (f"/", f"/case/{cid}", f"/case/{cid}/report"):
            html = self.c.get(path).get_data(as_text=True)
            self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)")
            self.assertNotRegex(html, r'\sstyle="')
            self.assertNotRegex(html, r'\son\w+="')

    def test_cookie_flags(self):
        r = self.c.get("/")
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_unknown_ids_and_kinds_404(self):
        self.assertEqual(self.c.get("/case/999").status_code, 404)
        self.assertEqual(self.c.get("/case/999/report").status_code, 404)
        cid = self.case_id()
        self.assertEqual(self.post(f"/case/{cid}/run/portscan", {"target": "example.com"}).status_code, 404)
        self.assertEqual(self.post("/case/999/run/whois", {"target": "example.com"}).status_code, 404)

    def test_oversized_body_rejected(self):
        self.c.get("/")
        r = self.c.post("/cases", data={"csrf": "x", "title": "a" * 70000})
        self.assertEqual(r.status_code, 413)


class CaseTests(Base):
    def test_create_requires_authorization_and_confirmation(self):
        for over in ({"title": ""}, {"analyst": " "}, {"authorization": "short"}, {"confirm": ""}):
            r = self.make_case(**over)
            self.assertEqual(r.status_code, 400, over)
        self.assertEqual(self.app.store.list_cases(), [])

    def test_create_and_list(self):
        cid = self.case_id()
        html = self.c.get("/").get_data(as_text=True)
        self.assertIn("Acme review", html)
        self.assertIn("0 results", html)
        self.assertEqual(self.c.get(f"/case/{cid}").status_code, 200)

    def test_lookup_validation_blocks_bad_targets_before_any_service_call(self):
        cid = self.case_id()
        bad = [("whois", "localhost"), ("whois", "10.0.0.1"), ("dns", "intranet"), ("ip", "192.168.1.1"), ("ip", "127.0.0.1"),
               ("ip", "169.254.169.254"), ("ip", "example.com"), ("username", "a/b"), ("username", "x"), ("whois", "")]
        for kind, target in bad:
            r = self.post(f"/case/{cid}/run/{kind}", {"target": target}, follow_redirects=True)
            self.assertEqual(r.status_code, 200)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.app.store.get_results(cid), [])

    def test_all_four_lookups_store_results(self):
        cid = self.case_id()
        for kind, target in [("whois", "Example.com"), ("dns", "https://example.com/x"), ("ip", "8.8.8.8"), ("username", "@octocat")]:
            r = self.post(f"/case/{cid}/run/{kind}", {"target": target})
            self.assertEqual(r.status_code, 302, kind)
        res = self.app.store.get_results(cid)
        self.assertEqual([(r["kind"], r["target"]) for r in res],
                         [("whois", "example.com"), ("dns", "example.com"), ("ip", "8.8.8.8"), ("username", "octocat")])
        self.assertIn("retrieved_at", res[0]["data"])

    def test_cache_avoids_second_service_call(self):
        cid = self.case_id()
        self.post(f"/case/{cid}/run/whois", {"target": "example.com"})
        self.post(f"/case/{cid}/run/whois", {"target": "EXAMPLE.com"})
        self.assertEqual([c for c in self.calls if c[0] == "whois"], [("whois", "example.com")])
        self.assertEqual(len(self.app.store.get_results(cid)), 2)

    def test_service_crash_is_handled(self):
        def boom(_):
            raise RuntimeError("secret internals /home/x")
        app = create_app({"DATABASE": f"{self.tmp.name}/b.db", "SECRET_KEY": "t"}, services={**fake_services(), "dns": boom})
        c = app.test_client()
        tok = re.search(r'value="([^"]+)"', c.get("/").get_data(as_text=True)).group(1)
        r = c.post("/cases", data={"csrf": tok, "title": "t", "analyst": "a", "authorization": "my own domain here", "confirm": "yes"})
        cid = r.headers["Location"].split("/")[-1]
        with self.assertLogs(app.logger, "ERROR"):
            r = c.post(f"/case/{cid}/run/dns", data={"csrf": tok, "target": "example.com"}, follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("failed unexpectedly", html)
        self.assertNotIn("secret internals", html)

    def test_rate_limit(self):
        app = create_app({"DATABASE": f"{self.tmp.name}/r.db", "SECRET_KEY": "t", "USERNAME_CHECKS_PER_MINUTE": 2},
                         services=fake_services())
        c = app.test_client()
        tok = re.search(r'value="([^"]+)"', c.get("/").get_data(as_text=True)).group(1)
        r = c.post("/cases", data={"csrf": tok, "title": "t", "analyst": "a", "authorization": "my own domain here", "confirm": "yes"})
        cid = r.headers["Location"].split("/")[-1]
        outs = []
        for name in ("alice", "bobby", "carol"):
            r = c.post(f"/case/{cid}/run/username", data={"csrf": tok, "target": name}, follow_redirects=True)
            outs.append("too many lookups" in r.get_data(as_text=True))
        self.assertEqual(outs, [False, False, True])
        self.assertEqual(len(app.store.get_results(int(cid))), 2)

    def test_delete_result_and_case(self):
        cid = self.case_id()
        self.post(f"/case/{cid}/run/ip", {"target": "8.8.8.8"})
        rid = self.app.store.get_results(cid)[0]["id"]
        other = self.case_id()
        self.post(f"/case/{other}/result/{rid}/delete")  # wrong case: must not delete
        self.assertEqual(len(self.app.store.get_results(cid)), 1)
        self.post(f"/case/{cid}/result/{rid}/delete")
        self.assertEqual(self.app.store.get_results(cid), [])
        self.post(f"/case/{cid}/delete")
        self.assertIsNone(self.app.store.get_case(cid))

    def test_notes_saved(self):
        cid = self.case_id()
        self.post(f"/case/{cid}/notes", {"notes": "line1\nline2 \x00\x07"})
        self.assertEqual(self.app.store.get_case(cid)["notes"], "line1\nline2")


class Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.attrs = [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += [(tag, k, v) for k, v in attrs]


class ReportTests(Base):
    def full_case(self):
        cid = self.case_id()
        self.post(f"/case/{cid}/notes", {"notes": "Note " + XSS})
        for kind, target in [("whois", "example.com"), ("dns", "example.com"), ("ip", "8.8.8.8"), ("username", "octocat")]:
            self.post(f"/case/{cid}/run/{kind}", {"target": target})
        return cid

    def test_html_report_escapes_everything(self):
        cid = self.full_case()
        for path in (f"/case/{cid}/report", f"/case/{cid}/report.html", f"/case/{cid}"):
            r = self.c.get(path)
            self.assertEqual(r.status_code, 200)
            html = r.get_data(as_text=True)
            self.assertNotIn("<script>alert", html)
            self.assertNotIn("<img src=x", html)
            p = Collector()
            p.feed(html)
            self.assertNotIn("img", p.tags)
            self.assertFalse([a for a in p.attrs if a[1].startswith("on")], path)
            self.assertIn("&lt;script&gt;", html)

    def test_report_contents(self):
        cid = self.full_case()
        html = self.c.get(f"/case/{cid}/report").get_data(as_text=True)
        for needle in ("Investigation report", "Acme review", "Written permission from Acme", "No SPF record found.",
                       "SPF allows every sender", "Limitations", "GitHub", "h.example.test", "Found 1"):
            self.assertIn(needle, html)
        # observations are sorted High before Warning before Note
        self.assertLess(html.index("SPF allows every sender"), html.index("No SPF record found."))

    def test_downloads(self):
        cid = self.full_case()
        h = self.c.get(f"/case/{cid}/report.html")
        self.assertIn("attachment", h.headers["Content-Disposition"])
        self.assertIn("<style>", h.get_data(as_text=True))
        self.assertIn("style-src 'unsafe-inline'", h.get_data(as_text=True))
        m = self.c.get(f"/case/{cid}/report.md")
        self.assertIn("attachment", m.headers["Content-Disposition"])
        text = m.get_data(as_text=True)
        self.assertTrue(text.startswith("# Investigation report: Acme review"))
        self.assertIn("## DNS records: example.com", text)
        self.assertIn("| GitHub | found |", text)

    def test_markdown_escaping(self):
        self.assertEqual(report.md("a|b\nc"), "a\\|b c")
        out = report.md(XSS)
        self.assertNotIn("<", out.replace("\\<", ""))
        self.assertNotIn("\x00", report.md("a\x00b\x0bc"))
        cid = self.full_case()
        text = self.c.get(f"/case/{cid}/report.md").get_data(as_text=True)
        self.assertNotIn("<script>", text)
        # a table row must stay on one line
        for line in text.splitlines():
            if line.startswith("| Registrar"):
                self.assertTrue(line.endswith("|"))

    def test_empty_report_works(self):
        cid = self.case_id()
        self.assertEqual(self.c.get(f"/case/{cid}/report").status_code, 200)
        self.assertEqual(self.c.get(f"/case/{cid}/report.md").status_code, 200)
        self.assertEqual(self.c.get(f"/case/{cid}/report.html").status_code, 200)


if __name__ == "__main__":
    unittest.main()


class EmptyFieldTests(Base):
    def test_empty_fields_are_not_rendered_but_zero_is(self):
        cid = self.case_id()
        self.post(f"/case/{cid}/run/ip", {"target": "8.8.8.8"})
        html = self.c.get(f"/case/{cid}").get_data(as_text=True)
        self.assertNotIn("<th scope=\"row\">Range</th>", html)
        self.assertNotIn("<th scope=\"row\">ASN</th>", html)
        self.assertIn("<th scope=\"row\">Network</th>", html)
        self.app.store.add_result(cid, "whois", "zero.test", {"found": True, "age_days": 0, "days_to_expiry": 0, "nameservers": [], "status": [], "observations": []})
        html = self.c.get(f"/case/{cid}").get_data(as_text=True)
        self.assertIn("Domain age (days)</th><td>0</td>", html)
