import unittest
from datetime import date, datetime

from osint import dns_lookup, ip_lookup, username_check, whois_lookup
from osint.validate import ValidationError, normalize_domain, normalize_ip, normalize_username

from tests.fakes import (GEO, NXDOMAIN, RDAP_DOMAIN, RDAP_IP, FakeResolver, FakeResponse, FakeSession, Timeout)


class ValidateTests(unittest.TestCase):
    def test_domain_cleaning(self):
        cases = {
            "Example.COM": "example.com",
            "https://www.Example.com:8443/a/b?x=1": "www.example.com",
            "example.com/path": "example.com",
            "user:pw@example.com": "example.com",
            "example.com.": "example.com",
            "  example.com  ": "example.com",
            "bücher.de": "xn--bcher-kva.de",
        }
        for raw, want in cases.items():
            self.assertEqual(normalize_domain(raw), want, raw)

    def test_domain_rejections(self):
        bad = ["", "   ", "localhost", "intranet", "a.local", "server.internal", "x.localhost", "127.0.0.1",
               "-bad.com", "bad-.com", "a b.com", "exa_mple.com", "example.123", "a" * 64 + ".com",
               "http://", "[::1]", "my.home.arpa", ("a." * 130) + "com", None, 5]
        for raw in bad:
            with self.assertRaises(ValidationError, msg=repr(raw)):
                normalize_domain(raw)

    def test_ip_accepts_public_only(self):
        self.assertEqual(normalize_ip(" 8.8.8.8 "), "8.8.8.8")
        self.assertEqual(normalize_ip("[2606:4700:4700::1111]"), "2606:4700:4700::1111")
        for bad in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254", "0.0.0.0",
                    "::1", "fe80::1", "224.0.0.1", "100.64.0.1", "::ffff:10.0.0.1", "999.1.1.1", "abc", "", "1.2.3"]:
            with self.assertRaises(ValidationError, msg=bad):
                normalize_ip(bad)

    def test_username(self):
        self.assertEqual(normalize_username(" @octocat "), "octocat")
        for bad in ["a", "x" * 33, "bad name", "a/b", "a?b", "../x", "é", "", None, "a\nb"]:
            with self.assertRaises(ValidationError, msg=repr(bad)):
                normalize_username(bad)


class WhoisTests(unittest.TestCase):
    TODAY = date(2026, 11, 15)

    def test_rdap_parsing(self):
        s = FakeSession({"rdap.org/domain/": FakeResponse(200, json_data=RDAP_DOMAIN)})
        r = whois_lookup.lookup("example.test", session=s, use_whois_lib=False, today=self.TODAY)
        self.assertEqual(r["source"], "rdap")
        self.assertTrue(r["found"])
        self.assertEqual(r["registrar"], "Example Registrar Inc.")
        self.assertEqual(r["created"], "2020-05-01")
        self.assertEqual(r["expires"], "2027-05-01")
        self.assertEqual(r["nameservers"], ["ns1.example.test", "ns2.example.test"])
        self.assertTrue(r["privacy_protected"])
        self.assertIsNone(r["org"])
        self.assertEqual(r["dnssec"], "signed")
        self.assertGreater(r["age_days"], 2000)
        self.assertEqual(r["days_to_expiry"], (date(2027, 5, 1) - self.TODAY).days)

    def test_rdap_not_found(self):
        s = FakeSession({"rdap.org": FakeResponse(404)})
        r = whois_lookup.lookup("nope.test", session=s, use_whois_lib=False, today=self.TODAY)
        self.assertIs(r["found"], False)
        self.assertIn("No registration record", r["observations"][0]["text"])

    def test_rdap_http_error_and_network_error(self):
        r = whois_lookup.lookup("x.test", session=FakeSession({"rdap": FakeResponse(500)}), use_whois_lib=False)
        self.assertIsNone(r["found"])
        self.assertTrue(r["errors"])
        r = whois_lookup.lookup("x.test", session=FakeSession({"rdap": ConnectionError("boom")}), use_whois_lib=False)
        self.assertIsNone(r["found"])
        self.assertIn("RDAP request failed", r["errors"][0])

    def test_whois_library_path(self):
        class Lib:
            @staticmethod
            def whois(domain):
                return {"domain_name": ["EXAMPLE.TEST", "example.test"], "registrar": "Reg Co",
                        "creation_date": [datetime(2026, 11, 1, 5), datetime(2026, 11, 2)],
                        "expiration_date": datetime(2026, 11, 25), "name_servers": ["NS1.X.TEST", "ns1.x.test"],
                        "status": ["clientTransferProhibited https://icann.org/epp"], "org": "Domains By Proxy, LLC",
                        "emails": ["abuse@reg.test"]}
        r = whois_lookup.lookup("example.test", whois_module=Lib, today=self.TODAY)
        self.assertEqual(r["source"], "whois")
        self.assertEqual(r["created"], "2026-11-01")
        self.assertEqual(r["nameservers"], ["ns1.x.test"])
        self.assertEqual(r["status"], ["clientTransferProhibited"])
        self.assertTrue(r["privacy_protected"])
        texts = " ".join(o["text"] for o in r["observations"])
        self.assertIn("Newly registered", texts)
        self.assertIn("expires in 10 days", texts)

    def test_whois_library_failure_falls_back_to_rdap(self):
        class Lib:
            @staticmethod
            def whois(domain):
                raise RuntimeError("port 43 blocked")
        s = FakeSession({"rdap.org/domain/": FakeResponse(200, json_data=RDAP_DOMAIN)})
        r = whois_lookup.lookup("example.test", session=s, whois_module=Lib, today=self.TODAY)
        self.assertEqual(r["source"], "rdap")
        self.assertTrue(any("WHOIS failed" in e for e in r["errors"]))

    def test_whois_empty_record_falls_back(self):
        class Lib:
            @staticmethod
            def whois(domain):
                return {"domain_name": None}
        s = FakeSession({"rdap.org/domain/": FakeResponse(200, json_data=RDAP_DOMAIN)})
        self.assertEqual(whois_lookup.lookup("example.test", session=s, whois_module=Lib)["source"], "rdap")

    def test_expired_domain_is_high(self):
        data = dict(RDAP_DOMAIN, events=[{"eventAction": "expiration", "eventDate": "2026-10-01T00:00:00Z"}])
        r = whois_lookup.lookup("example.test", session=FakeSession({"rdap": FakeResponse(200, json_data=data)}),
                                use_whois_lib=False, today=self.TODAY)
        self.assertEqual(r["observations"][0]["level"], "high")

    def test_weird_rdap_shapes_do_not_crash(self):
        for data in [{}, {"entities": None, "events": None, "nameservers": None}, {"entities": [{"roles": ["registrant"]}]},
                     {"entities": [{"roles": ["registrar"], "vcardArray": "junk"}]}, {"events": [{"eventAction": "registration", "eventDate": "garbage"}]}]:
            r = whois_lookup.lookup("x.test", session=FakeSession({"rdap": FakeResponse(200, json_data=data)}), use_whois_lib=False)
            self.assertTrue(r["found"])


class DnsTests(unittest.TestCase):
    def make(self, table=None, errors=None, **kw):
        t = {("example.test", "A"): ["93.184.216.34"], ("example.test", "NS"): ["a.ns.test.", "b.ns.test."],
             ("example.test", "MX"): ["10 mail.example.test."],
             ("example.test", "TXT"): ['"v=spf1 include:_spf.example.test ~all"', '"google-site-verification=abc"'],
             ("_dmarc.example.test", "TXT"): ['"v=DMARC1; p=none; rua=mailto:r@example.test"'],
             ("default._domainkey.example.test", "TXT"): ['"v=DKIM1; k=rsa; " "p=MIGf"']}
        t.update(table or {})
        backend = dns_lookup.DnspythonBackend(FakeResolver(t, errors))
        return dns_lookup.lookup("example.test", backend=backend, **kw)

    def test_records_and_email_security(self):
        r = self.make()
        self.assertEqual(r["records"]["A"], ["93.184.216.34"])
        self.assertEqual(r["records"]["TXT"][0], "v=spf1 include:_spf.example.test ~all")
        es = r["email_security"]
        self.assertTrue(es["spf"]["present"])
        self.assertIn("soft fail", es["spf"]["policy"])
        self.assertEqual(es["dmarc"]["policy"], "none")
        self.assertEqual(es["dkim_selectors_found"], ["default"])
        texts = [o["text"] for o in r["observations"]]
        self.assertTrue(any("DMARC policy is 'none'" in t for t in texts))
        self.assertTrue(any("CAA" in t for t in texts))

    def test_missing_spf_dmarc_with_mail_is_warn(self):
        r = self.make({("example.test", "TXT"): [], ("_dmarc.example.test", "TXT"): []})
        levels = {o["text"]: o["level"] for o in r["observations"]}
        self.assertEqual(levels["No SPF record found."], "warn")
        self.assertEqual(levels["No DMARC record found."], "warn")

    def test_dangerous_spf(self):
        r = self.make({("example.test", "TXT"): ['"v=spf1 +all"']})
        self.assertTrue(r["email_security"]["spf"]["dangerous"])
        self.assertTrue(any(o["level"] == "high" for o in r["observations"]))

    def test_nxdomain(self):
        backend = dns_lookup.DnspythonBackend(FakeResolver({}, {("gone.test", t): NXDOMAIN() for t in dns_lookup.RECORD_TYPES}))
        r = dns_lookup.lookup("gone.test", backend=backend)
        self.assertTrue(r["nxdomain"])
        self.assertIsNone(r["email_security"])
        self.assertIn("NXDOMAIN", r["observations"][0]["text"])

    def test_total_failure_is_reported(self):
        errs = {("example.test", t): Timeout() for t in dns_lookup.RECORD_TYPES}
        r = self.make(errors=errs)
        self.assertEqual(len(r["errors"]), len(dns_lookup.RECORD_TYPES))
        self.assertIn("Every DNS query failed", r["observations"][0]["text"])

    def test_partial_failure_keeps_other_records(self):
        r = self.make(errors={("example.test", "MX"): Timeout()})
        self.assertIn("MX", r["errors"])
        self.assertEqual(r["records"]["A"], ["93.184.216.34"])

    def test_txt_clean(self):
        self.assertEqual(dns_lookup.txt_clean('"a" "b"'), "ab")
        self.assertEqual(dns_lookup.txt_clean('"say \\"hi\\""'), 'say \\"hi\\"')
        self.assertEqual(dns_lookup.txt_clean("plain"), "plain")

    def test_doh_backend(self):
        def reply(url):
            if "type=A" in url and "name=example.test" in url:
                return FakeResponse(200, json_data={"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})
            if "name=gone.test" in url:
                return FakeResponse(200, json_data={"Status": 3})
            return FakeResponse(200, json_data={"Status": 0})
        backend = dns_lookup.DohBackend(FakeSession({"cloudflare-dns.com": reply}))
        self.assertEqual(backend.query("example.test", "A"), ["1.2.3.4"])
        with self.assertRaises(dns_lookup.NoRecord):
            backend.query("example.test", "MX")
        with self.assertRaises(dns_lookup.NoDomain):
            backend.query("gone.test", "A")
        r = dns_lookup.lookup("example.test", backend=backend, check_dkim=False)
        self.assertEqual(r["resolver"], "doh-cloudflare")
        self.assertEqual(r["records"]["A"], ["1.2.3.4"])

    def test_no_backend_available(self):
        import unittest.mock as m
        with m.patch.object(dns_lookup, "DnspythonBackend", side_effect=ImportError("no dns")):
            r = dns_lookup.lookup("example.test")
        self.assertIsNone(r["resolver"])
        self.assertEqual(r["observations"][0]["level"], "warn")


class IpTests(unittest.TestCase):
    def test_full_lookup(self):
        s = FakeSession({"rdap.org/ip/": FakeResponse(200, json_data=RDAP_IP), "ipwho.is": FakeResponse(200, json_data=GEO)})
        r = ip_lookup.lookup("8.8.8.8", session=s, rdns=lambda ip: "dns.example.test")
        self.assertEqual(r["reverse_dns"], "dns.example.test")
        self.assertEqual(r["registry"]["organization"], "Example Networks LLC")
        self.assertEqual(r["registry"]["range"], "8.8.8.0 - 8.8.8.255")
        self.assertEqual(r["geolocation"]["asn"], 15169)
        self.assertEqual(r["errors"], {})
        self.assertEqual(r["version"], 4)

    def test_partial_failure(self):
        s = FakeSession({"rdap.org/ip/": ConnectionError("down"), "ipwho.is": FakeResponse(200, json_data=GEO)})
        r = ip_lookup.lookup("2606:4700:4700::1111", session=s, rdns=lambda ip: None)
        self.assertIsNone(r["registry"])
        self.assertIn("registry", r["errors"])
        self.assertIsNotNone(r["geolocation"])
        self.assertEqual(r["version"], 6)

    def test_all_fail(self):
        s = FakeSession({}, default=FakeResponse(500))
        r = ip_lookup.lookup("8.8.8.8", session=s, rdns=lambda ip: None)
        self.assertTrue(any("No registry or geolocation" in o["text"] for o in r["observations"]))

    def test_geo_api_error_message(self):
        s = FakeSession({"rdap.org": FakeResponse(404), "ipwho.is": FakeResponse(200, json_data={"success": False, "message": "Reserved range"})})
        r = ip_lookup.lookup("8.8.8.8", session=s, rdns=lambda ip: None)
        self.assertEqual(r["errors"]["geolocation"], "Reserved range")


class UsernameTests(unittest.TestCase):
    def spec(self, kind, **kw):
        return dict({"name": "T", "profile": "https://t.test/{u}", "check": "https://t.test/{u}", "kind": kind, "reliability": "high"}, **kw)

    def test_classify_matrix(self):
        R = FakeResponse
        cases = [
            (R(200), self.spec("status"), "found"),
            (R(404), self.spec("status"), "not_found"),
            (R(200), self.spec("status", reliability="low"), "unsure"),
            (R(404), self.spec("status", reliability="low"), "not_found"),
            (R(429), self.spec("status"), "unsure"),
            (R(403), self.spec("status"), "unsure"),
            (R(503), self.spec("status"), "unsure"),
            (R(301), self.spec("status"), "unsure"),
            (R(200, url="https://x.test/login?next=1", history=[object()]), self.spec("status"), "unsure"),
            (R(200, url="https://api.test/users/login"), self.spec("status"), "found"),  # no redirect: a user may be named 'login'
            (R(200, body="null"), self.spec("json_null"), "not_found"),
            (R(200, body='{"id":1}'), self.spec("json_null"), "found"),
            (R(200, json_data=[]), self.spec("json_list"), "not_found"),
            (R(200, json_data=[{"id": 1}]), self.spec("json_list"), "found"),
            (R(200, json_data={"x": 1}), self.spec("json_list"), "unsure"),
            (R(200, json_data={"them": [None]}), self.spec("keybase"), "not_found"),
            (R(200, json_data={"them": [{"basics": {}}]}), self.spec("keybase"), "found"),
            (R(200, json_data={"them": []}), self.spec("keybase"), "unsure"),
            (R(200, body="<html>The specified profile could not be found</html>"), self.spec("body_missing", marker="could not be found"), "not_found"),
            (R(200, body="<html>profile</html>"), self.spec("body_missing", marker="could not be found"), "found"),
            (R(404), self.spec("json_null"), "unsure"),
            (R(200, body="<html>not json"), self.spec("json_list"), "unsure"),
        ]
        for resp, spec, want in cases:
            self.assertEqual(username_check.classify(resp, spec)[0], want, (resp.status_code, spec["kind"], want))

    def test_run_all_platforms_and_errors_become_unsure(self):
        def route(url):
            if "api.github.com" in url:
                return FakeResponse(200)
            if "gitlab.com/api" in url:
                return FakeResponse(200, json_data=[])
            if "hacker-news" in url:
                return ConnectionError  # not callable result; handled below
            return FakeResponse(404)
        s = FakeSession({"api.github.com": FakeResponse(200), "gitlab.com/api": FakeResponse(200, json_data=[]),
                         "hacker-news": ConnectionError("net down")})
        out = username_check.check_username("octocat", session=s)
        by = {r["platform"]: r for r in out["results"]}
        self.assertEqual(len(out["results"]), len(username_check.PLATFORMS))
        self.assertEqual(by["GitHub"]["status"], "found")
        self.assertEqual(by["GitHub"]["url"], "https://github.com/octocat")
        self.assertEqual(by["GitLab"]["status"], "not_found")
        self.assertEqual(by["Hacker News"]["status"], "unsure")
        self.assertIn("request failed", by["Hacker News"]["detail"])
        self.assertEqual(sum(out["counts"].values()), len(out["results"]))

    def test_known_false_positive_sites_are_low_reliability(self):
        """A live control test (random username) showed these answer HTTP 200 for any name."""
        by = {p["name"]: p for p in username_check.PLATFORMS}
        for name in ("Medium", "Pinterest", "Instagram", "TikTok", "X (Twitter)"):
            self.assertEqual(by[name]["reliability"], "low", name)
            self.assertEqual(username_check.classify(FakeResponse(200), by[name])[0], "unsure", name)

    def test_all_platform_specs_are_well_formed(self):
        names = set()
        for p in username_check.PLATFORMS:
            self.assertNotIn(p["name"], names)
            names.add(p["name"])
            self.assertTrue(p["profile"].startswith("https://") and "{u}" in p["profile"])
            self.assertTrue(p["check"].startswith("https://") and "{u}" in p["check"])
            self.assertIn(p["kind"], {"status", "json_null", "json_list", "keybase", "body_missing"})
            self.assertIn(p["reliability"], {"high", "medium", "low"})
            if p["kind"] == "body_missing":
                self.assertTrue(p["marker"])


if __name__ == "__main__":
    unittest.main()
