"""Fake network pieces so tests never touch the internet."""

from __future__ import annotations

import json


class FakeResponse:
    def __init__(self, status=200, body="", url="", history=None, json_data=None):
        self.status_code = status
        self.text = body if json_data is None else json.dumps(json_data)
        self._json = json_data
        self.url = url
        self.history = history or []

    def json(self):
        if self._json is not None:
            return self._json
        return json.loads(self.text)


class FakeSession:
    """Maps URL substrings to responses (or exceptions). Records every requested URL."""

    def __init__(self, routes=None, default=None):
        self.routes = routes or {}
        self.default = default if default is not None else FakeResponse(404)
        self.calls = []
        self.headers = {}

    def get(self, url, **kw):
        self.calls.append(url)
        for key, value in self.routes.items():
            if key in url:
                if isinstance(value, Exception):
                    raise value
                return value(url) if callable(value) else value
        return self.default


class FakeResolver:
    """Mimics dns.resolver.Resolver.resolve using a {(name, type): [text,...]} table."""

    class _R:
        def __init__(self, text):
            self._t = text

        def to_text(self):
            return self._t

    def __init__(self, table, errors=None):
        self.table = table
        self.errors = errors or {}

    def resolve(self, name, rtype):
        key = (name, rtype)
        if key in self.errors:
            raise self.errors[key]
        if key in self.table:
            return [self._R(t) for t in self.table[key]]
        raise NoAnswer()


# dnspython's exception classes are matched by name, so plain classes are enough here.
class NoAnswer(Exception):
    pass


class NXDOMAIN(Exception):
    pass


class Timeout(Exception):
    pass


RDAP_DOMAIN = {
    "ldhName": "EXAMPLE.TEST",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "2020-05-01T10:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-05-01T10:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2026-01-02T00:00:00Z"},
    ],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.TEST"}, {"ldhName": "ns2.example.test."}],
    "secureDNS": {"delegationSigned": True},
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc."]]]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "REDACTED FOR PRIVACY"]]]},
    ],
}

RDAP_IP = {
    "name": "EXAMPLE-NET", "handle": "NET-192-0-2-0-1", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
    "country": "US", "type": "DIRECT ALLOCATION",
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Networks LLC"]]]}],
}

GEO = {"success": True, "country": "United States", "country_code": "US", "region": "California", "city": "Mountain View",
       "timezone": {"id": "America/Los_Angeles"}, "connection": {"asn": 15169, "org": "Example Org", "isp": "Example ISP", "domain": "example.test"}}
