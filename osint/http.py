"""One shared way to make HTTP requests (so tests can swap in a fake session)."""

from __future__ import annotations

import requests

from . import USER_AGENT

DEFAULT_TIMEOUT = 10


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en"})
    return s


def get_json(session, url: str, *, accept: str = "application/json", timeout: int = DEFAULT_TIMEOUT):
    """GET a URL and return (status_code, parsed_json_or_None). Network errors raise."""
    resp = session.get(url, headers={"Accept": accept}, timeout=timeout, allow_redirects=True)
    data = None
    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            data = None
    return resp.status_code, data
