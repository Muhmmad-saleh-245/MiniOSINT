"""Username availability check across public platforms.

For every platform the answer is one of:
  found      - the account page/API says the username exists
  not_found  - the platform says it does not exist
  unsure     - blocked, rate limited, login wall, timeout or an unreliable site

This tool only reports whether an account NAME exists. It never collects profile
content (photos, bios, friends, location) and refuses to run without authorization.
Platform endpoints can change at any time; always confirm a hit by hand.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

# kind: how to read the answer
#   status        200 -> found, 404 -> not_found
#   json_null     body "null" -> not_found, otherwise found
#   json_list     JSON list empty -> not_found, non-empty -> found
#   keybase       {"them":[null]} -> not_found
#   body_missing  200 and the marker text present -> not_found
# reliability "low": only an explicit 404 counts as not_found, everything else is "unsure".
# Medium and Pinterest are low because a live control test showed they answer 200 for random names.
PLATFORMS = [
    {"name": "GitHub", "profile": "https://github.com/{u}", "check": "https://api.github.com/users/{u}", "kind": "status", "reliability": "high"},
    {"name": "GitLab", "profile": "https://gitlab.com/{u}", "check": "https://gitlab.com/api/v4/users?username={u}", "kind": "json_list", "reliability": "high"},
    {"name": "Hacker News", "profile": "https://news.ycombinator.com/user?id={u}", "check": "https://hacker-news.firebaseio.com/v0/user/{u}.json", "kind": "json_null", "reliability": "high"},
    {"name": "Keybase", "profile": "https://keybase.io/{u}", "check": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}&fields=basics", "kind": "keybase", "reliability": "high"},
    {"name": "Dev.to", "profile": "https://dev.to/{u}", "check": "https://dev.to/api/users/by_username?url={u}", "kind": "status", "reliability": "high"},
    {"name": "Docker Hub", "profile": "https://hub.docker.com/u/{u}", "check": "https://hub.docker.com/v2/users/{u}/", "kind": "status", "reliability": "medium"},
    {"name": "Reddit", "profile": "https://www.reddit.com/user/{u}", "check": "https://www.reddit.com/user/{u}/about.json", "kind": "status", "reliability": "medium"},
    {"name": "Medium", "profile": "https://medium.com/@{u}", "check": "https://medium.com/@{u}", "kind": "status", "reliability": "low"},
    {"name": "Steam", "profile": "https://steamcommunity.com/id/{u}", "check": "https://steamcommunity.com/id/{u}", "kind": "body_missing", "marker": "The specified profile could not be found", "reliability": "medium"},
    {"name": "YouTube", "profile": "https://www.youtube.com/@{u}", "check": "https://www.youtube.com/@{u}", "kind": "status", "reliability": "medium"},
    {"name": "SoundCloud", "profile": "https://soundcloud.com/{u}", "check": "https://soundcloud.com/{u}", "kind": "status", "reliability": "medium"},
    {"name": "Vimeo", "profile": "https://vimeo.com/{u}", "check": "https://vimeo.com/{u}", "kind": "status", "reliability": "medium"},
    {"name": "Pinterest", "profile": "https://www.pinterest.com/{u}/", "check": "https://www.pinterest.com/{u}/", "kind": "status", "reliability": "low"},
    {"name": "Instagram", "profile": "https://www.instagram.com/{u}/", "check": "https://www.instagram.com/{u}/", "kind": "status", "reliability": "low"},
    {"name": "TikTok", "profile": "https://www.tiktok.com/@{u}", "check": "https://www.tiktok.com/@{u}", "kind": "status", "reliability": "low"},
    {"name": "X (Twitter)", "profile": "https://x.com/{u}", "check": "https://x.com/{u}", "kind": "status", "reliability": "low"},
]

_LOGIN_HINTS = ("login", "signin", "sign_in", "accounts/login", "consent", "captcha", "challenge")


def classify(resp, spec: dict) -> tuple[str, str]:
    """Turn an HTTP response into (status, short explanation)."""
    code = resp.status_code
    if code in (401, 403, 429) or code >= 500:
        return "unsure", f"blocked or rate limited (HTTP {code})"
    final = str(getattr(resp, "url", "") or "").lower()
    if getattr(resp, "history", None) and any(h in final for h in _LOGIN_HINTS):
        return "unsure", "redirected to a login or check page"
    kind, low = spec["kind"], spec.get("reliability") == "low"
    if code == 404:
        if kind in ("status", "body_missing"):
            return "not_found", "HTTP 404"
        return "unsure", "unexpected 404"
    if code != 200:
        return "unsure", f"unexpected HTTP {code}"
    try:
        if kind == "status":
            return ("unsure", "site answers 200 for everyone (unreliable)") if low else ("found", "HTTP 200")
        if kind == "json_null":
            return ("not_found", "API returned null") if resp.text.strip() == "null" else ("found", "API returned a user")
        if kind == "json_list":
            data = resp.json()
            if not isinstance(data, list):
                return "unsure", "unexpected API reply"
            return ("found", "API returned a user") if data else ("not_found", "API returned an empty list")
        if kind == "keybase":
            data = resp.json()
            them = data.get("them") if isinstance(data, dict) else None
            if not isinstance(them, list) or not them:
                return "unsure", "unexpected API reply"
            return ("found", "API returned a user") if them[0] else ("not_found", "API returned no user")
        if kind == "body_missing":
            return ("not_found", "page says the profile does not exist") if spec["marker"] in resp.text else ("found", "HTTP 200")
    except ValueError:
        return "unsure", "unreadable reply"
    return "unsure", "unknown check type"


def _check_one(session, username: str, spec: dict, timeout: int) -> dict:
    row = {"platform": spec["name"], "url": spec["profile"].format(u=username),
           "reliability": spec["reliability"], "status": "unsure", "detail": ""}
    try:
        resp = session.get(spec["check"].format(u=username), timeout=timeout, allow_redirects=True,
                           headers={"Accept": "application/json, text/html;q=0.8"})
        row["status"], row["detail"] = classify(resp, spec)
    except Exception as exc:
        row["detail"] = f"request failed ({type(exc).__name__})"
    return row


def check_username(username: str, *, session, platforms=None, workers: int = 4, timeout: int = 8) -> dict:
    """Check a validated username on every platform (a few at a time, politely)."""
    platforms = platforms or PLATFORMS
    with ThreadPoolExecutor(max_workers=workers) as pool:
        rows = list(pool.map(lambda p: _check_one(session, username, p, timeout), platforms))
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("found", "not_found", "unsure")}
    obs = []
    if counts["found"]:
        obs.append({"level": "info", "text": f"The username exists on {counts['found']} platform(s). A matching name does not prove it is the same person."})
    if counts["unsure"]:
        obs.append({"level": "info", "text": f"{counts['unsure']} result(s) are unsure (blocked, login wall or unreliable site). Check those manually."})
    return {"username": username, "results": rows, "counts": counts, "observations": obs}
