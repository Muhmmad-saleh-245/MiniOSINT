"""Mini OSINT Toolkit: local Flask dashboard.

Run:   python app.py            (opens on http://127.0.0.1:5000)
Check: python app.py selftest   (tries every lookup once on a safe example, needs internet)
"""

from __future__ import annotations

import copy
import os
import secrets
import time
from collections import deque
from pathlib import Path

from flask import (Flask, Response, abort, flash, redirect, render_template, request, session, url_for)

from osint import dns_lookup, ip_lookup, report, username_check, whois_lookup
from osint.http import make_session
from osint.storage import Store, now_iso
from osint.validate import ValidationError, normalize_domain, normalize_ip, normalize_username

KINDS = {
    "whois": ("Domain (WHOIS)", normalize_domain, "example.com"),
    "dns": ("DNS records", normalize_domain, "example.com"),
    "ip": ("IP address", normalize_ip, "8.8.8.8"),
    "username": ("Username", normalize_username, "octocat"),
}
MAX_RESULTS_PER_CASE = 200
CSP = ("default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
       "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")


class RateLimiter:
    def __init__(self, limit: int, window: int = 60):
        self.limit, self.window, self.hits = limit, window, deque()

    def allow(self) -> bool:
        now = time.monotonic()
        while self.hits and now - self.hits[0] > self.window:
            self.hits.popleft()
        if len(self.hits) >= self.limit:
            return False
        self.hits.append(now)
        return True


def default_services(http_session) -> dict:
    return {
        "whois": lambda d: whois_lookup.lookup(d, session=http_session),
        "dns": lambda d: dns_lookup.lookup(d, session=http_session),
        "ip": lambda ip: ip_lookup.lookup(ip, session=http_session),
        "username": lambda u: username_check.check_username(u, session=http_session),
    }


def _load_secret(instance: Path) -> bytes:
    path = instance / "secret.key"
    if path.exists():
        return path.read_bytes()
    key = secrets.token_bytes(32)
    path.write_bytes(key)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def create_app(config: dict | None = None, services: dict | None = None) -> Flask:
    app = Flask(__name__, instance_path=str(Path(__file__).parent / "instance"))
    app.config.update(DATABASE=None, ALLOWED_HOSTS=(), CACHE_TTL=600, LOOKUPS_PER_MINUTE=30,
                      USERNAME_CHECKS_PER_MINUTE=6, MAX_CONTENT_LENGTH=64 * 1024)
    app.config.update(config or {})
    os.makedirs(app.instance_path, exist_ok=True)
    app.secret_key = app.config.get("SECRET_KEY") or _load_secret(Path(app.instance_path))
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")

    store = Store(app.config["DATABASE"] or os.path.join(app.instance_path, "osint.db"))
    svc = services or default_services(make_session())
    cache: dict = {}
    limit_all = RateLimiter(app.config["LOOKUPS_PER_MINUTE"])
    limit_user = RateLimiter(app.config["USERNAME_CHECKS_PER_MINUTE"])
    allowed_hosts = {"127.0.0.1", "localhost", "[::1]"} | set(app.config["ALLOWED_HOSTS"])
    app.store = store  # handy for tests

    # ---------- security plumbing ----------
    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["KINDS"] = KINDS

    @app.before_request
    def guard():
        host = request.host.rsplit(":", 1)[0] if not request.host.startswith("[") else request.host.split("]")[0] + "]"
        if host not in allowed_hosts:
            abort(400, "Unexpected Host header.")
        if request.method == "POST":
            sent = request.form.get("csrf", "")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                abort(400, "Security token missing or expired. Go back, reload the page and try again.")

    @app.after_request
    def headers(resp: Response):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def friendly(err):
        return render_template("error.html", code=err.code, message=err.description), err.code

    # ---------- helpers ----------
    def get_case_or_404(case_id: int) -> dict:
        case = store.get_case(case_id)
        if not case:
            abort(404, "That investigation does not exist.")
        return case

    def clean(text: str, limit: int) -> str:
        return "".join(ch for ch in (text or "") if ch == "\n" or (ch >= " " and ch != "\x7f")).strip()[:limit]

    # ---------- pages ----------
    @app.get("/")
    def index():
        return render_template("index.html", cases=store.list_cases())

    @app.post("/cases")
    def new_case():
        title, analyst = clean(request.form.get("title"), 120), clean(request.form.get("analyst"), 80)
        auth, notes = clean(request.form.get("authorization"), 500), clean(request.form.get("notes"), 2000)
        problems = []
        if not title:
            problems.append("Give the investigation a title.")
        if not analyst:
            problems.append("Enter the analyst name.")
        if len(auth) < 10:
            problems.append("Describe your authorization (for example: 'my own domain', 'written permission from Acme, ref SOW-12', 'lab').")
        if request.form.get("confirm") != "yes":
            problems.append("You must confirm that the targets are authorized and the information is public.")
        if problems:
            for p in problems:
                flash(p, "error")
            return render_template("index.html", cases=store.list_cases(), form=request.form), 400
        case_id = store.create_case(title, analyst, auth, notes)
        flash("Investigation created.", "ok")
        return redirect(url_for("case_page", case_id=case_id))

    @app.get("/case/<int:case_id>")
    def case_page(case_id):
        case = get_case_or_404(case_id)
        tab = request.args.get("tab", "whois")
        if tab not in KINDS:
            tab = "whois"
        return render_template("case.html", case=case, tab=tab, results=store.get_results(case_id))

    @app.post("/case/<int:case_id>/run/<kind>")
    def run_lookup(case_id, kind):
        get_case_or_404(case_id)
        if kind not in KINDS:
            abort(404, "Unknown lookup type.")
        label, normalize, _ = KINDS[kind]
        back = redirect(url_for("case_page", case_id=case_id, tab=kind) + "#results")
        try:
            target = normalize(request.form.get("target", ""))
        except ValidationError as exc:
            flash(str(exc), "error")
            return back
        if len(store.get_results(case_id)) >= MAX_RESULTS_PER_CASE:
            flash("This investigation is full. Start a new one.", "error")
            return back
        key = (kind, target)
        hit = cache.get(key)
        if hit and time.monotonic() - hit[0] < app.config["CACHE_TTL"]:
            data, note = copy.deepcopy(hit[1]), " (reused a result fetched less than a few minutes ago)"
        else:
            if not limit_all.allow() or (kind == "username" and not limit_user.allow()):
                flash("Slow down: too many lookups in the last minute. Wait a little and try again.", "error")
                return back
            try:
                data = svc[kind](target)
            except Exception as exc:  # a lookup bug must never produce a stack trace page
                app.logger.exception("lookup failed")
                flash(f"The {label} lookup failed unexpectedly ({type(exc).__name__}).", "error")
                return back
            data["retrieved_at"] = now_iso()
            cache[key] = (time.monotonic(), copy.deepcopy(data))
            note = ""
        store.add_result(case_id, kind, target, data)
        flash(f"{label} for {target} added to the investigation{note}.", "ok")
        return back

    @app.post("/case/<int:case_id>/notes")
    def save_notes(case_id):
        get_case_or_404(case_id)
        store.update_notes(case_id, clean(request.form.get("notes"), 2000))
        flash("Notes saved.", "ok")
        return redirect(url_for("case_page", case_id=case_id))

    @app.post("/case/<int:case_id>/result/<int:result_id>/delete")
    def delete_result(case_id, result_id):
        get_case_or_404(case_id)
        store.delete_result(case_id, result_id)
        flash("Result removed.", "ok")
        return redirect(url_for("case_page", case_id=case_id) + "#results")

    @app.post("/case/<int:case_id>/delete")
    def delete_case(case_id):
        get_case_or_404(case_id)
        store.delete_case(case_id)
        flash("Investigation deleted.", "ok")
        return redirect(url_for("index"))

    # ---------- report ----------
    def context(case_id):
        case = get_case_or_404(case_id)
        return report.build_context(case, store.get_results(case_id))

    @app.get("/case/<int:case_id>/report")
    def report_view(case_id):
        return render_template("report.html", ctx=context(case_id))

    @app.get("/case/<int:case_id>/report.md")
    def report_md(case_id):
        ctx = context(case_id)
        return Response(report.to_markdown(ctx), mimetype="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="osint-report-{case_id}.md"'})

    @app.get("/case/<int:case_id>/report.html")
    def report_html(case_id):
        css = (Path(app.static_folder) / "style.css").read_text(encoding="utf-8")
        body = render_template("report_standalone.html", ctx=context(case_id), css=css)
        return Response(body, mimetype="text/html",
                        headers={"Content-Disposition": f'attachment; filename="osint-report-{case_id}.html"'})

    return app


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Mini OSINT Toolkit")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="start the dashboard (default)")
    s.add_argument("--port", type=int, default=5000)
    t = sub.add_parser("selftest", help="try every lookup once on safe examples (needs internet)")
    t.add_argument("--domain", default="example.com")
    args = ap.parse_args(argv)
    if args.cmd == "selftest":
        from osint.selftest import run
        return run(args.domain)
    port = getattr(args, "port", 5000)
    print(f"Mini OSINT Toolkit: open http://127.0.0.1:{port}  (Ctrl+C to stop)")
    create_app().run(host="127.0.0.1", port=port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
