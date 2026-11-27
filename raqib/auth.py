import secrets
from functools import wraps

from flask import abort, g, redirect, request, session, url_for


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def check_csrf():
    if request.method != "POST":
        return
    sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token") or ""
    if not secrets.compare_digest(sent, session.get("csrf", "")):
        abort(400)


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("live")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapper
