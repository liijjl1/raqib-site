import os
import secrets
import shutil
import tempfile
import uuid

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session,
                   url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from raqib.auth import admin_required, check_csrf, csrf_token, login_required, safe_next
from raqib.content import REFERENCES, SETTING_LABELS, SETTINGS
from raqib.database import Database
from raqib.experiment import (guess_label, guess_normal, load_or_run_lab, prepare_dataset, read_csv_sample,
                              report_json, run_experiment)
from raqib.models import MODEL_KEYS, MODEL_NAMES, POLICIES
from raqib.monitor import LiveMonitor
from raqib.traffic import ATTACK_NAMES_AR, ATTACK_TYPES, DEVICE_NAMES_AR, DEVICES, FEATURE_NAMES_AR, generate_dataset

HERE = os.path.dirname(os.path.abspath(__file__))
INSTANCE = os.path.join(HERE, "instance")
REPORTS = os.path.join(HERE, "static", "reports")
os.makedirs(INSTANCE, exist_ok=True)
os.makedirs(REPORTS, exist_ok=True)


def secret_key():
    path = os.path.join(INSTANCE, "secret_key")
    if not os.path.exists(path):
        with open(path, "w") as handle:
            handle.write(secrets.token_hex(32))
    with open(path) as handle:
        return handle.read().strip()


app = Flask(__name__)
app.secret_key = secret_key()
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db = Database(os.path.join(INSTANCE, "raqib.db"))
system, lab_report, baseline = load_or_run_lab(os.path.join(INSTANCE, "lab_models.joblib"), REPORTS)
monitor = LiveMonitor(system, DEVICES, baseline, on_close=db.save_incident)


@app.before_request
def load_user():
    user_id = session.get("user_id")
    g.user = db.user_by_id(user_id) if user_id else None
    if user_id and g.user is None:
        session.clear()
    check_csrf()


@app.context_processor
def shared():
    return {"ATTACK_NAMES": ATTACK_NAMES_AR, "DEVICE_NAMES": DEVICE_NAMES_AR, "FEATURE_NAMES": FEATURE_NAMES_AR,
            "MODEL_KEYS": MODEL_KEYS, "MODEL_NAMES": MODEL_NAMES, "csrf_token": csrf_token,
            "site": db.get_settings(SETTINGS), "user": g.get("user")}


@app.template_filter("pct")
def pct(value, digits=1):
    return "—" if value is None else f"{value * 100:.{digits}f}٪"


def vote_row(report):
    return next(row for row in report["table"] if row["key"] == "vote")


# ---------- public pages ----------

@app.route("/")
def home():
    return render_template("home.html", lab=lab_report, vote=vote_row(lab_report))


@app.route("/about")
def about():
    return render_template("about.html", lab=lab_report)


@app.route("/team")
def team():
    return render_template("team.html")


@app.route("/references")
def references():
    return render_template("references.html", references=REFERENCES)


# ---------- accounts ----------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not username or not username.replace("_", "").replace(".", "").isalnum():
            flash("اكتب اسمك واسم مستخدم من حروف إنجليزية وأرقام فقط.", "error")
        elif len(password) < 8:
            flash("كلمة المرور يجب أن تكون 8 أحرف على الأقل.", "error")
        elif password != request.form.get("confirm", ""):
            flash("كلمتا المرور غير متطابقتين.", "error")
        elif db.user_by_username(username):
            flash("اسم المستخدم مستعمل، اختر اسماً آخر.", "error")
        else:
            first = db.count_users() == 0
            session.clear()
            session["user_id"] = db.create_user(name, username, generate_password_hash(password))
            flash("أُنشئ حسابك. " + ("أنت مدير الموقع لأنك أول من سجّل." if first else "مرحباً بك في رقيب."), "ok")
            return redirect(url_for("live"))
    return render_template("register.html", first=db.count_users() == 0)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = db.user_by_username(request.form.get("username", "").strip().lower())
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(safe_next(request.args.get("next")))
        flash("اسم المستخدم أو كلمة المرور غير صحيحة.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------- the detection system ----------

@app.route("/live")
@login_required
def live():
    return render_template("live.html", panel=monitor.snapshot(0), devices=DEVICES, attacks=ATTACK_TYPES, policies=POLICIES)


@app.route("/live/panel")
@login_required
def live_panel():
    return render_template("_panel.html", panel=monitor.snapshot(request.args.get("device", 0, type=int)))


@app.post("/api/control")
@login_required
def control():
    form = request.form
    return jsonify(monitor.configure(
        running=form.get("running", type=lambda v: v == "1"),
        speed=form.get("speed", type=int),
        policy=form.get("policy"),
        sensitivity=form.get("sensitivity", type=float),
        auto_attacks=form.get("auto", type=lambda v: v == "1"),
    ))


@app.post("/api/attack")
@login_required
def attack():
    ok = monitor.launch_attack(request.form.get("device", 0, type=int), request.form.get("kind", ""),
                               request.form.get("stealthy") == "1", request.form.get("duration", 30, type=int),
                               by=g.user["id"])
    return jsonify(ok=ok)


@app.post("/api/stop")
@login_required
def stop_attacks():
    monitor.stop_attacks()
    return jsonify(ok=True)


@app.post("/api/reset")
@login_required
def reset():
    monitor.reset()
    return jsonify(ok=True)


@app.route("/lab")
@login_required
def lab():
    return render_template("lab.html", report=lab_report)


@app.route("/data", methods=["GET", "POST"])
@login_required
def data_page():
    if request.method == "GET":
        return render_template("data.html", error=None)
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return render_template("data.html", error="اختر ملف CSV أولاً.")
    folder = uuid.uuid4().hex
    try:
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "upload.csv")
            upload.save(path)
            df = read_csv_sample(path, max_rows=min(request.form.get("max_rows", 50_000, type=int), 200_000))
        label_col = request.form.get("label_col", "").strip() or guess_label(df)
        if label_col is None:
            raise ValueError("لم أجد عموداً يصلح أن يكون التصنيف. اكتب اسمه في الحقل.")
        normal = request.form.get("normal_value", "").strip() or guess_normal(df[label_col])
        features, labels, dropped = prepare_dataset(df, label_col, normal)
        _, report = run_experiment(features, labels, normal, REPORTS, folder, trees=100)
    except (ValueError, KeyError, UnicodeDecodeError, OSError) as error:
        shutil.rmtree(os.path.join(REPORTS, folder), ignore_errors=True)
        return render_template("data.html", error=f"تعذّر تحليل الملف: {error}")
    report["dropped"] = dropped
    info = {"label_col": label_col, "normal": normal}
    report_id = db.save_report(g.user["id"], upload.filename, info, report, report_json(report))
    flash("اكتمل التحليل وحُفظ التقرير في قاعدة البيانات.", "ok")
    return redirect(url_for("report_page", report_id=report_id))


@app.route("/sample.csv")
@login_required
def sample_csv():
    data = generate_dataset(15000, 5000, seed=7, normal_label="BenignTraffic")
    return Response(data.to_csv(index=False, float_format="%.4f"), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=raqib_sample.csv"})


@app.route("/incidents")
@login_required
def incidents():
    truth = request.args.get("truth", "all")
    if truth not in ("all", "real", "false"):
        truth = "all"
    return render_template("incidents.html", rows=db.list_incidents(truth), stats=db.incident_stats(), truth=truth)


@app.route("/reports")
@login_required
def reports():
    rows = db.list_reports(None if g.user["role"] == "admin" else g.user["id"])
    return render_template("reports.html", rows=rows)


def own_report(report_id):
    row = db.get_report(report_id)
    if row is None:
        abort(404)
    if g.user["role"] != "admin" and row["user_id"] != g.user["id"]:
        abort(403)
    return row


@app.route("/reports/<int:report_id>")
@login_required
def report_page(report_id):
    return render_template("report.html", row=own_report(report_id))


@app.post("/reports/<int:report_id>/delete")
@login_required
def delete_report(report_id):
    row = own_report(report_id)
    db.delete_report(report_id)
    shutil.rmtree(os.path.join(REPORTS, row["folder"]), ignore_errors=True)
    flash("حُذف التقرير.", "ok")
    return redirect(url_for("reports"))


# ---------- administration ----------

@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html", users=db.list_users(), labels=SETTING_LABELS)


@app.post("/admin/settings")
@admin_required
def admin_settings():
    db.save_settings({key: request.form.get(key, "").strip()[:300] for key in SETTINGS})
    flash("حُفظت معلومات المشروع.", "ok")
    return redirect(url_for("admin"))


@app.post("/admin/users/<int:user_id>/role")
@admin_required
def admin_role(user_id):
    role = request.form.get("role")
    if user_id != g.user["id"] and role in ("admin", "analyst"):
        db.set_role(user_id, role)
        flash("تغيّرت صلاحية المستخدم.", "ok")
    return redirect(url_for("admin"))


@app.post("/admin/users/<int:user_id>/delete")
@admin_required
def admin_delete_user(user_id):
    if user_id != g.user["id"]:
        db.delete_user(user_id)
        flash("حُذف المستخدم.", "ok")
    return redirect(url_for("admin"))


@app.post("/admin/incidents/clear")
@admin_required
def admin_clear_incidents():
    db.clear_incidents()
    flash("مُسح سجل الحوادث.", "ok")
    return redirect(url_for("incidents"))


# ---------- errors ----------

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def error_page(error):
    messages = {400: "انتهت صلاحية النموذج. حدّث الصفحة وحاول مرة أخرى.", 403: "ليست لديك صلاحية لهذه الصفحة.",
                404: "الصفحة غير موجودة.", 413: "الملف أكبر من الحد المسموح (200 ميغابايت)."}
    return render_template("error.html", code=error.code, message=messages[error.code]), error.code


if __name__ == "__main__":
    print("Raqib is ready: open http://127.0.0.1:5000 in your browser (Ctrl+C to stop).")
    app.run(host="127.0.0.1", port=5000, threaded=True)
