import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pandas as pd
from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

from charts import build_charts, find_scan_suspects
from ml.extract import extract_flows
from ml.predict import predict_flows
from models import Analysis, FlaggedFlow, PairSummary, db

app = Flask(__name__)

# ---------- configuration ----------
IS_PROD = os.environ.get("NIDS_ENV") == "production"
_secret = os.environ.get("SECRET_KEY")
if IS_PROD and not _secret:
    raise RuntimeError("Set the SECRET_KEY environment variable in production.")

app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", "50")) * 1024 * 1024
app.config["SECRET_KEY"] = _secret or "dev-only-change-me"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_PROD
app.permanent_session_lifetime = timedelta(days=30)

_db_url = os.environ.get("DATABASE_URL", "sqlite:///nids.db")
if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = _db_url

RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "7"))

# Behind a hosting provider's proxy, the real visitor address is in a header.
# Only trust that header in production, where a proxy really sits in front.
if IS_PROD:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

db.init_app(app)
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED = {".pcap", ".pcapng"}

# The first bytes of real capture files: classic pcap (both byte orders,
# with microsecond or nanosecond times) and pcapng.
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}


# ---------- helpers ----------
def to_json(obj):
    """json.dumps that also understands numpy numbers."""
    return json.dumps(obj, default=lambda o: o.item() if hasattr(o, "item") else str(o))


def current_owner():
    """A random ID for this browser, kept in a signed cookie."""
    if "owner" not in session:
        session["owner"] = uuid.uuid4().hex
    session.permanent = True
    return session["owner"]


def purge_old():
    """Delete analyses older than RETENTION_DAYS (and their child rows)."""
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=RETENTION_DAYS)
    for a in Analysis.query.filter(Analysis.created < cutoff).all():
        db.session.delete(a)
    db.session.commit()


with app.app_context():
    db.create_all()
    purge_old()


# ---------- security headers and friendly errors ----------
@app.after_request
def add_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.errorhandler(413)
def too_large(_e):
    mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    flash(f"That file is too large. The limit is {mb} MB.")
    return redirect(url_for("home"))


@app.errorhandler(429)
def too_many(_e):
    flash("Too many uploads from your address. Please wait a while and try again.")
    return redirect(url_for("home"))


# ---------- pages ----------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
@limiter.limit(lambda: os.environ.get("UPLOAD_LIMIT", "10 per hour; 30 per day"))
def upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        flash("Please choose a file.")
        return redirect(url_for("home"))

    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in ALLOWED:
        flash("Only .pcap or .pcapng files are accepted.")
        return redirect(url_for("home"))

    token = uuid.uuid4().hex
    pcap_path = os.path.join(UPLOAD_DIR, token + ext)
    csv_path = os.path.join(UPLOAD_DIR, token + ".csv")
    f.save(pcap_path)

    try:
        with open(pcap_path, "rb") as fh:
            magic = fh.read(4)
        if magic not in PCAP_MAGICS:
            flash("That file does not look like a packet capture.")
            return redirect(url_for("home"))

        extract_flows(pcap_path, csv_path)
        if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
            flash("No TCP or UDP flows were found in that file.")
            return redirect(url_for("home"))
        result = predict_flows(pd.read_csv(csv_path))
    except Exception:
        app.logger.exception("Analysis failed")
        flash("Could not analyze that file. Is it a valid capture?")
        return redirect(url_for("home"))
    finally:
        for p in (pcap_path, csv_path):           # never keep uploaded files
            if os.path.exists(p):
                os.remove(p)

    pairs_df = (
        result.groupby(["src_ip", "dst_ip"])
        .agg(flows=("prediction", "size"), flagged=("prediction", "sum"),
             distinct_ports=("dst_port", "nunique"))
        .reset_index()
        .sort_values(["flagged", "flows"], ascending=False)
        .head(10)
    )
    top_df = (
        result[result["prediction"] == 1]
        .sort_values("attack_probability", ascending=False)
        [["src_ip", "dst_ip", "dst_port", "protocol", "attack_probability"]]
        .head(20)
    )

    analysis = Analysis(
        owner=current_owner(),
        filename=secure_filename(f.filename),
        total_flows=len(result),
        flagged_flows=int(result["prediction"].sum()),
        charts_json=to_json(build_charts(result)),
        suspects_json=to_json(find_scan_suspects(result)),
    )
    for p in pairs_df.to_dict("records"):
        analysis.pairs.append(PairSummary(
            src_ip=str(p["src_ip"]), dst_ip=str(p["dst_ip"]),
            flows=int(p["flows"]), flagged=int(p["flagged"]),
            distinct_ports=int(p["distinct_ports"]),
        ))
    for r in top_df.to_dict("records"):
        analysis.flagged.append(FlaggedFlow(
            src_ip=str(r["src_ip"]), dst_ip=str(r["dst_ip"]),
            dst_port=int(r["dst_port"]), protocol=int(r["protocol"]),
            attack_probability=float(r["attack_probability"]),
        ))
    db.session.add(analysis)
    db.session.commit()
    purge_old()

    return redirect(url_for("results", analysis_id=analysis.id))


@app.route("/results/<int:analysis_id>")
def results(analysis_id):
    a = db.session.get(Analysis, analysis_id)
    if a is None or a.owner != current_owner():
        abort(404)

    pairs = sorted(a.pairs, key=lambda p: (p.flagged, p.flows), reverse=True)
    top = sorted(a.flagged, key=lambda r: r.attack_probability, reverse=True)

    return render_template(
        "results.html",
        filename=a.filename,
        total=a.total_flows,
        flagged=a.flagged_flows,
        percent=round(100 * a.flagged_flows / a.total_flows) if a.total_flows else 0,
        pairs=[{"src_ip": p.src_ip, "dst_ip": p.dst_ip, "flows": p.flows,
                "flagged": p.flagged, "distinct_ports": p.distinct_ports} for p in pairs],
        top=[{"src_ip": r.src_ip, "dst_ip": r.dst_ip, "dst_port": r.dst_port,
              "protocol": r.protocol, "attack_probability": r.attack_probability} for r in top],
        charts=json.loads(a.charts_json),
        suspects=json.loads(a.suspects_json),
    )


@app.route("/history")
def history():
    analyses = (Analysis.query.filter_by(owner=current_owner())
                .order_by(Analysis.created.desc()).all())
    return render_template("history.html", analyses=analyses, days=RETENTION_DAYS)


@app.route("/delete/<int:analysis_id>", methods=["POST"])
def delete(analysis_id):
    a = db.session.get(Analysis, analysis_id)
    if a is None or a.owner != current_owner():
        abort(404)
    db.session.delete(a)
    db.session.commit()
    flash("Analysis deleted.")
    return redirect(url_for("history"))


if __name__ == "__main__":
    app.run(debug=True)