import os
import uuid
from charts import build_charts, find_scan_suspects

import pandas as pd
from flask import Flask, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from ml.extract import extract_flows
from ml.predict import predict_flows

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024   
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED = {".pcap", ".pcapng"}


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        flash("Please choose a file.")
        return redirect(url_for("home"))

    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in ALLOWED:
        flash("Only .pcap or .pcapng files are accepted.")
        return redirect(url_for("home"))

    token = uuid.uuid4().hex                      # random name, so uploads can't clash
    pcap_path = os.path.join(UPLOAD_DIR, token + ext)
    csv_path = os.path.join(UPLOAD_DIR, token + ".csv")
    f.save(pcap_path)

    try:
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
        for p in (pcap_path, csv_path):           
            if os.path.exists(p):
                os.remove(p)

    total = len(result)
    flagged = int(result["prediction"].sum())

    pairs = (
        result.groupby(["src_ip", "dst_ip"])
        .agg(
            flows=("prediction", "size"),
            flagged=("prediction", "sum"),
            distinct_ports=("dst_port", "nunique"),
            avg_prob=("attack_probability", "mean"),
        )
        .reset_index()
        .sort_values(["flagged", "flows"], ascending=False)
        .head(10)
    )

    top = (
        result[result["prediction"] == 1]
        .sort_values("attack_probability", ascending=False)
        [["src_ip", "dst_ip", "dst_port", "protocol", "attack_probability"]]
        .head(20)
    )

    return render_template(
        "results.html",
        filename=secure_filename(f.filename),
        total=total,
        flagged=flagged,
        percent=round(100 * flagged / total) if total else 0,
        pairs=pairs.to_dict("records"),
        top=top.to_dict("records"),
        charts=build_charts(result),
        suspects=find_scan_suspects(result),
    )


if __name__ == "__main__":
    app.run(debug=True)