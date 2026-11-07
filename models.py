from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    created = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    total_flows = db.Column(db.Integer, nullable=False)
    flagged_flows = db.Column(db.Integer, nullable=False)
    charts_json = db.Column(db.Text, nullable=False)     # chart data, so charts can be redrawn later
    suspects_json = db.Column(db.Text, nullable=False)   # scan warnings

    pairs = db.relationship("PairSummary", backref="analysis", cascade="all, delete-orphan")
    flagged = db.relationship("FlaggedFlow", backref="analysis", cascade="all, delete-orphan")


class PairSummary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analysis.id"), nullable=False)
    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))
    flows = db.Column(db.Integer)
    flagged = db.Column(db.Integer)
    distinct_ports = db.Column(db.Integer)


class FlaggedFlow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analysis.id"), nullable=False)
    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.Integer)
    attack_probability = db.Column(db.Float)