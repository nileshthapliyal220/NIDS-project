import json

import pandas as pd
import plotly.graph_objects as go

NORMAL = "#4C78A8"
ATTACK = "#E45756"
PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP"}


def _fig_to_dict(fig, height=320):
    fig.update_layout(
        height=height,
        margin=dict(l=40, r=20, t=50, b=40),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return json.loads(fig.to_json())


def build_charts(result):
    """Take the DataFrame from predict_flows and return a dict of Plotly figures."""
    charts = {}
    r = result.copy()
    r["label"] = r["prediction"].map({0: "Normal", 1: "Attack"})
    n_attack = int(r["prediction"].sum())
    n_normal = len(r) - n_attack

    fig = go.Figure(go.Pie(
        labels=["Normal", "Attack"], values=[n_normal, n_attack], hole=0.55,
        marker=dict(colors=[NORMAL, ATTACK]), sort=False,
    ))
    fig.update_layout(title="Flows: normal vs attack")
    charts["donut"] = _fig_to_dict(fig)

    ts = pd.to_datetime(r["timestamp"], errors="coerce")
    if ts.notna().sum() > 1:
        span = ts.max() - ts.min()
        freq = "1s" if span.total_seconds() <= 300 else "1min"
        r["bucket"] = ts.dt.floor(freq)
        timeline = r.groupby(["bucket", "label"]).size().unstack(fill_value=0)
        fig = go.Figure()
        for name, color in (("Normal", NORMAL), ("Attack", ATTACK)):
            if name in timeline:
                fig.add_bar(x=timeline.index.astype(str), y=timeline[name], name=name, marker_color=color)
        fig.update_layout(barmode="stack", title="New flows over time (per " + ("second" if freq == "1s" else "minute") + ")")
        charts["timeline"] = _fig_to_dict(fig)

    src = r.groupby(["src_ip", "label"]).size().unstack(fill_value=0)
    src["total"] = src.sum(axis=1)
    src = src.sort_values("total", ascending=False).head(10).iloc[::-1]
    fig = go.Figure()
    for name, color in (("Normal", NORMAL), ("Attack", ATTACK)):
        if name in src:
            fig.add_bar(y=src.index, x=src[name], name=name, orientation="h", marker_color=color)
    fig.update_layout(barmode="stack", title="Top 10 sources by number of flows")
    charts["sources"] = _fig_to_dict(fig)

    ports = r.groupby(["dst_port", "label"]).size().unstack(fill_value=0)
    ports["total"] = ports.sum(axis=1)
    ports = ports.sort_values("total", ascending=False).head(10).iloc[::-1]
    fig = go.Figure()
    for name, color in (("Normal", NORMAL), ("Attack", ATTACK)):
        if name in ports:
            fig.add_bar(y=ports.index.astype(str), x=ports[name], name=name, orientation="h", marker_color=color)
    fig.update_layout(barmode="stack", title="Top 10 destination ports", yaxis_title="Port")
    charts["ports"] = _fig_to_dict(fig)

    proto = r["protocol"].map(lambda p: PROTOCOLS.get(int(p), "Other")).value_counts()
    fig = go.Figure(go.Bar(x=proto.index, y=proto.values, marker_color=NORMAL))
    fig.update_layout(title="Protocols")
    charts["protocols"] = _fig_to_dict(fig)

    fig = go.Figure(go.Histogram(x=r["attack_probability"], xbins=dict(start=0, end=1, size=0.05),
                                 marker_color=ATTACK))
    fig.update_layout(title="Model confidence (attack probability per flow)",
                      xaxis_title="Attack probability", yaxis_title="Flows")
    charts["confidence"] = _fig_to_dict(fig)

    return charts


def find_scan_suspects(result, min_ports=100):
    """Simple rule: one source hitting many different ports of one target."""
    g = (
        result.groupby(["src_ip", "dst_ip"])
        .agg(flows=("prediction", "size"), flagged=("prediction", "sum"),
             distinct_ports=("dst_port", "nunique"))
        .reset_index()
    )
    g = g[(g["distinct_ports"] >= min_ports) & (g["flagged"] >= 0.3 * g["flows"])]
    return g.sort_values("distinct_ports", ascending=False).head(5).to_dict("records")