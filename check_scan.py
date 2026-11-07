import sys

import pandas as pd

from ml.extract import extract_flows
from ml.predict import predict_flows

pcap = sys.argv[1]
extract_flows(pcap, "data/_check.csv")
r = predict_flows(pd.read_csv("data/_check.csv"))

by_target = (
    r.groupby("dst_ip")
    .agg(
        flows=("prediction", "size"),
        flagged=("prediction", "sum"),
        distinct_ports=("dst_port", "nunique"),
        avg_prob=("attack_probability", "mean"),
    )
    .sort_values("flows", ascending=False)
)
print(by_target.head(10).round(3).to_string())