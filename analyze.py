import os
import sys
import pandas as pd
from ml.extract import extract_flows
from ml.predict import predict_flows
if len(sys.argv) != 2:
    print("Usage: python analyze.py path/to/file.pcap")
    sys.exit(1)
pcap = sys.argv[1]
tmp_csv = "data/_tmp_flows.csv"
extract_flows(pcap, tmp_csv)
if not os.path.exists(tmp_csv) or os.path.getsize(tmp_csv) == 0:
    print("No flows could be extracted from this file.")
    sys.exit(1)
flows = pd.read_csv(tmp_csv)
result = predict_flows(flows)
n_attack = int(result["prediction"].sum())
print()
print("File:", pcap)
print("Flows:", len(result))
print("Flagged as attack:", n_attack, "({:.0%})".format(n_attack / len(result)))
if n_attack:
    cols = ["src_ip", "dst_ip", "dst_port", "protocol", "attack_probability"]
    print()
    print("Top flagged flows:")
    flagged = result[result["prediction"] == 1]
    print(flagged[cols].sort_values("attack_probability", ascending=False).head(10).to_string(index=False))
    print()
    print("Most frequent sources among flagged flows:")
    print(flagged["src_ip"].value_counts().head(5).to_string())
print()
print("Highest attack probability of any flow: {:.3f}".format(result["attack_probability"].max()))
print("Average attack probability: {:.3f}".format(result["attack_probability"].mean()))