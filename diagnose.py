import numpy as np
import pandas as pd

from ml.extract import extract_flows
from ml.predict import FEATURES, MAPPING, TIME_FEATURES, TIME_SCALE

extract_flows("data/portscan.pcap", "data/_scan_flows.csv")
mine = pd.read_csv("data/_scan_flows.csv")

X = pd.DataFrame({f: mine[c] for f, c in MAPPING.items()})[FEATURES]
print("TIME_SCALE:", TIME_SCALE)
print("Your scan: flows =", len(X))
print("Raw flow_duration from the tool: max =", mine[MAPPING["Flow Duration"]].max(),
      "| median =", mine[MAPPING["Flow Duration"]].median())

for f in TIME_FEATURES:
    X[f] = X[f] * TIME_SCALE
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

wanted = set(FEATURES) | {"Label"}
ds = pd.read_csv(
    "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    usecols=lambda c: c.strip() in wanted,
)
ds.columns = ds.columns.str.strip()
ds = ds.replace([np.inf, -np.inf], np.nan).dropna()
ds_scan = ds[ds["Label"] != "BENIGN"][FEATURES]
ds_benign = ds[ds["Label"] == "BENIGN"][FEATURES]

table = pd.DataFrame({
    "dataset_scan": ds_scan.median(),
    "dataset_benign": ds_benign.median(),
    "your_scan": X.median(),
})
gap = (table["your_scan"] - table["dataset_scan"]).abs() / (
    table["your_scan"].abs() + table["dataset_scan"].abs() + 1e-9
)
table["gap"] = gap.round(2)

pd.set_option("display.width", 200)
print()
print("Features where YOUR scan differs most from the dataset's scans (gap 1.0 = totally different):")
print(table.sort_values("gap", ascending=False).head(20).to_string())
print()
print("Number of features with gap > 0.5:", int((table["gap"] > 0.5).sum()), "of", len(table))