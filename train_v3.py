import os
import shutil

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

old = joblib.load("models/nids_rf.joblib")
ALL = old["features"]
MAPPING = old["mapping"]

SKIP = ("Length", "Size", "size", "Bytes", "bytes", "IAT", "Duration", "/s",
        "Active", "Idle", "Header", "Init_Win", "Variance", "Std", "Mean", "seg")
KEEP = [f for f in ALL if not any(k in f for k in SKIP)]

print("Keeping", len(KEEP), "of", len(ALL), "features:")
for f in KEEP:
    print("  ", f)
if len(KEEP) < 5:
    raise SystemExit("Too few features kept. Send me this output.")

FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]
wanted = set(KEEP) | {"Label"}


def load(name):
    df = pd.read_csv("data/" + name, usecols=lambda c: c.strip() in wanted)
    df.columns = df.columns.str.strip()
    return df.replace([np.inf, -np.inf], np.nan).dropna()


data = pd.concat([load(f) for f in FILES], ignore_index=True)

benign = data[data["Label"] == "BENIGN"]
benign = benign.sample(n=min(300_000, len(benign)), random_state=42)
attack_parts = [
    g.sample(n=min(len(g), 100_000), random_state=42)
    for _, g in data[data["Label"] != "BENIGN"].groupby("Label")
]
data = pd.concat([benign] + attack_parts, ignore_index=True)

y = (data["Label"] != "BENIGN").astype(int)
X = data[KEEP].astype("float32")
print("\nTraining rows:", len(X), "| attack share: {:.1%}".format(y.mean()))

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
rf = RandomForestClassifier(n_estimators=60, min_samples_leaf=5,class_weight="balanced_subsample", random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

pred = rf.predict(X_test)
print(classification_report(y_test, pred, target_names=["normal", "attack"], digits=4))
print(confusion_matrix(y_test, pred))

if not os.path.exists("models/nids_rf_full.joblib"):
    shutil.copy("models/nids_rf.joblib", "models/nids_rf_full.joblib")

joblib.dump(
    {"model": rf, "features": KEEP,
     "mapping": {f: MAPPING[f] for f in KEEP}, "time_scale": 1},
    "models/nids_rf.joblib", compress=3,
)
print("\nSaved models/nids_rf.joblib (full-feature backup: models/nids_rf_full.joblib)")