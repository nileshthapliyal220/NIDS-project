import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

old = joblib.load("models/nids_rf.joblib")
FEATURES = old["features"]
MAPPING = old["mapping"]
TIME_SCALE = old["time_scale"]
print("TIME_SCALE in use:", TIME_SCALE)

FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]
wanted = set(FEATURES) | {"Label"}


def load(name):
    df = pd.read_csv("data/" + name, usecols=lambda c: c.strip() in wanted)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).dropna().drop_duplicates()
    print(f"{name}: {len(df):,} rows")
    return df


data = pd.concat([load(f) for f in FILES], ignore_index=True)
print()
print(data["Label"].value_counts())

benign = data[data["Label"] == "BENIGN"].sample(n=min(400_000, (data["Label"] == "BENIGN").sum()), random_state=42)
attacks = (
    data[data["Label"] != "BENIGN"]
    .groupby("Label", group_keys=False)
    .apply(lambda g: g.sample(n=min(len(g), 100_000), random_state=42))
)
data = pd.concat([benign, attacks], ignore_index=True)

y = (data["Label"] != "BENIGN").astype(int)
X = data[FEATURES].astype("float32")
print()
print("Training rows:", len(X), "| attack share: {:.1%}".format(y.mean()))

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

print("Training... this can take a few minutes")
rf = RandomForestClassifier(n_estimators=60, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

pred = rf.predict(X_test)
print()
print(classification_report(y_test, pred, target_names=["normal", "attack"], digits=4))
print(confusion_matrix(y_test, pred))

joblib.dump(
    {"model": rf, "features": FEATURES, "mapping": MAPPING, "time_scale": TIME_SCALE},
    "models/nids_rf.joblib",
)
print()
print("Saved models/nids_rf.joblib")