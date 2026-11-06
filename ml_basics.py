import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
rng = np.random.default_rng(42)
normal = pd.DataFrame({
    "packets": rng.integers(2, 200, 900),
    "bytes": rng.integers(100, 200000, 900),
    "duration_s": rng.uniform(0.01, 60, 900),
    "ports_contacted": rng.integers(1, 13, 900),
    "label": 0,
})
attack = pd.DataFrame({
    "packets": rng.integers(1, 8, 100),
    "bytes": rng.integers(40, 600, 100),
    "duration_s": rng.uniform(0.0, 1.0, 100),
    "ports_contacted": rng.integers(8, 500, 100),
    "label": 1,
})
data = pd.concat([normal, attack]).sample(frac=1, random_state=42).reset_index(drop=True)
print(data.head())
print()
print("Label counts:")
print(data["label"].value_counts())
X = data.drop(columns=["label"])
y = data["label"]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
predictions = model.predict(X_test)
print()
print("Accuracy:", accuracy_score(y_test, predictions))
print()
print("Confusion matrix:")
print(confusion_matrix(y_test, predictions))
print()
print(classification_report(y_test, predictions, target_names=["normal", "attack"]))
lazy_accuracy = (y_test == 0).mean()
print("Accuracy of a model that ALWAYS says 'normal':", lazy_accuracy)
print()
for name, score in sorted(zip(X.columns, model.feature_importances_), key=lambda p: -p[1]):
    print(f"{name}: {score:.2f}")