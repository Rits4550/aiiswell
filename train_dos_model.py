"""
train_dos_model.py

Trains a classifier on dos_traffic_log.csv to distinguish normal traffic
windows from DoS-flood windows, based purely on requests-per-second.
This is a deliberately simple model -- the point for your report is that
DoS detection is fundamentally a RATE/TIMING problem, unlike the
per-request SQLi classifier, which is a CONTENT problem. Say this
explicitly: it's a genuine methodological difference worth discussing.
"""
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os

DATA_PATH = os.path.join(os.path.dirname(__file__), "dos_traffic_log.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "dos_model.pkl")

def main():
    df = pd.read_csv(DATA_PATH)
    df["label_num"] = (df["label"] == "attack").astype(int)

    X = df[["requests_per_window"]]
    y = df["label_num"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    model = LogisticRegression()
    model.fit(X_train, y_train)
    preds = model.predict(X_test)

    print("=== Classification Report ===")
    print(classification_report(y_test, preds, target_names=["normal", "attack"]))
    print("=== Confusion Matrix ===")
    cm = confusion_matrix(y_test, preds)
    print(f"              predicted normal   predicted attack")
    print(f"actual normal       {cm[0][0]:>5}              {cm[0][1]:>5}")
    print(f"actual attack       {cm[1][0]:>5}              {cm[1][1]:>5}")

    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": model}, f)
    print(f"\nModel saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()
