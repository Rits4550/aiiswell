"""
train_model.py

Trains a supervised classifier (Logistic Regression) to distinguish
malicious (SQL-injection-style) search requests from benign ones, using
the traffic logged by generate_traffic.py.

Saves the trained model + feature list to model.pkl so detector_demo.py
can load it and classify new, unseen requests in real time.
"""
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os

DATA_PATH = os.path.join(os.path.dirname(__file__), "traffic_log.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

FEATURES = ["length", "num_quotes", "num_special_chars", "has_sql_keyword",
            "num_spaces", "has_comment_marker", "digit_ratio"]

def main():
    df = pd.read_csv(DATA_PATH)
    df["label_num"] = (df["label"] == "malicious").astype(int)

    X = df[FEATURES]
    y = df["label_num"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)

    print("=== Classification Report (held-out test set) ===")
    print(classification_report(y_test, preds, target_names=["benign", "malicious"]))
    print("=== Confusion Matrix ===")
    cm = confusion_matrix(y_test, preds)
    print(f"              predicted benign   predicted malicious")
    print(f"actual benign       {cm[0][0]:>5}              {cm[0][1]:>5}")
    print(f"actual malicious    {cm[1][0]:>5}              {cm[1][1]:>5}")

    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": model, "features": FEATURES}, f)

    print(f"\nModel saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()
