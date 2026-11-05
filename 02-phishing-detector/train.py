"""Lesson 3: train and evaluate the phishing classifier.

We use a Random Forest because it handles mixed feature scales without
normalization, gives feature-importance scores for free, and is hard to
overfit on a small dataset.  The training pipeline:

  1. Load the labelled URLs from collect_urls.py
  2. Extract URL features (lesson 1) for every row
  3. Train/test split (stratified, so both sets have the same phishing ratio)
  4. Train a Random Forest
  5. Evaluate with precision, recall, F1 and a confusion matrix
  6. Save the model for predict.py (lesson 4)

Usage:
    python train.py --data data/urls.csv --out model/phishing_rf.joblib
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from url_features import extract


def build_feature_matrix(urls: list[str]) -> pd.DataFrame:
    rows = []
    for i, url in enumerate(urls, 1):
        rows.append(extract(url))
        if i % 500 == 0:
            print(f"  features extracted: {i}/{len(urls)}")
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data/urls.csv")
    ap.add_argument("--out", default="model/phishing_rf.joblib")
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    print("Loading labelled URLs ...")
    df = pd.read_csv(args.data)
    print(f"  {len(df)} rows — {df['label'].sum()} phishing, "
          f"{len(df) - df['label'].sum()} legit")

    print("Extracting URL features ...")
    X = build_feature_matrix(df["url"].tolist())
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )
    print(f"  train: {len(X_train)},  test: {len(X_test)}")

    print("Training Random Forest ...")
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=15, min_samples_leaf=5,
        random_state=args.seed, n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["legit", "phishing"])
    cm = confusion_matrix(y_test, y_pred)
    print("\n" + report)
    print("Confusion matrix:")
    print(f"  TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"  FN={cm[1][0]}  TP={cm[1][1]}")

    importances = sorted(
        zip(X.columns, clf.feature_importances_), key=lambda x: -x[1]
    )
    print("\nTop features:")
    for name, imp in importances[:8]:
        print(f"  {name:28} {imp:.4f}")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)

    import joblib
    joblib.dump({"model": clf, "features": list(X.columns)}, args.out)
    print(f"\nModel saved to {args.out}")

    metrics = {
        "test_size": len(X_test),
        "report": report,
        "confusion_matrix": cm.tolist(),
        "top_features": importances[:10],
    }
    metrics_path = Path(args.out).with_suffix(".json")
    metrics_path.write_text(json.dumps(metrics, indent=2, default=str))
    print(f"Metrics saved to {metrics_path}")


if __name__ == "__main__":
    main()
