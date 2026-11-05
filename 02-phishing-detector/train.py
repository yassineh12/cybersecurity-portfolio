"""Lesson 3: train and evaluate the phishing classifier.

We use a Random Forest because it handles mixed feature scales without
normalization, gives feature-importance scores for free, and is hard to
overfit on a small dataset.  The training pipeline:

  1. Load the labelled URLs from collect_urls.py
  2. Extract URL features (lesson 1) for every row
  3. Train/test split (stratified, so both sets have the same phishing ratio)
  4. 5-fold cross-validation for a robust accuracy estimate
  5. Train a Random Forest on the full training set
  6. Evaluate with precision, recall, F1, ROC-AUC and a confusion matrix
  7. Save the model for predict.py (lesson 4)

Usage:
    python train.py --data data/urls.csv --out model/phishing_rf.joblib
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from url_features import extract

__version__ = "1.1.0"

log = logging.getLogger(__name__)


def build_feature_matrix(urls: list[str]) -> pd.DataFrame:
    rows = []
    for i, url in enumerate(urls, 1):
        rows.append(extract(url))
        if i % 500 == 0:
            log.info("  features extracted: %d/%d", i, len(urls))
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data/urls.csv")
    ap.add_argument("--out", default="model/phishing_rf.joblib")
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--verbose", "-v", action="store_true", help="debug-level output")
    ap.add_argument("--quiet", "-q", action="store_true", help="errors only")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")

    t0 = time.monotonic()

    log.info("Loading labelled URLs ...")
    df = pd.read_csv(args.data)
    log.info("  %d rows — %d phishing, %d legit",
             len(df), df["label"].sum(), len(df) - df["label"].sum())

    log.info("Extracting URL features ...")
    X = build_feature_matrix(df["url"].tolist())
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )
    log.info("  train: %d,  test: %d", len(X_train), len(X_test))

    log.info("5-fold cross-validation ...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=15, min_samples_leaf=5,
        random_state=args.seed, n_jobs=-1
    )
    cv_scores = cross_val_score(clf, X_train, y_train, cv=cv, scoring="accuracy")
    log.info("  CV accuracy: %.3f +/- %.3f", cv_scores.mean(), cv_scores.std())

    log.info("Training Random Forest on full training set ...")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    report = classification_report(y_test, y_pred, target_names=["legit", "phishing"])
    cm = confusion_matrix(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    log.info("\n%s", report)
    log.info("Confusion matrix:  TN=%d  FP=%d  FN=%d  TP=%d",
             cm[0][0], cm[0][1], cm[1][0], cm[1][1])
    log.info("ROC-AUC: %.4f", auc)

    importances = sorted(
        zip(X.columns, clf.feature_importances_), key=lambda x: -x[1]
    )
    log.info("Top features:")
    for name, imp in importances[:8]:
        log.info("  %s  %.4f", name.ljust(28), imp)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)

    import joblib
    joblib.dump({"model": clf, "features": list(X.columns)}, args.out)
    log.info("Model saved to %s", args.out)

    elapsed = time.monotonic() - t0
    metrics = {
        "test_size": len(X_test),
        "cv_accuracy_mean": round(cv_scores.mean(), 4),
        "cv_accuracy_std": round(cv_scores.std(), 4),
        "roc_auc": round(auc, 4),
        "report": report,
        "confusion_matrix": cm.tolist(),
        "top_features": importances[:10],
        "elapsed_seconds": round(elapsed, 2),
    }
    metrics_path = Path(args.out).with_suffix(".json")
    metrics_path.write_text(json.dumps(metrics, indent=2, default=str))
    log.info("Metrics saved to %s  (%.1fs elapsed)", metrics_path, elapsed)


if __name__ == "__main__":
    main()
