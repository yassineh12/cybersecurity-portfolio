"""Lesson 4: classify a URL and explain *why*.

Usage:
    python predict.py https://www.google.com
    python predict.py http://paypa1-login.xyz/verify --model model/phishing_rf.joblib

The explanation shows which features pushed the score toward phishing and
which pulled it toward safe. This matters because a security analyst needs
to trust — or override — the verdict, and a black-box number is not enough.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib

from url_features import extract


def explain(features: dict, model, feature_names: list[str]) -> list[tuple[str, float, float]]:
    """Per-feature contribution using the forest's tree structure.

    For each tree we trace the decision path and accumulate the change in
    predicted probability at every split. Averaging across all trees gives
    a contribution per feature — positive means "more likely phishing".
    """
    import numpy as np

    vals = [features.get(f, 0) for f in feature_names]
    x = np.array(vals).reshape(1, -1)

    contribs = np.zeros(len(feature_names))
    for tree in model.estimators_:
        node_indicator = tree.decision_path(x)
        node_ids = node_indicator.indices
        values = tree.tree_.value
        feature_idx = tree.tree_.feature
        for i in range(len(node_ids) - 1):
            node = node_ids[i]
            f = feature_idx[node]
            if f < 0:
                continue
            before = values[node][0][1] / values[node][0].sum()
            child = node_ids[i + 1]
            after = values[child][0][1] / values[child][0].sum()
            contribs[f] += after - before

    contribs /= len(model.estimators_)
    return sorted(
        [(feature_names[i], contribs[i], vals[i]) for i in range(len(feature_names))],
        key=lambda x: -abs(x[1])
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--model", default="model/phishing_rf.joblib")
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args()

    model_path = Path(args.model)
    if not model_path.exists():
        print(f"Model not found at {model_path}. Run train.py first.")
        sys.exit(1)

    bundle = joblib.load(model_path)
    clf = bundle["model"]
    feature_names = bundle["features"]

    features = extract(args.url)
    vals = [features.get(f, 0) for f in feature_names]

    import numpy as np
    x = np.array(vals).reshape(1, -1)
    prob = clf.predict_proba(x)[0][1]
    verdict = "PHISHING" if prob >= args.threshold else "SAFE"

    print(f"\nURL:       {args.url}")
    print(f"Verdict:   {verdict}")
    print(f"Score:     {prob:.3f}  (threshold {args.threshold})")
    print()

    contributions = explain(features, clf, feature_names)
    print("Top factors:")
    for name, contrib, value in contributions[:8]:
        direction = "phishing" if contrib > 0 else "safe"
        bar = "+" * min(int(abs(contrib) * 50), 30) if contrib > 0 else "-" * min(int(abs(contrib) * 50), 30)
        print(f"  {name:28} = {value:<8}  {bar:>30}  ({direction})")

    print()


if __name__ == "__main__":
    main()
