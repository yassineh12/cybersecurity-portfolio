"""Lesson 4: classify a URL and explain *why*.

Usage:
    python predict.py https://www.google.com
    python predict.py http://paypa1-login.xyz/verify --model model/phishing_rf.joblib
    python predict.py --batch urls.txt --json

The explanation shows which features pushed the score toward phishing and
which pulled it toward safe. This matters because a security analyst needs
to trust — or override — the verdict, and a black-box number is not enough.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import joblib

from url_features import extract

__version__ = "1.1.0"

log = logging.getLogger(__name__)


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


def classify_url(url: str, clf, feature_names: list[str], threshold: float) -> dict:
    import numpy as np

    features = extract(url)
    vals = [features.get(f, 0) for f in feature_names]
    x = np.array(vals).reshape(1, -1)
    prob = clf.predict_proba(x)[0][1]
    verdict = "PHISHING" if prob >= threshold else "SAFE"
    contributions = explain(features, clf, feature_names)
    return {
        "url": url,
        "verdict": verdict,
        "score": round(float(prob), 4),
        "threshold": threshold,
        "top_factors": [
            {"feature": name, "contribution": round(float(c), 4), "value": v}
            for name, c, v in contributions[:8]
        ],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", nargs="?")
    ap.add_argument("--batch", metavar="FILE", help="classify every URL in a text file, one per line")
    ap.add_argument("--model", default="model/phishing_rf.joblib")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--json", dest="json_output", action="store_true", help="output JSON instead of text")
    ap.add_argument("--verbose", "-v", action="store_true", help="debug-level output")
    ap.add_argument("--quiet", "-q", action="store_true", help="errors only")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")

    if not args.url and not args.batch:
        ap.error("provide a URL or --batch FILE")

    model_path = Path(args.model)
    if not model_path.exists():
        log.error("Model not found at %s. Run train.py first.", model_path)
        sys.exit(1)

    bundle = joblib.load(model_path)
    clf = bundle["model"]
    feature_names = bundle["features"]

    urls = []
    if args.batch:
        urls = [line.strip() for line in Path(args.batch).read_text().splitlines() if line.strip()]
        log.info("Loaded %d URLs from %s", len(urls), args.batch)
    else:
        urls = [args.url]

    results = [classify_url(u, clf, feature_names, args.threshold) for u in urls]

    if args.json_output:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
        return

    for r in results:
        print(f"\nURL:       {r['url']}")
        print(f"Verdict:   {r['verdict']}")
        print(f"Score:     {r['score']:.3f}  (threshold {r['threshold']})")
        print()
        print("Top factors:")
        for f in r["top_factors"]:
            direction = "phishing" if f["contribution"] > 0 else "safe"
            bar_len = min(int(abs(f["contribution"]) * 50), 30)
            bar = ("+" if f["contribution"] > 0 else "-") * bar_len
            print(f"  {f['feature']:28} = {str(f['value']):<8}  {bar:>30}  ({direction})")
        print()


if __name__ == "__main__":
    main()
