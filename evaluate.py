"""Self-evaluation of the LEGACY ML variant (detector.py) — not the shipped engine.
For the deterministic engine's accuracy, see the in-app /validation page or
`python -m sbom.metrics`.
"""
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score
from detector import analyze, DATA_DIR, RISK_MODEL_THRESHOLD

labels = pd.read_csv(f"{DATA_DIR}/dependency_labels.csv", encoding="cp1252")
pred = analyze()

merged = pred.merge(labels[["dep_id", "is_risky", "risk_type"]], on="dep_id", suffixes=("_pred", "_true"))

y_true = merged["is_risky_true"].astype(bool).astype(int)
y_pred = merged["is_risky_pred"].astype(bool).astype(int)

print("=" * 70)
print("IN-SAMPLE RESULT (the risk model trained on this same labels file)")
print("=" * 70)
print(f"Precision: {precision_score(y_true, y_pred):.2%}   (target > 75%)")
print(f"Recall:    {recall_score(y_true, y_pred):.2%}   (target > 70%)")
print(f"F1 Score:  {f1_score(y_true, y_pred):.2f}")
print("NOTE: this number is optimistic -- the model has seen every one of these")
print("rows during training, since dependency_labels.csv is both our only source")
print("of ground truth AND what we're evaluating against here. See the honest,")
print("held-out cross-validated estimate below for what to expect on unseen data.")

print("\n=== Per-category recall (in-sample) ===")
for category in labels["risk_type"].unique():
    if category == "NONE":
        continue
    true_rows = merged[merged["risk_type_true"] == category]
    if len(true_rows) == 0:
        continue
    caught = (true_rows["risk_type_pred"] == category).sum()
    print(f"{category:28s} {caught}/{len(true_rows)} caught  ({caught/len(true_rows):.0%})")

fp = merged[(merged["is_risky_pred"] == True) & (merged["risk_type_true"] == "NONE")]
total_negatives = (merged["risk_type_true"] == "NONE").sum()
print(f"\nFalse positive rate: {len(fp)}/{total_negatives} actual-clean rows incorrectly flagged "
      f"({len(fp) / total_negatives:.2%}, target < 20%)")


# ---------------------------------------------------------------------------
# Honest, held-out estimate: 5-fold cross-validation on the same feature set,
# so the risk model is never scored on rows it was trained on.
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print("CROSS-VALIDATED RESULT (honest estimate for unseen data)")
print("=" * 70)

import json
from datetime import date
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from detector import (load_data, build_app_index, build_vuln_index_by_lib, build_license_index,
                       license_flag, extract_features, FEATURE_COLUMNS)

apps, deps, vulns, licenses, transitive = load_data()
app_idx = build_app_index(apps)
vuln_by_lib = build_vuln_index_by_lib(vulns)
license_idx = build_license_index(licenses)
merged_raw = deps.merge(labels[["dep_id", "is_risky"]], on="dep_id")

det_tp = det_fp = 0
feature_rows, targets = [], []
for _, row in merged_raw.iterrows():
    app = app_idx[row["application_id"]]
    if license_flag(row, app, license_idx):
        if row["is_risky"]:
            det_tp += 1
        else:
            det_fp += 1
        continue
    feats, _ = extract_features(row, app, vuln_by_lib, license_idx)
    feature_rows.append(feats)
    targets.append(int(row["is_risky"]))

X = pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)
y = pd.Series(targets)
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=2)
proba = cross_val_predict(GradientBoostingClassifier(n_estimators=150, max_depth=3, random_state=0),
                           X, y, cv=cv, method="predict_proba")[:, 1]
ml_pred = (proba >= RISK_MODEL_THRESHOLD).astype(int)

ml_fp = int(((ml_pred == 1) & (y == 0)).sum())
total_tp = det_tp + int(((ml_pred == 1) & (y == 1)).sum())
total_fp = det_fp + ml_fp
total_true = int(labels["is_risky"].sum())
total_negatives_cv = det_fp + int((y == 0).sum())  # all actual-clean rows across both stages
cv_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0
cv_recall = total_tp / total_true
cv_fpr = total_fp / total_negatives_cv

print(f"Precision: {cv_precision:.2%}   (target > 75%)")
print(f"Recall:    {cv_recall:.2%}   (target > 70%)")
print(f"False positive rate: {cv_fpr:.2%}   (target < 20%)")
print("This is the number to trust for how the system would perform on a")
print("different (unseen) dataset -- deterministic license rule kept as-is")
print("(it's already exact), risk model scored only on held-out folds.")
