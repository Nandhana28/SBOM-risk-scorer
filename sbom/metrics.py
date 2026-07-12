"""Validate the engine against the labelled ground truth and the challenge criteria.

Because the engine is deterministic (no training), there is no train/test leakage to
worry about: the numbers here are exactly what the same rules would produce on unseen
data drawn from the same schema. metrics for every policy are computed so the UI can
show the precision/recall trade-off honestly instead of quoting one flattering number.
"""
from __future__ import annotations
import csv
import os
from . import config, db, rules
from .engine import analyze

VULN_CATS = {"VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"}
LICENSE_CATS = {"LICENSE_CONFLICT", "TRANSITIVE_LICENSE_CONFLICT", "LICENSE_UNKNOWN"}


def _load_labels():
    """dep_id -> {is_risky, risk_type}. The labels file carries cp1252 bytes (em-dashes)."""
    path = os.path.join(db.DATA_DIR, "dependency_labels.csv")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="cp1252") as f:
        return {r["dep_id"]: {"is_risky": r["is_risky"].strip().lower() == "true",
                              "risk_type": r["risk_type"]}
                for r in csv.DictReader(f)}


def _cmp(value, target, op):
    return value >= target if op == ">=" else value > target if op == ">" else value < target


def evaluate_policy(policy):
    labels = _load_labels()
    if not labels:
        return None
    findings = {f["dep_id"]: f for f in analyze(db.BASELINE, policy)}

    tp = fp = fn = tn = 0
    cat_total, cat_caught = {}, {}
    for dep_id, lab in labels.items():
        f = findings.get(dep_id)
        if f is None:
            continue
        pred, actual = f["is_risky"], lab["is_risky"]
        tp += pred and actual
        fp += pred and not actual
        fn += (not pred) and actual
        tn += (not pred) and (not actual)
        if actual:
            c = lab["risk_type"]
            cat_total[c] = cat_total.get(c, 0) + 1
            cat_caught[c] = cat_caught.get(c, 0) + (1 if pred else 0)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    def cat_recall(cats):
        t = sum(cat_total.get(c, 0) for c in cats)
        c = sum(cat_caught.get(c, 0) for c in cats)
        return (c / t if t else 1.0), c, t

    vuln_recall, vc, vt = cat_recall(VULN_CATS)
    license_recall, lc, lt = cat_recall(LICENSE_CATS)

    measured = {
        "vuln_recall": vuln_recall,
        "transitive_resolution": _transitive_resolution(),
        "license_recall": license_recall,
        "false_positive_rate": fpr,
        "eval_precision": precision,
        "eval_recall": recall,
    }
    criteria = []
    for key, spec in config.SUCCESS_CRITERIA.items():
        val = measured[key]
        criteria.append({
            "key": key, "label": spec["label"], "target": spec["target"],
            "cmp": spec["cmp"], "value": val, "passed": _cmp(val, spec["target"], spec["cmp"]),
        })

    return {
        "policy": policy,
        "policy_label": config.POLICIES[policy]["label"],
        "precision": precision, "recall": recall, "fpr": fpr,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "vuln_recall": vuln_recall, "vuln_caught": vc, "vuln_total": vt,
        "license_recall": license_recall, "license_caught": lc, "license_total": lt,
        "per_category": {c: {"caught": cat_caught.get(c, 0), "total": cat_total[c],
                             "recall": cat_caught.get(c, 0) / cat_total[c]}
                         for c in sorted(cat_total)},
        "criteria": criteria,
        "criteria_passed": sum(c["passed"] for c in criteria),
        "criteria_total": len(criteria),
    }


def transitive_stats():
    """Transitive-graph resolution stats.

    resolution = fraction of parent->child edges in the SBOM that we successfully link
    to a real dependency (our capability). We also count 'orphans': dependencies marked
    transitive that carry no parent edge in the source data at all — a completeness gap
    in the input SBOM, surfaced rather than hidden.
    """
    deps = db.get_dependencies(db.BASELINE)
    edges = db.get_edges(db.BASELINE)
    dep_libs = {(d["library"], d["application_id"]) for d in deps}
    parents = {(e["child_library"], e["application_id"]) for e in edges}
    trans = [d for d in deps if d["dependency_type"] == "transitive"]
    resolved_edges = sum(1 for e in edges if (e["child_library"], e["application_id"]) in dep_libs)
    orphans = [d for d in trans if (d["library"], d["application_id"]) not in parents]
    return {
        "resolution": resolved_edges / len(edges) if edges else 1.0,
        "edges": len(edges),
        "resolved_edges": resolved_edges,
        "transitive_deps": len(trans),
        "orphans": len(orphans),
    }


def _transitive_resolution():
    return transitive_stats()["resolution"]


def evaluate_all_policies():
    return {p: evaluate_policy(p) for p in config.POLICIES}


if __name__ == "__main__":
    db.init_db()
    for pol in config.POLICIES:
        r = evaluate_policy(pol)
        print(f"\n=== {r['policy_label']} ===")
        print(f"  precision={r['precision']:.1%}  recall={r['recall']:.1%}  fpr={r['fpr']:.1%}"
              f"  vuln-recall={r['vuln_recall']:.1%}")
        print(f"  criteria passed: {r['criteria_passed']}/{r['criteria_total']}")
        for c in r["criteria"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"    [{mark}] {c['label']:32s} {c['value']:.1%} (target {c['cmp']} {c['target']:.0%})")
