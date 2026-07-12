"""Transparent additive risk score.

Implements Option C's prescribed shape

    dependency_score = (sum of matched-CVE severity)  +  license_penalty  +  maintenance_penalty
    (then weighted by dependency depth)

but returns, alongside the number, an itemised breakdown so the UI can show *why*
a dependency scored what it did. No component is hidden inside a model — every point
is attributable to a named factor, which is what makes the score auditable.

The per-application roll-up sums its dependencies' scores and amplifies by business
criticality, again with a breakdown.
"""
from __future__ import annotations
from . import config, rules


def score_dependency(row: dict, app: dict, hits: list, license_idx: dict, policy: str):
    """Return (final_score, breakdown[list of {component, detail, points}])."""
    breakdown = []

    # --- vulnerability component: (CVE count x severity), realised as sum of CVSS ---
    escalated = [c for c in hits if rules.cve_escalates(c, policy)]
    for cve in sorted(escalated, key=lambda c: c["cvss_score"], reverse=True):
        pts = cve["cvss_score"]
        detail = f"{cve['cve_id']} CVSS {cve['cvss_score']} ({cve['severity']})"
        if not cve["patch_available"]:
            pts *= config.UNPATCHED_MULTIPLIER
            detail += f" x{config.UNPATCHED_MULTIPLIER} unpatched"
        breakdown.append({"component": "vulnerability", "detail": detail, "points": round(pts, 2)})

    # --- license_penalty ---
    if row["license"] == "UNKNOWN":
        breakdown.append({"component": "license", "detail": "undeclared license",
                          "points": config.LICENSE_UNKNOWN_PENALTY})
    else:
        lic = license_idx.get(row["license"])
        if lic and app["license_model"] == "proprietary" and not lic["compatible_with_proprietary"]:
            pts = config.LICENSE_PENALTY.get(lic["risk_level"], 0.0)
            breakdown.append({"component": "license",
                              "detail": f"{row['license']} incompatible with proprietary ({lic['risk_level']})",
                              "points": pts})

    # --- maintenance_penalty ---
    if rules.is_unmaintained(row["last_updated"]):
        breakdown.append({"component": "maintenance",
                          "detail": f"stale since {row['last_updated']}",
                          "points": config.MAINTENANCE_PENALTY})

    raw = sum(item["points"] for item in breakdown)
    depth_w = config.DEPTH_WEIGHT.get(row["dependency_type"], 1.0)
    final = round(raw * depth_w, 2)
    if depth_w != 1.0 and raw:
        breakdown.append({"component": "depth-weight",
                          "detail": f"x{depth_w} ({row['dependency_type']} dependency)",
                          "points": round(final - raw, 2)})
    return final, breakdown


def score_application(app: dict, dep_scores: list):
    """Return (weighted_score, breakdown) for one application from its dep scores."""
    raw = round(sum(dep_scores), 2)
    w = config.CRITICALITY_WEIGHT.get(app["criticality"], 1.0)
    weighted = round(raw * w, 1)
    breakdown = {
        "raw_dependency_total": raw,
        "criticality": app["criticality"],
        "criticality_weight": w,
        "weighted_score": weighted,
    }
    return weighted, breakdown
