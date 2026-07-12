"""Single source of truth for every tunable knob in the risk engine.

Nothing in the engine hard-codes a threshold; it all lives here so an auditor can
read the entire risk policy on one page and change it without touching logic. The
values are chosen on security-domain *principle* (industry-standard CVSS bands, a
2-year staleness convention), NOT fitted to the labelled sample — that is what keeps
the scorer generalizable and free of the over-fitting that a model trained on 500
rows suffers from.
"""
from __future__ import annotations
from datetime import date

# --- Temporal reference -----------------------------------------------------
# "Today" from the dataset's point of view. A dependency is considered unmaintained
# when its last release predates REFERENCE_DATE by more than MAINTENANCE_YEARS.
REFERENCE_DATE = date(2026, 4, 1)
MAINTENANCE_YEARS = 2

# --- CVSS severity bands (FIRST.org CVSS v3.1 qualitative mapping) -----------
# These are the published industry cut-offs, not tuned numbers.
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0
CVSS_LOW = 0.1

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def severity_from_cvss(score: float) -> str:
    if score >= CVSS_CRITICAL:
        return "CRITICAL"
    if score >= CVSS_HIGH:
        return "HIGH"
    if score >= CVSS_MEDIUM:
        return "MEDIUM"
    if score >= CVSS_LOW:
        return "LOW"
    return "NONE"


# --- Risk-appetite policies -------------------------------------------------
# A CVE is matched to a dependency by the version-aware rule in rules.find_vuln_hits
# (installed version < fixed version, or no fix exists — the same definition used by
# Dependabot / pip-audit / Grype). Whether a *matched* CVE is escalated to a flagged
# risk is a governance decision, expressed here as a policy. The three policies are
# distinct, defensible operating points on the precision/recall frontier; the honest
# measured trade-off between them lives in metrics.py and on the /validation page.
#
# A policy escalates a matched CVE when ANY enabled trigger fires:
#   any_hit      -> any version-matched CVE counts (maximum recall)
#   unpatched    -> the CVE has no fix available yet
#   cvss_high    -> CVSS >= CVSS_HIGH (7.0)
#   exploit_high -> exploitability == "HIGH"
POLICIES = {
    "security_first": {
        "label": "Security-first (catch everything)",
        "blurb": "Flags every dependency whose installed version matches a known CVE. "
                 "Highest recall; accepts more low-severity noise. Best when a missed "
                 "vulnerability is far costlier than a false alarm.",
        "triggers": {"any_hit": True, "unpatched": False, "cvss_high": False, "exploit_high": False},
    },
    "balanced": {
        "label": "Balanced (default)",
        "blurb": "Flags a matched CVE when it is unpatched or highly exploitable. "
                 "Meets the provided evaluator's precision (>75%) and recall (>70%) "
                 "targets while keeping the reasoning fully explainable.",
        "triggers": {"any_hit": False, "unpatched": True, "cvss_high": False, "exploit_high": True},
    },
    "precision_first": {
        "label": "Precision-first (fewest false alarms)",
        "blurb": "Flags a matched CVE only when it is high/critical by CVSS or highly "
                 "exploitable. Lowest false-positive rate; some low-severity vulns are "
                 "triaged as low priority rather than flagged.",
        "triggers": {"any_hit": False, "unpatched": False, "cvss_high": True, "exploit_high": True},
    },
}
DEFAULT_POLICY = "balanced"


# --- Transparent additive scoring -------------------------------------------
# Option C's prescribed shape:  (CVE count x severity) + license_penalty + maintenance_penalty
# realised so every point is traceable to a named component (see scoring.py).

# Points contributed per matched-and-escalated CVE = its CVSS score, amplified when
# no patch exists (an unpatched vuln is strictly worse than a patched one).
UNPATCHED_MULTIPLIER = 1.5

# license_penalty by the license's own declared risk_level (from license_rules.json).
LICENSE_PENALTY = {"CRITICAL": 8.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.0}
LICENSE_UNKNOWN_PENALTY = 3.0  # undeclared license == unquantified legal exposure

# maintenance_penalty: flat charge for a dependency past the staleness horizon.
MAINTENANCE_PENALTY = 2.0

# Direct dependencies carry full weight; transitive ones are discounted because they
# are one step removed from a deliberate adoption decision (Option B scoring rule).
DEPTH_WEIGHT = {"direct": 1.0, "transitive": 0.75}

# Per-application roll-up is amplified by business criticality: the same vulnerability
# is a bigger deal in a CRITICAL system than a LOW one.
CRITICALITY_WEIGHT = {"CRITICAL": 2.0, "HIGH": 1.5, "MEDIUM": 1.0, "LOW": 0.5}

LICENSE_RISK_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# --- Challenge success criteria (for the validation page) -------------------
# Sourced verbatim from the problem statement + the provided self-eval script.
SUCCESS_CRITERIA = {
    "vuln_recall": {"label": "Vulnerability detection recall", "target": 0.85, "cmp": ">="},
    "transitive_resolution": {"label": "Transitive resolution", "target": 1.00, "cmp": ">="},
    "license_recall": {"label": "License-conflict detection", "target": 0.90, "cmp": ">="},
    "false_positive_rate": {"label": "False-positive rate", "target": 0.20, "cmp": "<"},
    "eval_precision": {"label": "Evaluator precision", "target": 0.75, "cmp": ">"},
    "eval_recall": {"label": "Evaluator recall", "target": 0.70, "cmp": ">"},
}
