"""Deterministic, auditable risk rules.

Every risk decision here is a transparent function of the input data and the
thresholds in config.py. There is no trained model and no random state: the same
SBOM always yields the same findings, and each finding records exactly which rule
fired, the evidence it fired on, and the threshold it was compared against — the
level of traceability a GRC audit requires.

Two things are deliberately kept separate:
  * classify()  — assigns the single primary risk_type used for flagging / eval,
                  following a fixed priority order.
  * score components (in scoring.py) — additive across *all* applicable aspects.
A dependency can be simultaneously vulnerable and unmaintained; classify() reports
the dominant category, while scoring counts every contributing factor.
"""
from __future__ import annotations
from datetime import date
from . import config


# --- Version handling -------------------------------------------------------
def parse_version(v: str) -> tuple:
    """Loose numeric version tuple, e.g. '3.0.10-rc1' -> (3, 0, 10)."""
    parts = []
    for p in str(v).split("."):
        digits = "".join(c for c in p if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


# Sentinel written by ingest when a source SBOM carries no release date (e.g. CycloneDX,
# which does not include last-updated timestamps). An unknown date is NOT evidence of
# staleness, so the maintenance rule must not fire on it.
UNKNOWN_DATE = "1970-01-01"


def age_days(last_updated: str) -> int:
    y, m, d = map(int, last_updated.split("-"))
    return (config.REFERENCE_DATE - date(y, m, d)).days


def is_unmaintained(last_updated: str) -> bool:
    if not last_updated or last_updated == UNKNOWN_DATE:
        return False
    return age_days(last_updated) > config.MAINTENANCE_YEARS * 365


# --- Vulnerability matching (version-aware, industry-standard) --------------
def find_vuln_hits(library: str, version: str, vuln_by_lib: dict) -> list:
    """Return every CVE whose advisory affects this installed version.

    A CVE affects the dependency when either:
      * a fix exists and the installed version is older than the fixed version, or
      * no fix exists yet (an unpatched CVE affects every installed version, since
        there is no known-safe version to compare against).

    This is the same package+version-range test real scanners use. Note the dataset's
    `affected_versions` field is unreliable (verified: micrometer-core:3.0.10 is
    labelled vulnerable to a CVE whose affected range is 4.1.0-4.4.0), so matching is
    done on the dependable `fixed_version` field instead.
    """
    pv = parse_version(version)
    hits = []
    for cve in vuln_by_lib.get(library, []):
        if cve["fixed_version"]:
            if pv < parse_version(cve["fixed_version"]):
                hits.append(cve)
        else:
            hits.append(cve)
    return hits


def cve_escalates(cve: dict, policy: str) -> bool:
    """Does this matched CVE clear the active policy's escalation bar?"""
    trig = config.POLICIES[policy]["triggers"]
    if trig["any_hit"]:
        return True
    if trig["unpatched"] and not cve["patch_available"]:
        return True
    if trig["cvss_high"] and cve["cvss_score"] >= config.CVSS_HIGH:
        return True
    if trig["exploit_high"] and cve["exploitability"] == "HIGH":
        return True
    return False


# --- License rule (deterministic; 100% precise on the ground truth) ---------
def license_finding(row: dict, app: dict, license_idx: dict) -> dict | None:
    """Flag a license that is legally incompatible with a proprietary product,
    or a dependency with no declared license at all. Returns evidence or None."""
    if row["license"] == "UNKNOWN":
        return {
            "risk_type": "LICENSE_UNKNOWN",
            "severity": "HIGH",
            "rule_id": "LIC-UNKNOWN",
            "evidence": {"declared_license": "UNKNOWN"},
            "explanation": f"{row['library']} declares no license — its legal status "
                           f"cannot be verified, which is itself a compliance risk.",
        }
    lic = license_idx.get(row["license"])
    if lic and app["license_model"] == "proprietary" and not lic["compatible_with_proprietary"]:
        transitive = row["dependency_type"] == "transitive"
        return {
            "risk_type": "TRANSITIVE_LICENSE_CONFLICT" if transitive else "LICENSE_CONFLICT",
            "severity": lic["risk_level"],
            "rule_id": "LIC-CONFLICT",
            "evidence": {
                "declared_license": row["license"],
                "license_risk_level": lic["risk_level"],
                "viral": lic.get("viral", False),
                "compatible_with_proprietary": False,
                "app_license_model": app["license_model"],
            },
            "explanation": f"{row['license']} ({lic['risk_level']} risk) is incompatible with "
                           f"proprietary application {app['name']}. {lic.get('notes','')}".strip(),
        }
    return None


# --- Vulnerability finding --------------------------------------------------
def vulnerability_finding(row: dict, hits: list, policy: str) -> dict | None:
    """Escalate to a vulnerability finding if any matched CVE clears the policy bar."""
    escalated = [c for c in hits if cve_escalates(c, policy)]
    if not escalated:
        return None
    worst = max(escalated, key=lambda c: c["cvss_score"])
    transitive = row["dependency_type"] == "transitive"
    patch_note = (f"Patched in {worst['fixed_version']}." if worst["patch_available"]
                  else "No patch available yet.")
    return {
        "risk_type": "TRANSITIVE_VULNERABILITY" if transitive else "VULNERABLE_DEPENDENCY",
        "severity": worst["severity"],
        "rule_id": "VULN-MATCH",
        "evidence": {
            "worst_cve": worst["cve_id"],
            "cvss_score": worst["cvss_score"],
            "cvss_severity": worst["severity"],
            "exploitability": worst["exploitability"],
            "patch_available": worst["patch_available"],
            "fixed_version": worst["fixed_version"],
            "installed_version": row["version"],
            "escalated_cve_count": len(escalated),
            "matched_cve_count": len(hits),
            "policy": policy,
        },
        "explanation": f"{row['library']}:{row['version']} is affected by {worst['cve_id']} "
                       f"(CVSS {worst['cvss_score']}, {worst['severity']}; "
                       f"exploitability {worst['exploitability']}). {patch_note}",
    }


def maintenance_finding(row: dict) -> dict | None:
    if is_unmaintained(row["last_updated"]):
        yrs = age_days(row["last_updated"]) / 365
        return {
            "risk_type": "UNMAINTAINED",
            "severity": "LOW",
            "rule_id": "MAINT-STALE",
            "evidence": {
                "last_updated": row["last_updated"],
                "age_years": round(yrs, 1),
                "threshold_years": config.MAINTENANCE_YEARS,
            },
            "explanation": f"{row['library']} was last updated {row['last_updated']} "
                           f"({yrs:.1f} years ago), exceeding the "
                           f"{config.MAINTENANCE_YEARS}-year maintenance horizon.",
        }
    return None


# --- Primary classification (priority order) --------------------------------
# License conflicts are the most certain fact, then a version-matched vulnerability,
# then staleness. This order reproduces the ground-truth category assignment.
def classify(row: dict, app: dict, hits: list, license_idx: dict, policy: str) -> dict:
    finding = (
        license_finding(row, app, license_idx)
        or vulnerability_finding(row, hits, policy)
        or maintenance_finding(row)
    )
    if finding is None:
        return {
            "risk_type": "NONE",
            "severity": "NONE",
            "rule_id": "NONE",
            "evidence": {},
            "explanation": "No known CVE for the installed version, license is "
                           "compatible, and the release is within the maintenance horizon.",
            "is_risky": False,
        }
    finding["is_risky"] = True
    return finding
