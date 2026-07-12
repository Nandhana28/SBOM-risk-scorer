"""Orchestration: turn stored SBOM data into scored, explained findings.

Pipeline per dependency:  load -> match CVEs (version-aware) -> classify (rules) ->
score (transparent additive) -> attach remediation + transitive chain. Results are
cached in-memory per (scan_id, policy) and persisted to the findings table for audit.
"""
from __future__ import annotations
from . import config, db, rules, scoring
from .alternatives_bridge import suggest_alternative

_CACHE = {}


def _indexes(scan_id):
    apps = db.get_applications(scan_id)
    deps = db.get_dependencies(scan_id)
    vulns = db.get_vulnerabilities()
    licenses = db.get_license_rules()
    edges = db.get_edges(scan_id)

    app_idx = {a["app_id"]: a for a in apps}
    license_idx = {l["license"]: l for l in licenses}
    vuln_by_lib = {}
    for v in vulns:
        vuln_by_lib.setdefault(v["library"], []).append(v)
    parent_map = {}
    for e in edges:
        parent_map.setdefault((e["child_library"], e["application_id"]), []).append(
            (e["parent_library"], e["parent_version"]))
    return apps, app_idx, deps, vuln_by_lib, license_idx, parent_map


def _remediation(finding, row):
    rt = finding["risk_type"]
    if rt in ("LICENSE_CONFLICT", "TRANSITIVE_LICENSE_CONFLICT", "LICENSE_UNKNOWN"):
        return suggest_alternative(row["library"])
    if rt in ("VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"):
        fv = finding["evidence"].get("fixed_version")
        return (f"Upgrade to {fv} or later." if fv
                else "No patch is available yet — isolate, replace, or add a compensating control.")
    if rt == "UNMAINTAINED":
        return "Move to an actively maintained equivalent, or fork and own the maintenance."
    return ""


def analyze(scan_id=db.BASELINE, policy=config.DEFAULT_POLICY, use_cache=True):
    key = (scan_id, policy)
    if use_cache and key in _CACHE:
        return _CACHE[key]

    apps, app_idx, deps, vuln_by_lib, license_idx, parent_map = _indexes(scan_id)
    findings = []
    for row in deps:
        app = app_idx.get(row["application_id"], {
            "name": row.get("application_name") or row["application_id"],
            "criticality": "MEDIUM", "license_model": "proprietary"})
        hits = rules.find_vuln_hits(row["library"], row["version"], vuln_by_lib)
        finding = rules.classify(row, app, hits, license_idx, policy)
        score, breakdown = scoring.score_dependency(row, app, hits, license_idx, policy)
        parents = parent_map.get((row["library"], row["application_id"]), [])

        findings.append({
            "dep_id": row["dep_id"],
            "application_id": row["application_id"],
            "application_name": app.get("name", row["application_id"]),
            "library": row["library"],
            "version": row["version"],
            "license": row["license"],
            "dependency_type": row["dependency_type"],
            "last_updated": row["last_updated"],
            "risk_type": finding["risk_type"],
            "severity": finding["severity"],
            "is_risky": finding["is_risky"],
            "rule_id": finding["rule_id"],
            "evidence": finding["evidence"],
            "explanation": finding["explanation"],
            "remediation": _remediation(finding, row) if finding["is_risky"] else "",
            "score": score,
            "score_breakdown": breakdown,
            "matched_cves": hits,
            "parents": parents,
        })

    n_flagged = sum(1 for f in findings if f["is_risky"])
    db.save_findings(scan_id, policy, findings)
    db.record_scan(scan_id, "analyze", policy, len(apps), len(deps), n_flagged,
                   f"{n_flagged}/{len(deps)} dependencies flagged under '{policy}' policy.")
    _CACHE[key] = findings
    return findings


def application_summaries(findings, scan_id=db.BASELINE):
    app_idx = {a["app_id"]: a for a in db.get_applications(scan_id)}
    by_app = {}
    for f in findings:
        by_app.setdefault(f["application_id"], []).append(f)

    summaries = []
    for app_id, group in by_app.items():
        app = app_idx.get(app_id, {"app_id": app_id, "name": app_id,
                                   "criticality": "MEDIUM", "license_model": "proprietary"})
        weighted, sbreak = scoring.score_application(app, [f["score"] for f in group])
        risky = [f for f in group if f["is_risky"]]
        summaries.append({
            "application_id": app_id,
            "name": app.get("name", app_id),
            "criticality": app.get("criticality", "MEDIUM"),
            "department": app.get("department"),
            "risk_score": weighted,
            "score_breakdown": sbreak,
            "flagged_count": len(risky),
            "total_deps": len(group),
            "top_findings": sorted(risky, key=lambda f: f["score"], reverse=True)[:5],
        })
    return sorted(summaries, key=lambda s: s["risk_score"], reverse=True)


def clear_cache():
    _CACHE.clear()
