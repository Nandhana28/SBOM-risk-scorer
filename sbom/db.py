"""SQLite storage layer.

Why SQLite: it turns the flat sample files into a real queryable store, isolates each
uploaded SBOM under its own scan_id (so one deployment can hold many analyses), and
gives us a durable audit trail of every scan run — all without a server. Reference
data that is global to the organisation (the CVE feed and the license matrix) lives in
its own tables; per-SBOM data (applications, dependencies, transitive edges) is
partitioned by scan_id.

The database is seeded once from the bundled data/ files under the BASELINE scan.
"""
from __future__ import annotations
import json
import os
import sqlite3
from contextlib import contextmanager

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "sbom.db")
BASELINE = "BASELINE"

SCHEMA = """
CREATE TABLE IF NOT EXISTS applications (
    scan_id TEXT, app_id TEXT, name TEXT, language TEXT, criticality TEXT,
    license_model TEXT, business_owner TEXT, department TEXT, deployment TEXT,
    PRIMARY KEY (scan_id, app_id)
);
CREATE TABLE IF NOT EXISTS dependencies (
    scan_id TEXT, dep_id TEXT, application_id TEXT, application_name TEXT,
    library TEXT, version TEXT, license TEXT, dependency_type TEXT,
    last_updated TEXT, transitive_deps TEXT,
    PRIMARY KEY (scan_id, dep_id)
);
CREATE TABLE IF NOT EXISTS transitive_edges (
    scan_id TEXT, parent_library TEXT, parent_version TEXT,
    child_library TEXT, child_version TEXT, application_id TEXT
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT, library TEXT, affected_versions TEXT, fixed_version TEXT,
    cvss_score REAL, severity TEXT, exploitability TEXT, description TEXT,
    patch_available INTEGER, published_date TEXT
);
CREATE TABLE IF NOT EXISTS license_rules (
    license TEXT PRIMARY KEY, spdx TEXT, risk_level TEXT,
    compatible_with_proprietary INTEGER, viral INTEGER, notes TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY, created_at TEXT, source TEXT, policy TEXT,
    n_apps INTEGER, n_deps INTEGER, n_flagged INTEGER, notes TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id TEXT, policy TEXT, dep_id TEXT, risk_type TEXT, severity TEXT,
    is_risky INTEGER, score REAL, rule_id TEXT, evidence TEXT, explanation TEXT,
    PRIMARY KEY (scan_id, policy, dep_id)
);
CREATE INDEX IF NOT EXISTS idx_vuln_lib ON vulnerabilities(library);
CREATE INDEX IF NOT EXISTS idx_dep_scan ON dependencies(scan_id);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(force_reseed: bool = False):
    os.makedirs(DATA_DIR, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        seeded = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        baseline = conn.execute(
            "SELECT COUNT(*) FROM dependencies WHERE scan_id=?", (BASELINE,)).fetchone()[0]
    if force_reseed or not seeded or not baseline:
        _seed_baseline()


def _load_json(name):
    with open(os.path.join(DATA_DIR, name), encoding="utf-8") as f:
        return json.load(f)


def _seed_baseline():
    """Load the bundled sample files into SQLite under the BASELINE scan."""
    import csv
    apps = _load_json("applications.json")
    vulns = _load_json("vulnerability_db.json")
    licenses = _load_json("license_rules.json")
    transitive = _load_json("transitive_dependencies.json")
    with open(os.path.join(DATA_DIR, "sbom_dependencies.csv"), encoding="utf-8") as f:
        deps = list(csv.DictReader(f))

    with get_conn() as conn:
        conn.execute("DELETE FROM vulnerabilities")
        conn.execute("DELETE FROM license_rules")
        for t in ("applications", "dependencies", "transitive_edges", "findings"):
            conn.execute(f"DELETE FROM {t} WHERE scan_id=?", (BASELINE,))
        conn.execute("DELETE FROM scans WHERE scan_id=?", (BASELINE,))

        conn.executemany(
            "INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(v["cve_id"], v["library"], json.dumps(v["affected_versions"]), v["fixed_version"],
              v["cvss_score"], v["severity"], v["exploitability"], v["description"],
              int(v["patch_available"]), v["published_date"]) for v in vulns])
        conn.executemany(
            "INSERT INTO license_rules VALUES (?,?,?,?,?,?)",
            [(l["license"], l["spdx"], l["risk_level"], int(l["compatible_with_proprietary"]),
              int(l["viral"]), l["notes"]) for l in licenses])
        insert_applications(conn, BASELINE, apps)
        insert_dependencies(conn, BASELINE, deps)
        insert_edges(conn, BASELINE, transitive)
        conn.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)",
                     (BASELINE, _now(), "seed", None, len(apps), len(deps), None,
                      "Bundled SG hackathon sample dataset (10 applications)."))


# --- writers ----------------------------------------------------------------
def insert_applications(conn, scan_id, apps):
    conn.executemany(
        "INSERT OR REPLACE INTO applications VALUES (?,?,?,?,?,?,?,?,?)",
        [(scan_id, a["app_id"], a["name"], a.get("language"), a.get("criticality", "MEDIUM"),
          a.get("license_model", "proprietary"), a.get("business_owner"),
          a.get("department"), a.get("deployment")) for a in apps])


def insert_dependencies(conn, scan_id, deps):
    conn.executemany(
        "INSERT OR REPLACE INTO dependencies VALUES (?,?,?,?,?,?,?,?,?,?)",
        [(scan_id, d["dep_id"], d["application_id"], d.get("application_name"), d["library"],
          d["version"], d.get("license", "UNKNOWN"), d.get("dependency_type", "direct"),
          d.get("last_updated", "1970-01-01"), d.get("transitive_deps", "")) for d in deps])


def insert_edges(conn, scan_id, edges):
    conn.executemany(
        "INSERT INTO transitive_edges VALUES (?,?,?,?,?,?)",
        [(scan_id, e["parent_library"], e["parent_version"], e["child_library"],
          e["child_version"], e["application_id"]) for e in edges])


def record_scan(scan_id, source, policy, n_apps, n_deps, n_flagged, notes=""):
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?)",
                     (scan_id, _now(), source, policy, n_apps, n_deps, n_flagged, notes))


def save_findings(scan_id, policy, findings):
    with get_conn() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id=? AND policy=?", (scan_id, policy))
        conn.executemany(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(scan_id, policy, f["dep_id"], f["risk_type"], f["severity"], int(f["is_risky"]),
              f["score"], f["rule_id"], json.dumps(f["evidence"]), f["explanation"])
             for f in findings])


def _now():
    # date/time is passed in by callers where determinism matters; scans log uses wall clock.
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- readers ----------------------------------------------------------------
def get_applications(scan_id):
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM applications WHERE scan_id=?", (scan_id,))]


def get_dependencies(scan_id):
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM dependencies WHERE scan_id=?", (scan_id,))]


def get_edges(scan_id):
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM transitive_edges WHERE scan_id=?", (scan_id,))]


def get_vulnerabilities():
    with get_conn() as conn:
        rows = []
        for r in conn.execute("SELECT * FROM vulnerabilities"):
            d = dict(r)
            d["affected_versions"] = json.loads(d["affected_versions"])
            d["patch_available"] = bool(d["patch_available"])
            rows.append(d)
        return rows


def get_license_rules():
    with get_conn() as conn:
        rows = []
        for r in conn.execute("SELECT * FROM license_rules"):
            d = dict(r)
            d["compatible_with_proprietary"] = bool(d["compatible_with_proprietary"])
            d["viral"] = bool(d["viral"])
            rows.append(d)
        return rows


def list_scans():
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC, scan_id")]
