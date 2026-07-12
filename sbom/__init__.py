"""SBOM Supply-Chain Risk Scorer — auditable, explainable, deterministic engine.

Package layout:
    config.py   all thresholds, weights and risk-appetite policies (single source of truth)
    db.py       SQLite storage: schema, seeding, query helpers
    ingest.py   parse native CSV / CycloneDX SBOM uploads into normalized rows
    rules.py    deterministic risk rules; every finding carries structured evidence
    scoring.py  transparent additive risk score with a per-component breakdown
    engine.py   orchestration: load -> classify -> score -> per-app rollup
    metrics.py  validation against ground truth and the challenge success criteria
"""
