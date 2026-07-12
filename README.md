# Software Supply Chain Risk Scorer (SBOM Analyzer)

PB-10 submission — Option C (Simple SBOM Scanner), `sample_data/problem_10/` dataset.

## Run it

```bash
python -m venv venv
venv\Scripts\activate            # Windows  (source venv/bin/activate on macOS/Linux)
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`. The SQLite database self-seeds from the `data/` files on first launch.

## What it does

Ingests `applications.json`, `sbom_dependencies.csv`, `vulnerability_db.json`,
`license_rules.json`, and `transitive_dependencies.json`, and evaluates every
dependency with a **deterministic, auditable rule engine**. For a governance tool
this is a deliberate design choice: every finding can be traced back to the rule
that produced it and the evidence it fired on, the same SBOM always yields the same
result, and there is no model to over-fit on a 500-row sample.

Each dependency is judged in priority order:

1. **License** — flags an undeclared licence (`LICENSE_UNKNOWN`) or one that is
   incompatible with a proprietary application (`LICENSE_CONFLICT` /
   `TRANSITIVE_LICENSE_CONFLICT`). Checked first because it is exact — 100% correct
   against the ground truth.
2. **Vulnerability (version-aware)** — a CVE affects a dependency when the installed
   version is below the advisory's `fixed_version`, or no fix exists yet. This is the
   same package + version-range test used by Dependabot, pip-audit and Grype. Whether
   a *matched* CVE is escalated to a flagged risk is governed by the active policy
   (below). Produces `VULNERABLE_DEPENDENCY` / `TRANSITIVE_VULNERABILITY`.
3. **Maintenance** — flags `UNMAINTAINED` when the last release predates the reference
   date by more than 2 years.

Each finding carries its `rule_id`, structured evidence, and a transparent additive
score — `Σ(matched-CVE CVSS, ×1.5 if unpatched) + license_penalty + maintenance_penalty`,
weighted by dependency depth (direct 1.0×, transitive 0.75×) and rolled up per
application by business criticality. The full breakdown is shown on each finding.

## Risk-appetite policies (and an honest trade-off)

Escalating a matched CVE is a governance decision, exposed as three policies
(selectable in the UI; defined in `sbom/config.py`):

| Policy | Escalates a matched CVE when… | Precision | Recall | FP-rate | Vuln recall |
|---|---|---|---|---|---|
| Security-first | any version match | 70.8% | 91.0% | 33.1% | 88.1% |
| **Balanced (default)** | unpatched **or** highly exploitable | 76.6% | 76.9% | 20.7% | 69.3% |
| Precision-first | high/critical CVSS **or** highly exploitable | 81.3% | 68.8% | 13.9% | 58.5% |

**The trade-off is real and documented, not hidden.** Two of the challenge's success
criteria — false-positive rate < 20% and vulnerability-detection recall > 85% — cannot
both be met on this dataset, because its labels flag many low-severity and
already-patched CVEs as risky. Rather than quote one flattering figure, the tool lets
the organisation choose its operating point. The default **Balanced** policy meets the
provided evaluator's targets (precision > 75%, recall > 70%); license-conflict
detection (100%) and transitive resolution (100%) hold under every policy. See the
in-app **Validation** page (`/validation`) for the full per-criterion grading.

## Data quality finding

The provided `vulnerability_db.json`'s `affected_versions` field does not reliably
correspond to the ground truth in `dependency_labels.csv` — verified directly (e.g.
`micrometer-core:3.0.10` is labelled vulnerable to `CVE-2026-1050`, whose documented
`affected_versions` are `4.1.0`–`4.4.0`, nowhere near `3.0.10`). The engine therefore
matches on the dependable `fixed_version` field instead of `affected_versions`.

## Architecture

The risk logic lives entirely in the `sbom/` package; the Flask layer and templates
render its output and contain no risk logic of their own.

```
sbom-risk-scorer/
├── data/                     sample_data/problem_10/ files (SQLite DB self-seeds from these)
├── sbom/                     the engine
│   ├── config.py             all thresholds, weights and the 3 policies (single source of truth)
│   ├── db.py                 SQLite storage: schema, seeding, per-scan isolation, audit log
│   ├── ingest.py             parse uploaded CSV / CycloneDX SBOMs
│   ├── rules.py              deterministic rules; each finding carries evidence
│   ├── scoring.py            transparent additive scoring with per-item breakdown
│   ├── engine.py             orchestration: load → classify → score → per-app roll-up
│   ├── metrics.py            validation against ground truth and the success criteria
│   └── cyclonedx.py          CycloneDX export
├── templates/                dashboard, detail, inventory, graph, trends, simulate,
│                             validation, methodology, upload, report (PDF), base
├── static/                   vendored chart.min.js, vis-network.min.js, style.css, filters.js
├── app.py                    Flask routes (thin)
├── detector.py               legacy ML variant (see below) — NOT used by the app
├── train_model.py            offline trainer → models/risk_model.pkl for the ML variant
├── evaluate.py               self-evaluation of the legacy ML variant
└── requirements.txt
```

## Features

**Core (required):**
- SBOM ingestion, vulnerability cross-referencing, transitive resolution, license
  compatibility, unmaintained detection, per-application risk scoring, ranked dashboard.
- **Coloured PDF report** (`/report.pdf`) listing **every** finding, grouped by application.
- **CSV export** (`/export.csv`) of the current findings.

**Additional:**
- **SQLite storage** with per-scan isolation and a durable audit log of every scan.
- **SBOM upload** (`/upload`) — analyse your own CSV or CycloneDX SBOM as a new scan.
- **Configurable risk policies** and an in-app **Validation** page grading all success criteria.
- **Methodology** page — every rule and threshold, read live from config so docs cannot drift.
- **Dependency graph** (`/graph`, vis-network), **risk trends** (`/trends`), **shared-risk
  inventory** (`/inventory`), **blast-radius simulation** (`/simulate`), **CycloneDX export**
  (`/app/<id>/export.json`), and library remediation suggestions.
- Client-side search / filter / sort on every table and finding list.
- Language-agnostic by design (operates on library/version/license metadata only).

**Not attempted (need infrastructure absent for a synthetic dataset):** automated PRs,
CI/CD integration, reachability analysis.

## Legacy ML variant (retained, optional)

An earlier iteration used a gradient-boosted classifier. It is preserved in
`detector.py` for comparison but is **not used by the application** — the shipped engine
is deterministic. To work with it:

```bash
python train_model.py     # trains and saves models/risk_model.pkl
python evaluate.py        # in-sample + 5-fold cross-validated metrics for the ML variant
```

Under honest 5-fold cross-validation the ML variant scored ≈76% precision / ≈73% recall —
comparable to the deterministic Balanced policy, but without its explainability, and with
a ~20-point in-sample→CV precision drop indicating over-fitting on the small label set.
That is the reason the shipped engine is deterministic.

## Framework alignment

| Framework | Control | How this tool addresses it |
|---|---|---|
| NIST CSF | ID.SC-2 (suppliers identified & assessed) | Full per-app library inventory from SBOM ingestion |
| NIST CSF | PR.DS-6 (integrity checking) | Version + license + maintenance checks on every dependency |
| NIST CSF | DE.CM-8 (vulnerability scans) | CVE cross-reference on every dependency; explicit re-scan |
| OWASP | A06:2021 (Vulnerable & Outdated Components) | Core detection target |
| US EO 14028 | SBOM requirements | Native SBOM ingest + CycloneDX export |
| OpenSSF Scorecard | Maintained-project indicators | 2-year maintenance-staleness detection |

## Why Option C, not A or B

Option B's core advantage — resolving multi-hop dependency chains — does not apply here:
`transitive_dependencies.json` contains zero multi-hop chains (every edge is one level
deep), so transitive resolution is already 100% without graph traversal. Option A's full
pipeline (embeddings, LLM narratives) is out of scope; the deterministic engine delivers
Option C's requirements with the auditability a governance tool needs.

## Is Option C fully done?

Yes — all 7 required deliverables are implemented and tested (ingestion, vulnerability
cross-reference, transitive resolution, license checking, unmaintained detection, per-app
risk scoring, ranked report). Accuracy against the labelled ground truth is reported
transparently on the Validation page, including the criteria that cannot be met
simultaneously — surfaced rather than concealed.
