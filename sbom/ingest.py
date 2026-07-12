"""SBOM ingestion — parse an uploaded file into normalized dependency rows.

Supports the two formats a user is most likely to bring:
  * the native CSV schema used by this challenge (sbom_dependencies.csv), and
  * CycloneDX JSON (the de-facto industry SBOM standard, what `syft`/`cdxgen` emit).

Each upload is stored under a fresh scan_id so it never disturbs the baseline data,
and any application referenced by a dependency but not otherwise described is given a
sensible placeholder (proprietary / MEDIUM criticality) so the pipeline can run. This
is what makes the tool usable beyond the bundled sample — the whole point of "scalable,
not just for this dataset".
"""
from __future__ import annotations
import csv
import io
import json
import re
from . import db


class IngestError(ValueError):
    pass


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").upper()[:40] or "UPLOAD"


def parse_native_csv(text: str) -> list:
    reader = csv.DictReader(io.StringIO(text))
    required = {"dep_id", "application_id", "library", "version"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
        raise IngestError(
            f"CSV must contain at least the columns {sorted(required)}; "
            f"got {reader.fieldnames}.")
    rows = []
    for i, r in enumerate(reader, 1):
        rows.append({
            "dep_id": r.get("dep_id") or f"DEP-{i:04d}",
            "application_id": r["application_id"],
            "application_name": r.get("application_name") or r["application_id"],
            "library": r["library"],
            "version": r.get("version", "0"),
            "license": r.get("license") or "UNKNOWN",
            "dependency_type": r.get("dependency_type") or "direct",
            "last_updated": r.get("last_updated") or "1970-01-01",
            "transitive_deps": r.get("transitive_deps") or "",
        })
    if not rows:
        raise IngestError("CSV contained no dependency rows.")
    return rows


_PURL_LICENSE = re.compile(r'"?(?:id|name)"?\s*:\s*"([^"]+)"')


def parse_cyclonedx(text: str) -> tuple:
    """Return (deps, app_name) from a CycloneDX 1.x JSON document."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise IngestError(f"Not valid JSON: {e}")
    if doc.get("bomFormat") != "CycloneDX":
        raise IngestError("JSON is not a CycloneDX document (missing bomFormat: CycloneDX).")

    meta_comp = (doc.get("metadata") or {}).get("component") or {}
    app_name = meta_comp.get("name") or "UploadedApp"
    app_id = _slug(app_name)

    deps = []
    for i, c in enumerate(doc.get("components", []), 1):
        if c.get("type") not in (None, "library", "framework", "application"):
            continue
        lic = "UNKNOWN"
        for entry in c.get("licenses", []) or []:
            info = entry.get("license") or {}
            lic = info.get("id") or info.get("name") or lic
            if lic != "UNKNOWN":
                break
        deps.append({
            "dep_id": c.get("bom-ref") or f"{app_id}-DEP-{i:04d}",
            "application_id": app_id,
            "application_name": app_name,
            "library": c.get("name") or f"component-{i}",
            "version": c.get("version") or "0",
            "license": lic,
            "dependency_type": "direct",
            "last_updated": (c.get("properties_last_updated") or "1970-01-01"),
            "transitive_deps": "",
        })
    if not deps:
        raise IngestError("CycloneDX document had no components to analyze.")
    return deps, app_name


def ingest_upload(filename: str, content: bytes) -> str:
    """Parse an uploaded SBOM, persist it under a new scan_id, and return that id."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("cp1252", errors="replace")

    name = (filename or "").lower()
    if name.endswith(".json") or text.lstrip().startswith("{"):
        deps, app_name = parse_cyclonedx(text)
    elif name.endswith(".csv") or "," in text.splitlines()[0]:
        deps = parse_native_csv(text)
        app_name = None
    else:
        raise IngestError("Unsupported file type — upload a .csv (native schema) or "
                          ".json (CycloneDX) SBOM.")

    # Synthesize application rows for any app referenced by a dependency.
    app_ids = {}
    for d in deps:
        app_ids.setdefault(d["application_id"], d.get("application_name") or d["application_id"])
    apps = [{"app_id": aid, "name": nm, "language": None, "criticality": "MEDIUM",
             "license_model": "proprietary", "business_owner": None,
             "department": None, "deployment": None} for aid, nm in app_ids.items()]

    scan_id = _slug((app_name or (filename or "upload")).rsplit(".", 1)[0]) + "-" + _short_hash(text)
    with db.get_conn() as conn:
        for t in ("applications", "dependencies", "transitive_edges", "findings"):
            conn.execute(f"DELETE FROM {t} WHERE scan_id=?", (scan_id,))
        db.insert_applications(conn, scan_id, apps)
        db.insert_dependencies(conn, scan_id, deps)
    db.record_scan(scan_id, filename or "upload", None, len(apps), len(deps), None,
                   f"Uploaded SBOM ({len(deps)} components across {len(apps)} app(s)).")
    return scan_id


def _short_hash(text: str) -> str:
    import hashlib
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:8]
