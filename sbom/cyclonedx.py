"""Export one application's analyzed dependencies as a CycloneDX 1.5 document
(components + vulnerabilities), the industry-standard interchange format."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone


def to_cyclonedx(app: dict, findings: list) -> dict:
    components, vulnerabilities = [], []
    for f in findings:
        bom_ref = f"{f['library']}@{f['version']}"
        components.append({
            "type": "library",
            "bom-ref": bom_ref,
            "name": f["library"],
            "version": f["version"],
            "purl": f"pkg:generic/{f['library']}@{f['version']}",
            "licenses": [{"license": {"id": f["license"]}}] if f["license"] != "UNKNOWN" else [],
        })
        if f["risk_type"] in ("VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"):
            ev = f["evidence"]
            vulnerabilities.append({
                "bom-ref": f"vuln-{bom_ref}",
                "id": ev.get("worst_cve", "UNKNOWN"),
                "ratings": [{"severity": f["severity"].lower(), "score": ev.get("cvss_score"),
                             "method": "CVSSv3"}],
                "description": f["explanation"],
                "recommendation": f.get("remediation", ""),
                "affects": [{"ref": bom_ref}],
            })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": app.get("name"),
                          "bom-ref": app.get("app_id")},
            "properties": [{"name": "sbom-risk-scorer:generator", "value": "deterministic-engine"}],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
