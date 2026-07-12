import uuid
from datetime import datetime, timezone


def to_cyclonedx(app, findings_df):
    """Build a CycloneDX 1.5-shaped SBOM+vulnerability document for one application."""
    components = []
    vulnerabilities = []

    for _, row in findings_df.iterrows():
        bom_ref = f"{row['library']}@{row['version']}"
        components.append({
            "type": "library",
            "bom-ref": bom_ref,
            "name": row["library"],
            "version": row["version"],
            "purl": f"pkg:generic/{row['library']}@{row['version']}",
        })
        if row["risk_type"] in ("VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"):
            vulnerabilities.append({
                "bom-ref": f"vuln-{bom_ref}",
                "id": row["explanation"].split("has ")[-1].split(" (")[0] if "has " in row["explanation"] else "UNKNOWN",
                "ratings": [{"severity": row["severity"].lower(), "method": "CVSSv3"}],
                "description": row["explanation"],
                "affects": [{"ref": bom_ref}],
            })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": app["name"],
                "bom-ref": app["app_id"],
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
