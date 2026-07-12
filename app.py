import os
from datetime import datetime
from flask import Flask, render_template, abort, jsonify, request, redirect, url_for, send_file
from detector import analyze, app_summary, load_data
from export import to_cyclonedx
from alternatives import suggest_alternative

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_data():
    apps, deps, vulns, licenses, transitive = load_data()
    df = analyze()
    summary = app_summary(df, apps)
    return apps, df, summary


@app.route("/")
def dashboard():
    apps, df, summary = get_data()

    total = len(df)
    flagged = int(df["is_risky"].sum())
    # All CRITICAL-severity findings, not just CVEs -- a CRITICAL license violation
    # (e.g. GPL-3.0 in a proprietary app) is a genuine business risk too, and the
    # PDF report already includes those; keeping this in sync avoids the dashboard
    # under-reporting relative to its own PDF export.
    critical_findings = df[df["severity"] == "CRITICAL"]

    return render_template(
        "dashboard.html",
        summary=summary,
        total=total,
        flagged=flagged,
        clean=total - flagged,
        critical_alerts=critical_findings.to_dict("records"),
        risk_breakdown=df["risk_type"].value_counts().to_dict(),
        scanned_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/rescan", methods=["POST"])
def rescan():
    # analyze() re-reads every source file from disk on every call -- there is no cache to
    # invalidate. This endpoint exists to make that re-ingestion explicit and demoable:
    # drop updated files into data/ and hit Re-scan to see them reflected immediately.
    return redirect(url_for("dashboard"))


@app.route("/app/<app_id>")
def app_detail(app_id):
    apps, df, summary = get_data()
    app_row = next((a for a in apps if a["app_id"] == app_id), None)
    if not app_row:
        abort(404)
    app_summary_row = next((s for s in summary if s["application_id"] == app_id), None)
    findings = df[(df["application_id"] == app_id) & (df["is_risky"])].sort_values("score", ascending=False).to_dict("records")
    for f in findings:
        if f["risk_type"] in ("LICENSE_CONFLICT", "TRANSITIVE_LICENSE_CONFLICT"):
            f["remediation"] = suggest_alternative(f["library"])
        elif f["risk_type"] in ("VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"):
            f["remediation"] = "Upgrade to the patched version noted above." if "Patched in" in f["explanation"] else "No patch available yet -- isolate or replace this dependency."
        elif f["risk_type"] == "UNMAINTAINED":
            f["remediation"] = "Evaluate an actively maintained replacement, or fork and maintain internally."
        elif f["risk_type"] == "ELEVATED_RISK":
            f["remediation"] = "No single clear issue -- have a security reviewer take a manual look."
        else:
            f["remediation"] = "Confirm the license terms with legal before distribution."
    clean = df[(df["application_id"] == app_id) & (~df["is_risky"])]

    return render_template(
        "detail.html",
        app=app_row,
        app_summary=app_summary_row,
        findings=findings,
        clean_count=len(clean),
    )


@app.route("/inventory")
def inventory():
    apps, df, summary = get_data()
    risky = df[df["is_risky"]]
    # Grouped by library name only, not library+version: every dependency row in this
    # dataset gets a distinct exact version (verified -- 239 risky rows, 239 unique
    # (library, version) pairs), so version-exact grouping never finds overlap across
    # apps even when the same library is a repeated risk source across the org.
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    grouped = (
        risky.groupby("library")
        .agg(
            apps_affected=("application_name", lambda x: sorted(set(x))),
            versions=("version", lambda x: sorted(set(x))),
            risk_types=("risk_type", lambda x: sorted(set(x))),
            worst_severity=("severity", lambda x: max(x, key=lambda s: severity_rank.get(s, 0))),
        )
        .reset_index()
    )
    grouped["app_count"] = grouped["apps_affected"].apply(len)
    shared = grouped[grouped["app_count"] > 1].sort_values(
        ["app_count", "worst_severity"],
        key=lambda col: col.map(severity_rank) if col.name == "worst_severity" else col,
        ascending=[False, False],
    )
    single = grouped[grouped["app_count"] == 1]

    return render_template(
        "inventory.html",
        shared=shared.to_dict("records"),
        total_unique_risky_libs=len(grouped),
        shared_count=len(shared),
        single_count=len(single),
    )


@app.route("/graph")
def graph():
    apps, df, summary = get_data()
    app_id = request.args.get("app", apps[0]["app_id"])
    app_row = next(a for a in apps if a["app_id"] == app_id)

    import json as _json
    transitive = _json.load(open(os.path.join(BASE_DIR, "data", "transitive_dependencies.json")))
    # Keyed on child library name only, not exact version: transitive_dependencies.json's
    # child_version/parent_version fields don't match the actual versions in
    # sbom_dependencies.csv for this dataset (verified: 0/369 exact matches), while
    # (library, application_id) alone matches 100%.
    parent_of = {}
    for t in transitive:
        if t["application_id"] == app_id:
            parent_of[t["child_library"]] = t["parent_library"]

    app_deps = df[df["application_id"] == app_id]
    node_id_by_library = {row["library"]: f"{row['library']}@{row['version']}" for _, row in app_deps.iterrows()}

    color_for = {"CRITICAL": "#a8291e", "HIGH": "#b5701c", "MEDIUM": "#c9a227", "LOW": "#8aa19b", "NONE": "#2f7d4f"}

    nodes = [{"id": app_id, "label": app_row["name"], "shape": "box", "color": "#1f7a72", "font": {"color": "#fff"}}]
    edges = []
    for _, row in app_deps.iterrows():
        node_id = node_id_by_library[row["library"]]
        nodes.append({
            "id": node_id, "label": row["library"],
            "color": color_for.get(row["severity"], "#8aa19b"),
            "title": f"{row['library']}:{row['version']} -- {row['risk_type']}",
        })
        parent_lib = parent_of.get(row["library"])
        parent_node_id = node_id_by_library.get(parent_lib) if parent_lib else None
        if parent_node_id:
            edges.append({"from": parent_node_id, "to": node_id})
        else:
            edges.append({"from": app_id, "to": node_id})

    return render_template("graph.html", apps=apps, current_app_id=app_id,
                            nodes_json=_json.dumps(nodes), edges_json=_json.dumps(edges))


@app.route("/trends")
def trends():
    apps, df, summary = get_data()
    vuln_rows = df[df["risk_type"].isin(["VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"])].copy()

    import json as _json
    vulns = _json.load(open(os.path.join(BASE_DIR, "data", "vulnerability_db.json")))
    cve_date = {}
    for v in vulns:
        for cve_id in [v["cve_id"]]:
            cve_date[(v["library"])] = cve_date.get(v["library"], []) + [v["published_date"][:7]]

    from collections import Counter
    month_counts = Counter()
    for _, row in vuln_rows.iterrows():
        months = cve_date.get(row["library"], [])
        if months:
            month_counts[months[0]] += 1

    months_sorted = sorted(month_counts.keys())

    unmaint = df[df["risk_type"] == "UNMAINTAINED"]
    deps = load_data()[1]
    year_counts = Counter()
    for dep_id in unmaint["dep_id"]:
        row = deps[deps["dep_id"] == dep_id].iloc[0]
        year_counts[row["last_updated"][:4]] += 1
    years_sorted = sorted(year_counts.keys())

    return render_template(
        "trends.html",
        cve_months=months_sorted, cve_counts=[month_counts[m] for m in months_sorted],
        stale_years=years_sorted, stale_counts=[year_counts[y] for y in years_sorted],
    )


@app.route("/simulate", methods=["GET", "POST"])
def simulate():
    apps, df, summary = get_data()
    app_idx = {a["app_id"]: a for a in apps}
    libraries = sorted(df["library"].unique())

    result = None
    if request.method == "POST":
        target_lib = request.form.get("library")
        affected = df[df["library"] == target_lib]
        by_app = affected.groupby("application_id").agg(
            versions=("version", lambda x: sorted(set(x))),
            dep_count=("dep_id", "count"),
        ).reset_index()
        rows = []
        blast_score = 0
        for _, r in by_app.iterrows():
            app = app_idx[r["application_id"]]
            weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(app["criticality"], 1)
            blast_score += weight
            rows.append({
                "name": app["name"], "criticality": app["criticality"],
                "department": app["department"], "versions": r["versions"], "deployment": app["deployment"],
            })
        result = {
            "library": target_lib,
            "affected_apps": sorted(rows, key=lambda x: -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["criticality"], 1)),
            "app_count": len(rows),
            "blast_score": blast_score,
        }

    return render_template("simulate.html", libraries=libraries, result=result)


@app.route("/app/<app_id>/export.json")
def export_cyclonedx(app_id):
    apps, df, summary = get_data()
    app_row = next((a for a in apps if a["app_id"] == app_id), None)
    if not app_row:
        abort(404)
    app_deps = df[df["application_id"] == app_id]
    return jsonify(to_cyclonedx(app_row, app_deps))


@app.route("/report.pdf")
def report_pdf():
    from io import BytesIO
    from xhtml2pdf import pisa
    apps, df, summary = get_data()
    html = render_template(
        "dashboard.html",
        summary=summary,
        total=len(df),
        flagged=int(df["is_risky"].sum()),
        clean=len(df) - int(df["is_risky"].sum()),
        critical_alerts=df[df["severity"] == "CRITICAL"].to_dict("records"),
        risk_breakdown=df["risk_type"].value_counts().to_dict(),
        is_pdf=True,
    )
    buffer = BytesIO()
    pisa.CreatePDF(html, dest=buffer)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"sbom-risk-report-{datetime.now().strftime('%Y%m%d-%H%M')}.pdf",
    )


if __name__ == "__main__":
    app.run(debug=True)
