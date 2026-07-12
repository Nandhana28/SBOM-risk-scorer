"""SBOM Supply-Chain Risk Scorer — web application.

Thin Flask layer over the sbom package. Every page is a view onto the deterministic
engine's output; the routes hold no risk logic themselves. Scan (which SBOM) and
policy (risk appetite) are carried as query parameters so any view can be shared as a
URL that reproduces exactly what was seen.
"""
import csv
import io
import json
from datetime import datetime

from flask import (Flask, render_template, abort, jsonify, request, redirect,
                   url_for, send_file, flash, Response)
from markupsafe import Markup

from sbom import config, db, engine, metrics
from sbom.ingest import ingest_upload, IngestError
from sbom.cyclonedx import to_cyclonedx

app = Flask(__name__)
app.secret_key = "sbom-risk-scorer-local"
db.init_db()

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

# --- inline SVG icon set (self-contained; stroke = currentColor) -------------
_ICON_PATHS = {
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "shield-check": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    "grid": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>',
    "box": '<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/>',
    "package": '<path d="M16.5 9.4 7.5 4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.27 6.96 12 12.01l8.73-5.05"/><path d="M12 22.08V12"/>',
    "network": '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>',
    "trending-up": '<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/>',
    "zap": '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    "book": '<path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/>',
    "upload": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
    "file": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
    "alert": '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "layers": '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
    "check": '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    "chevron": '<polyline points="9 18 15 12 9 6"/>',
    "refresh": '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    "gauge": '<path d="M12 14 8 10"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/><circle cx="12" cy="14" r="1.5"/>',
}


def icon(name, cls=""):
    inner = _ICON_PATHS.get(name, "")
    return Markup(f'<svg class="ic {cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                  f'stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">{inner}</svg>')


app.jinja_env.globals["icon"] = icon

PAGE_TITLES = {
    "dashboard": "Dashboard", "app_detail": "Application detail", "inventory": "Inventory",
    "graph": "Dependency Graph", "trends": "Trends", "simulate": "Blast Radius",
    "validation": "Validation", "methodology": "Methodology", "upload": "Upload SBOM",
}


# --- request context helpers ------------------------------------------------
def current_scan():
    scan = request.args.get("scan", db.BASELINE)
    known = {s["scan_id"] for s in db.list_scans()}
    return scan if scan in known else db.BASELINE


def current_policy():
    pol = request.args.get("policy", config.DEFAULT_POLICY)
    return pol if pol in config.POLICIES else config.DEFAULT_POLICY


@app.context_processor
def inject_nav():
    """Values every template needs for the menu and the scan/policy selectors."""
    return {
        "nav_scan": current_scan(),
        "nav_policy": current_policy(),
        "all_scans": db.list_scans(),
        "all_policies": config.POLICIES,
        "severity_order": SEVERITY_ORDER,
        "cfg": config,
        "page_title": PAGE_TITLES.get(request.endpoint, ""),
    }


def _findings():
    return engine.analyze(current_scan(), current_policy())


def _app_index(scan):
    return {a["app_id"]: a for a in db.get_applications(scan)}


# --- pages ------------------------------------------------------------------
@app.route("/")
def dashboard():
    scan, policy = current_scan(), current_policy()
    findings = _findings()
    summaries = engine.application_summaries(findings, scan)
    flagged = [f for f in findings if f["is_risky"]]
    risk_breakdown = {}
    for f in flagged:
        risk_breakdown[f["risk_type"]] = risk_breakdown.get(f["risk_type"], 0) + 1
    sev_breakdown = {}
    for f in flagged:
        sev_breakdown[f["severity"]] = sev_breakdown.get(f["severity"], 0) + 1
    critical = sorted([f for f in flagged if f["severity"] in ("CRITICAL", "HIGH")],
                      key=lambda f: (SEVERITY_ORDER[f["severity"]], f["score"]), reverse=True)[:12]
    critical_count = sum(1 for f in flagged if f["severity"] == "CRITICAL")
    assurance = metrics.evaluate_policy(policy) if scan == db.BASELINE else None

    return render_template(
        "dashboard.html", summaries=summaries, total=len(findings),
        flagged=len(flagged), clean=len(findings) - len(flagged),
        risk_breakdown=risk_breakdown, sev_breakdown=sev_breakdown,
        critical=critical, critical_count=critical_count, assurance=assurance,
        scanned_at=datetime.now().strftime("%Y-%m-%d %H:%M"))


@app.route("/app/<app_id>")
def app_detail(app_id):
    scan = current_scan()
    findings = _findings()
    app_row = _app_index(scan).get(app_id)
    if not app_row:
        abort(404)
    group = [f for f in findings if f["application_id"] == app_id]
    risky = sorted([f for f in group if f["is_risky"]], key=lambda f: f["score"], reverse=True)
    summary = next((s for s in engine.application_summaries(findings, scan)
                    if s["application_id"] == app_id), None)
    return render_template("detail.html", app=app_row, summary=summary,
                           findings=risky, clean_count=len(group) - len(risky),
                           total=len(group))


@app.route("/inventory")
def inventory():
    findings = _findings()
    risky = [f for f in findings if f["is_risky"]]
    grouped = {}
    for f in risky:
        g = grouped.setdefault(f["library"], {
            "library": f["library"], "apps": set(), "versions": set(),
            "risk_types": set(), "worst_severity": "NONE", "total_score": 0.0})
        g["apps"].add(f["application_name"])
        g["versions"].add(f["version"])
        g["risk_types"].add(f["risk_type"])
        g["total_score"] += f["score"]
        if SEVERITY_ORDER[f["severity"]] > SEVERITY_ORDER[g["worst_severity"]]:
            g["worst_severity"] = f["severity"]
    rows = []
    for g in grouped.values():
        g["app_count"] = len(g["apps"])
        g["apps"] = sorted(g["apps"])
        g["versions"] = sorted(g["versions"])
        g["risk_types"] = sorted(g["risk_types"])
        g["total_score"] = round(g["total_score"], 1)
        rows.append(g)
    shared = sorted([r for r in rows if r["app_count"] > 1],
                    key=lambda r: (r["app_count"], SEVERITY_ORDER[r["worst_severity"]]), reverse=True)
    single = sorted([r for r in rows if r["app_count"] == 1],
                    key=lambda r: SEVERITY_ORDER[r["worst_severity"]], reverse=True)
    return render_template("inventory.html", shared=shared, single=single,
                           unique_libs=len(rows))


@app.route("/graph")
def graph():
    scan = current_scan()
    findings = _findings()
    apps = db.get_applications(scan)
    if not apps:
        abort(404)
    app_id = request.args.get("app", apps[0]["app_id"])
    app_row = next((a for a in apps if a["app_id"] == app_id), apps[0])
    app_id = app_row["app_id"]

    color = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#d4a017",
             "LOW": "#7f8c8d", "NONE": "#27ae60"}
    group = [f for f in findings if f["application_id"] == app_id]
    node_id = {f["library"]: f"{f['library']}@{f['version']}" for f in group}
    nodes = [{"id": app_id, "label": app_row["name"], "shape": "box",
              "color": "#2c3e70", "font": {"color": "#fff", "size": 18}}]
    edges = []
    for f in group:
        nid = node_id[f["library"]]
        nodes.append({"id": nid, "label": f["library"], "sev": f["severity"],
                      "color": color.get(f["severity"], "#7f8c8d"),
                      "title": f"{f['library']}:{f['version']} — {f['risk_type']} ({f['severity']})"})
        parent = f["parents"][0][0] if f["parents"] else None
        pnid = node_id.get(parent) if parent else None
        edges.append({"from": pnid or app_id, "to": nid})
    return render_template("graph.html", apps=apps, current_app_id=app_id,
                           nodes_json=json.dumps(nodes), edges_json=json.dumps(edges),
                           color=color)


@app.route("/trends")
def trends():
    findings = _findings()
    vulns = {v["cve_id"]: v for v in []}  # placeholder; use published dates from DB
    pub_by_lib = {}
    for v in db.get_vulnerabilities():
        pub_by_lib.setdefault(v["library"], []).append(v["published_date"][:7])
    month_counts = {}
    for f in findings:
        if f["risk_type"] in ("VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"):
            months = pub_by_lib.get(f["library"], [])
            if months:
                m = min(months)
                month_counts[m] = month_counts.get(m, 0) + 1
    months = sorted(month_counts)

    stale_years = {}
    for f in findings:
        if f["risk_type"] == "UNMAINTAINED":
            yr = f["last_updated"][:4]
            stale_years[yr] = stale_years.get(yr, 0) + 1
    years = sorted(stale_years)
    return render_template("trends.html",
                           cve_months=months, cve_counts=[month_counts[m] for m in months],
                           stale_years=years, stale_counts=[stale_years[y] for y in years])


@app.route("/simulate", methods=["GET", "POST"])
def simulate():
    scan = current_scan()
    findings = _findings()
    app_idx = _app_index(scan)
    libraries = sorted({f["library"] for f in findings})
    result = None
    if request.method == "POST":
        target = request.form.get("library")
        affected = [f for f in findings if f["library"] == target]
        by_app = {}
        for f in affected:
            by_app.setdefault(f["application_id"], []).append(f)
        rows, blast = [], 0
        for aid, fs in by_app.items():
            a = app_idx.get(aid, {"name": aid, "criticality": "MEDIUM", "department": "-",
                                  "deployment": "-"})
            weight = config.CRITICALITY_WEIGHT.get(a.get("criticality"), 1.0)
            blast += weight
            rows.append({"name": a.get("name", aid), "criticality": a.get("criticality"),
                         "department": a.get("department"), "deployment": a.get("deployment"),
                         "versions": sorted({f["version"] for f in fs}),
                         "flagged": any(f["is_risky"] for f in fs)})
        result = {"library": target, "app_count": len(rows),
                  "blast_score": round(blast, 1),
                  "affected_apps": sorted(rows, key=lambda r: config.CRITICALITY_WEIGHT.get(
                      r["criticality"], 1.0), reverse=True)}
    return render_template("simulate.html", libraries=libraries, result=result)


@app.route("/validation")
def validation():
    results = metrics.evaluate_all_policies()
    tstats = metrics.transitive_stats()
    if all(v is None for v in results.values()):
        return render_template("validation.html", results=None, tstats=tstats)
    return render_template("validation.html", results=results, tstats=tstats,
                           active=current_policy())


@app.route("/methodology")
def methodology():
    return render_template("methodology.html")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("sbom")
        if not file or not file.filename:
            flash("Choose a file first.", "error")
            return redirect(url_for("upload"))
        try:
            scan_id = ingest_upload(file.filename, file.read())
            engine.clear_cache()
            flash(f"Ingested '{file.filename}' as scan {scan_id}.", "ok")
            return redirect(url_for("dashboard", scan=scan_id, policy=current_policy()))
        except IngestError as e:
            flash(f"Could not ingest file: {e}", "error")
            return redirect(url_for("upload"))
    return render_template("upload.html")


@app.route("/rescan", methods=["POST"])
def rescan():
    engine.clear_cache()
    return redirect(url_for("dashboard", scan=current_scan(), policy=current_policy()))


# --- exports ----------------------------------------------------------------
@app.route("/app/<app_id>/export.json")
def export_cyclonedx(app_id):
    scan = current_scan()
    app_row = _app_index(scan).get(app_id)
    if not app_row:
        abort(404)
    findings = [f for f in _findings() if f["application_id"] == app_id]
    return jsonify(to_cyclonedx(app_row, findings))


@app.route("/export.csv")
def export_csv():
    """Download the current scan+policy findings as a flat CSV (ranked by score)."""
    findings = sorted(_findings(), key=lambda f: f["score"], reverse=True)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["application_id", "application_name", "library", "version", "license",
                "dependency_type", "is_risky", "risk_type", "severity", "score",
                "rule_id", "explanation", "remediation"])
    for f in findings:
        w.writerow([f["application_id"], f["application_name"], f["library"], f["version"],
                    f["license"], f["dependency_type"], f["is_risky"], f["risk_type"],
                    f["severity"], f["score"], f["rule_id"], f["explanation"], f["remediation"]])
    return Response(buf.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": f"attachment; filename=sbom-findings-{current_scan()}-{current_policy()}.csv"})


@app.route("/report.pdf")
def report_pdf():
    from xhtml2pdf import pisa
    scan, policy = current_scan(), current_policy()
    findings = _findings()
    summaries = engine.application_summaries(findings, scan)
    flagged = [f for f in findings if f["is_risky"]]

    risk_breakdown, sev_breakdown = {}, {}
    for f in flagged:
        risk_breakdown[f["risk_type"]] = risk_breakdown.get(f["risk_type"], 0) + 1
        sev_breakdown[f["severity"]] = sev_breakdown.get(f["severity"], 0) + 1

    # Every flagged finding, grouped per application and ranked by score — the full problem list.
    by_app = {}
    for f in flagged:
        by_app.setdefault(f["application_id"], []).append(f)
    sections = []
    for s in summaries:
        rows = sorted(by_app.get(s["application_id"], []),
                      key=lambda f: (SEVERITY_ORDER[f["severity"]], f["score"]), reverse=True)
        sections.append({**s, "rows": rows})

    assurance = metrics.evaluate_policy(policy) if scan == db.BASELINE else None
    sev_ranked = sorted(sev_breakdown.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 0), reverse=True)
    risk_ranked = sorted(risk_breakdown.items(), key=lambda kv: kv[1], reverse=True)

    html = render_template(
        "report.html", scan=scan, sections=sections, summaries=summaries,
        total=len(findings), flagged=len(flagged), clean=len(findings) - len(flagged),
        critical_count=sum(1 for f in flagged if f["severity"] == "CRITICAL"),
        high_count=sum(1 for f in flagged if f["severity"] == "HIGH"),
        risk_ranked=risk_ranked, sev_ranked=sev_ranked, assurance=assurance,
        policy_label=config.POLICIES[policy]["label"],
        policy_blurb=config.POLICIES[policy]["blurb"],
        scanned_at=datetime.now().strftime("%Y-%m-%d %H:%M"))
    buffer = io.BytesIO()
    pisa.CreatePDF(html, dest=buffer)
    buffer.seek(0)
    return send_file(buffer, mimetype="application/pdf", as_attachment=True,
                     download_name=f"sbom-risk-report-{datetime.now().strftime('%Y%m%d-%H%M')}.pdf")


if __name__ == "__main__":
    app.run(debug=True)
