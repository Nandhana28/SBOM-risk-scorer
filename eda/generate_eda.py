"""
SBOM Risk Scorer — Exhaustive EDA report generator.

Reads the 6 Problem-10 data files from ../data and writes a single self-contained
interactive HTML report (eda_report.html) covering:
  0. Dataset summary
  1. Data quality & referential integrity
  2. Applications
  3. SBOM dependencies
  4. Vulnerability database
  5. License rules
  6. Transitive dependency graph
  7. Ground-truth labels (the target)
  8. Reverse-engineering the labelling rules (validated vs ground truth)  <-- the money section
  9. Engine blueprint & expected score ceiling

Run:  venv/Scripts/python.exe eda/generate_eda.py
"""
import json
import os
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.offline import get_plotlyjs

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
OUT = os.path.join(HERE, "eda_report.html")

PALETTE = ["#4C6EF5", "#F03E3E", "#F59F00", "#37B24D", "#7048E8", "#1098AD",
           "#E64980", "#495057", "#0CA678", "#F76707"]
SEV_COLORS = {"CRITICAL": "#C92A2A", "HIGH": "#F03E3E", "MEDIUM": "#F59F00",
              "LOW": "#94D82D", "NONE": "#CED4DA"}


# ------------------------------------------------------------------ loaders
def read_csv_safe(path):
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return pd.read_csv(path, encoding=enc)
        except UnicodeDecodeError:
            continue
    return pd.read_csv(path, encoding="latin-1", errors="replace")


def load():
    apps = pd.DataFrame(json.load(open(os.path.join(DATA, "applications.json"))))
    dep = read_csv_safe(os.path.join(DATA, "sbom_dependencies.csv"))
    vulns = pd.DataFrame(json.load(open(os.path.join(DATA, "vulnerability_db.json"))))
    lic = pd.DataFrame(json.load(open(os.path.join(DATA, "license_rules.json"))))
    trans = pd.DataFrame(json.load(open(os.path.join(DATA, "transitive_dependencies.json"))))
    labels = read_csv_safe(os.path.join(DATA, "dependency_labels.csv"))
    return apps, dep, vulns, lic, trans, labels


# ------------------------------------------------------------------ html helpers
_sections = []   # (id, title) for the nav
_blocks = []     # html chunks


def section(sid, title, subtitle=""):
    _sections.append((sid, title))
    sub = f'<p class="sub">{subtitle}</p>' if subtitle else ""
    _blocks.append(f'<section id="{sid}"><h2>{title}</h2>{sub}')


def endsection():
    _blocks.append("</section>")


def note(html):
    _blocks.append(f'<div class="note">{html}</div>')


def cards(pairs):
    items = "".join(
        f'<div class="card"><div class="cval">{v}</div><div class="clab">{k}</div></div>'
        for k, v in pairs)
    _blocks.append(f'<div class="cards">{items}</div>')


def fig(f, height=380):
    f.update_layout(margin=dict(l=40, r=20, t=40, b=40), height=height,
                    paper_bgcolor="white", plot_bgcolor="#F8F9FA",
                    font=dict(family="Inter, system-ui, sans-serif", size=12))
    _blocks.append('<div class="chart">' +
                   f.to_html(full_html=False, include_plotlyjs=False,
                             config={"displayModeBar": False}) + "</div>")


def table(df, cls=""):
    _blocks.append(f'<div class="tbl {cls}">' + df.to_html(index=False, border=0,
                   classes="dt", escape=False) + "</div>")


def h3(t):
    _blocks.append(f"<h3>{t}</h3>")


def para(t):
    _blocks.append(f"<p>{t}</p>")


# ------------------------------------------------------------------ analysis
def main():
    apps, dep, vulns, lic, trans, labels = load()

    # ---- derived structures -------------------------------------------------
    # vulnerability index: (library, version) -> list of cve dicts
    vindex = {}
    for _, v in vulns.iterrows():
        for ver in v["affected_versions"]:
            vindex.setdefault((v["library"], str(ver)), []).append(v)

    lic_by_spdx = {r["spdx"]: r for _, r in lic.iterrows()}
    lic_by_name = {r["license"]: r for _, r in lic.iterrows()}
    app_by_id = {r["app_id"]: r for _, r in apps.iterrows()}

    def lic_row(name):
        r = lic_by_spdx.get(name)
        if r is None:
            r = lic_by_name.get(name)
        return r

    # parse per-dep transitive children from the sbom column
    def children(row):
        s = row.get("transitive_deps")
        if not isinstance(s, str) or not s.strip():
            return []
        out = []
        for tok in s.split(";"):
            tok = tok.strip()
            if ":" in tok:
                libv = tok.rsplit(":", 1)
                out.append((libv[0], libv[1]))
        return out

    dep["_children"] = dep.apply(children, axis=1)

    # merge labels onto deps for cross analysis
    m = dep.merge(labels[["dep_id", "is_risky", "risk_type", "severity", "explanation"]],
                  on="dep_id", how="left")
    m = m.merge(apps[["app_id", "criticality", "license_model", "deployment", "name"]],
                left_on="application_id", right_on="app_id", how="left")
    m["_lu"] = pd.to_datetime(m["last_updated"], errors="coerce")

    # ===================================================================== 0
    section("summary", "0 · Dataset at a glance",
            "Six files, ten applications, 500 dependencies, 200 CVEs.")
    n_risky = int((labels["is_risky"].astype(str).str.lower() == "true").sum()) \
        if labels["is_risky"].dtype == object else int(labels["is_risky"].sum())
    cards([
        ("Applications", len(apps)),
        ("Dependencies", len(dep)),
        ("CVEs", len(vulns)),
        ("License rules", len(lic)),
        ("Transitive edges", len(trans)),
        ("Risky (ground truth)", f"{n_risky} / {len(labels)}"),
    ])
    note("<b>Encoding gotcha:</b> <code>dependency_labels.csv</code> contains "
         "Windows-1252 bytes (em-dashes in explanations). Read with an encoding "
         "fallback (utf-8 → cp1252) or the loader crashes. Your engine's loader "
         "must handle this.")
    endsection()

    # ===================================================================== 1
    section("quality", "1 · Data quality & referential integrity",
            "Can the files be trusted and joined cleanly?")
    checks = []
    checks.append(("dep_id unique in SBOM", dep["dep_id"].is_unique))
    checks.append(("dep_id unique in labels", labels["dep_id"].is_unique))
    checks.append(("labels ↔ SBOM 1:1 on dep_id",
                   set(dep["dep_id"]) == set(labels["dep_id"])))
    checks.append(("all SBOM application_id ∈ applications",
                   set(dep["application_id"]).issubset(set(apps["app_id"]))))
    checks.append(("all transitive application_id ∈ applications",
                   set(trans["application_id"]).issubset(set(apps["app_id"]))))
    miss = m["risk_type"].isna().sum()
    checks.append(("every SBOM dep has a label", miss == 0))
    qc = pd.DataFrame({"Check": [c[0] for c in checks],
                       "Result": ["✅ PASS" if c[1] else "❌ FAIL" for c in checks]})
    table(qc)

    # missing values
    mv = pd.concat([
        dep.isna().sum().rename("SBOM missing"),
    ], axis=1).reset_index().rename(columns={"index": "column"})
    mv = mv[mv["SBOM missing"] > 0]
    if len(mv):
        h3("Columns with missing values (SBOM)")
        note("Empty <code>transitive_deps</code> just means the dependency has no "
             "children — not a data error.")
        table(mv)
    endsection()

    # ===================================================================== 2
    section("apps", "2 · Applications (10)",
            "The assessment units. Criticality & license_model drive risk weighting.")
    table(apps)
    for col in ["language", "criticality", "license_model", "department", "deployment"]:
        vc = apps[col].value_counts()
        f = go.Figure(go.Bar(x=vc.index.tolist(), y=vc.values.tolist(),
                             marker_color=PALETTE[:len(vc)]))
        f.update_layout(title=f"Applications by {col}")
        fig(f, height=300)
    dpa = dep["application_name"].value_counts().sort_values()
    f = go.Figure(go.Bar(x=dpa.values.tolist(), y=dpa.index.tolist(), orientation="h",
                         marker_color="#4C6EF5"))
    f.update_layout(title="Dependencies per application")
    fig(f)
    endsection()

    # ===================================================================== 3
    section("sbom", "3 · SBOM dependencies (500)",
            "The core inventory: what each app depends on.")
    dt = dep["dependency_type"].value_counts()
    f = px.pie(values=dt.values, names=dt.index, title="Direct vs transitive",
               color_discrete_sequence=PALETTE, hole=0.45)
    fig(f, height=320)

    # licenses coloured by their risk level
    lc = dep["license"].value_counts()
    risk_of = {name: (lic_row(name)["risk_level"] if lic_row(name) is not None else "UNKNOWN")
               for name in lc.index}
    f = go.Figure(go.Bar(
        x=lc.index.tolist(), y=lc.values.tolist(),
        marker_color=[SEV_COLORS.get(risk_of[n], "#868E96") for n in lc.index],
        text=[risk_of[n] for n in lc.index]))
    f.update_layout(title="License distribution (bar colour = license risk level)")
    fig(f)

    # staleness timeline
    dep["_lu"] = pd.to_datetime(dep["last_updated"], errors="coerce")
    tl = dep["_lu"].dt.to_period("Q").astype(str).value_counts().sort_index()
    f = go.Figure(go.Bar(x=tl.index.tolist(), y=tl.values.tolist(), marker_color="#1098AD"))
    f.update_layout(title="last_updated by quarter (left = older = maintenance risk)")
    fig(f)

    # children per dep
    dep["_nchild"] = dep["_children"].apply(len)
    nc = dep["_nchild"].value_counts().sort_index()
    f = go.Figure(go.Bar(x=nc.index.astype(str).tolist(), y=nc.values.tolist(),
                         marker_color="#7048E8"))
    f.update_layout(title="Number of transitive children per dependency",
                    xaxis_title="# children", yaxis_title="# deps")
    fig(f, height=300)

    top_lib = dep["library"].value_counts().head(15)
    f = go.Figure(go.Bar(x=top_lib.values.tolist(), y=top_lib.index.tolist(),
                         orientation="h", marker_color="#495057"))
    f.update_layout(title="Top 15 most-used libraries")
    fig(f, height=420)
    endsection()

    # ===================================================================== 4
    section("vulns", "4 · Vulnerability database (200 CVEs)",
            "Keyed by library + affected version. This is a lookup, not a search.")
    sv = vulns["severity"].value_counts()
    f = go.Figure(go.Bar(x=sv.index.tolist(), y=sv.values.tolist(),
                         marker_color=[SEV_COLORS.get(s, "#868E96") for s in sv.index]))
    f.update_layout(title="CVE severity distribution")
    fig(f, height=300)

    f = px.histogram(vulns, x="cvss_score", nbins=20, title="CVSS score distribution",
                     color_discrete_sequence=["#F03E3E"])
    fig(f, height=300)

    pa = vulns["patch_available"].value_counts()
    f = px.pie(values=pa.values, names=[str(x) for x in pa.index],
               title="Patch available?", hole=0.45,
               color_discrete_sequence=["#37B24D", "#F03E3E"])
    fig(f, height=300)
    no_fix = vulns["fixed_version"].isna().sum()
    note(f"<b>{no_fix} CVEs have no fix</b> (fixed_version = null). These are "
         "un-remediable today → should score higher on actionable risk than a "
         "patchable CVE of equal CVSS.")

    ex = vulns["exploitability"].value_counts()
    f = go.Figure(go.Bar(x=ex.index.tolist(), y=ex.values.tolist(), marker_color="#E64980"))
    f.update_layout(title="Exploitability")
    fig(f, height=300)

    vulns["_pub"] = pd.to_datetime(vulns["published_date"], errors="coerce")
    yr = vulns["_pub"].dt.year.value_counts().sort_index()
    f = go.Figure(go.Bar(x=yr.index.astype(str).tolist(), y=yr.values.tolist(),
                         marker_color="#0CA678"))
    f.update_layout(title="CVEs by publication year")
    fig(f, height=300)

    topv = vulns["library"].value_counts().head(15)
    f = go.Figure(go.Bar(x=topv.values.tolist(), y=topv.index.tolist(), orientation="h",
                         marker_color="#F76707"))
    f.update_layout(title="Libraries with most CVEs")
    fig(f, height=420)
    endsection()

    # ===================================================================== 5
    section("lic", "5 · License rules (15)",
            "The compatibility matrix. GPL/AGPL are viral & proprietary-incompatible.")
    table(lic)
    rl = lic["risk_level"].value_counts()
    f = go.Figure(go.Bar(x=rl.index.tolist(), y=rl.values.tolist(),
                         marker_color=[SEV_COLORS.get(s, "#868E96") for s in rl.index]))
    f.update_layout(title="License risk levels")
    fig(f, height=300)
    endsection()

    # ===================================================================== 6
    section("graph", "6 · Transitive dependency graph (372 edges)",
            "Parent → child edges. This is what makes transitive risk detectable.")
    cards([
        ("Edges", len(trans)),
        ("Unique parents", trans["parent_library"].nunique()),
        ("Unique children", trans["child_library"].nunique()),
        ("Apps with edges", trans["application_id"].nunique()),
    ])
    fan = trans.groupby("parent_library").size().sort_values(ascending=False).head(15)
    f = go.Figure(go.Bar(x=fan.values.tolist(), y=fan.index.tolist(), orientation="h",
                         marker_color="#7048E8"))
    f.update_layout(title="Top parent libraries by number of children (fan-out)")
    fig(f, height=420)
    epa = trans["application_id"].value_counts().sort_index()
    f = go.Figure(go.Bar(x=epa.index.tolist(), y=epa.values.tolist(), marker_color="#1098AD"))
    f.update_layout(title="Transitive edges per application")
    fig(f, height=300)
    endsection()

    # ===================================================================== 7
    section("labels", "7 · Ground-truth labels (500) — the target",
            "What your engine must reproduce. Everything here is the answer key.")
    isr = labels["is_risky"].astype(str).str.lower().value_counts()
    f = px.pie(values=isr.values, names=isr.index, title="is_risky", hole=0.45,
               color_discrete_sequence=["#F03E3E", "#37B24D"])
    fig(f, height=300)

    rt = labels["risk_type"].value_counts()
    f = go.Figure(go.Bar(x=rt.values.tolist(), y=rt.index.tolist(), orientation="h",
                         marker_color="#4C6EF5", text=rt.values.tolist()))
    f.update_layout(title="risk_type distribution")
    fig(f, height=340)

    sev = labels["severity"].value_counts()
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    sev = sev.reindex([s for s in order if s in sev.index])
    f = go.Figure(go.Bar(x=sev.index.tolist(), y=sev.values.tolist(),
                         marker_color=[SEV_COLORS.get(s, "#868E96") for s in sev.index]))
    f.update_layout(title="severity distribution")
    fig(f, height=300)

    # risk_type per application (stacked)
    ct = pd.crosstab(m["name"], m["risk_type"])
    f = go.Figure()
    for i, rtn in enumerate(ct.columns):
        f.add_bar(name=rtn, x=ct.index.tolist(), y=ct[rtn].tolist(),
                  marker_color=PALETTE[i % len(PALETTE)])
    f.update_layout(barmode="stack", title="risk_type by application")
    fig(f, height=400)

    # risk rate by criticality
    rr = m.assign(risky=m["is_risky"].astype(str).str.lower().eq("true")) \
          .groupby("criticality")["risky"].mean().reindex(
              ["CRITICAL", "HIGH", "MEDIUM", "LOW"]).dropna()
    f = go.Figure(go.Bar(x=rr.index.tolist(), y=(rr.values * 100).round(1).tolist(),
                         marker_color="#F59F00"))
    f.update_layout(title="Risky-dependency rate (%) by application criticality")
    fig(f, height=300)

    # risk rate by dependency_type
    rrt = m.assign(risky=m["is_risky"].astype(str).str.lower().eq("true")) \
           .groupby("dependency_type")["risky"].mean() * 100
    f = go.Figure(go.Bar(x=rrt.index.tolist(), y=rrt.round(1).values.tolist(),
                         marker_color="#7048E8"))
    f.update_layout(title="Risky rate (%) by dependency type")
    fig(f, height=300)
    endsection()

    # ===================================================================== 8
    section("rules", "8 · Reverse-engineering the labelling rules ⭐",
            "The single most valuable section: what actually drives the labels, "
            "proven against ground truth.")

    import re as _re

    def _vt(v):
        p = _re.findall(r"\d+", str(v))
        return tuple(int(x) for x in p[:4]) if p else (0,)

    # vuln DB grouped by library → list of (lo, hi, fixed_version)
    vby = {}
    for _, v in vulns.iterrows():
        av = v["affected_versions"]
        lo, hi = _vt(av[0]), _vt(av[1])
        if lo > hi:
            lo, hi = hi, lo
        fx = v["fixed_version"]
        fx = None if (fx is None or (isinstance(fx, float))) else fx
        vby.setdefault(v["library"], []).append((lo, hi, fx))

    def match_exact(lib, ver):
        return (lib, str(ver)) in vindex

    def match_range(lib, ver):
        if lib not in vby:
            return False
        t = _vt(ver)
        return any(lo <= t <= hi for lo, hi, _ in vby[lib])

    def match_name(lib, ver):
        return lib in vby

    def match_fix(lib, ver):
        if lib not in vby:
            return False
        t = _vt(ver)
        return any(fx is None or t < _vt(fx) for _, _, fx in vby[lib])

    m["true_vuln"] = m["risk_type"].isin(
        ["VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"])

    h3("8.1 · How should a dependency be matched to a CVE? (the key question)")
    note("Intuition says match <code>library + version</code>. <b>The data says "
         "otherwise.</b> Below, each strategy is scored against the true vulnerable "
         "dependencies. Exact and range matching fail badly — the "
         "<code>affected_versions</code> ranges in this dataset are essentially "
         "noise. Matching on <b>library name alone</b> recovers 100% of vulnerable "
         "dependencies.")
    strat_rows = []
    for nm, fn in [("exact (lib+version)", match_exact),
                   ("range (semver in [lo,hi])", match_range),
                   ("fixed-ver (no fix or v<fix)", match_fix),
                   ("name-only (lib in CVE DB)", match_name)]:
        fires = m.apply(lambda r: fn(r["library"], r["version"]), axis=1)
        tp = int((fires & m["true_vuln"]).sum())
        cov = int(m["true_vuln"].sum())
        strat_rows.append(dict(Strategy=nm, Fires=int(fires.sum()), Matched=tp,
                               **{"Recall%": round(tp / cov * 100, 1),
                                  "Precision%": round(tp / fires.sum() * 100, 1)
                                  if fires.sum() else 0}))
    table(pd.DataFrame(strat_rows))

    # Build the working rule columns (name-based vuln, split by dependency_type)
    m["_vuln"] = m.apply(lambda r: match_name(r["library"], r["version"]), axis=1)

    def lic_conflict(r):
        lr = lic_row(r["license"])
        if lr is None:
            return False
        bad = bool(lr["viral"]) or (not bool(lr["compatible_with_proprietary"]))
        return bad and str(r["license_model"]) == "proprietary"
    m["_licconf"] = m.apply(lic_conflict, axis=1)
    m["_licunk"] = m["license"].astype(str).str.upper().eq("UNKNOWN")
    cutoff_hi = m[m["risk_type"] == "UNMAINTAINED"]["_lu"].max()
    m["_unmaint"] = m["_lu"] <= cutoff_hi

    h3("8.2 · Each non-vulnerability rule vs its label")
    def sc_row(col, target):
        fires = m[col]
        tp = int((fires & (m["risk_type"] == target)).sum())
        cov = int((m["risk_type"] == target).sum())
        return dict(Rule=target, Fires=int(fires.sum()), Labelled=cov, Matched=tp,
                    **{"Recall%": round(tp / cov * 100, 1) if cov else 0,
                       "Precision%": round(tp / fires.sum() * 100, 1)
                       if fires.sum() else 0})
    table(pd.DataFrame([
        sc_row("_vuln", "VULNERABLE_DEPENDENCY"),
        sc_row("_vuln", "TRANSITIVE_VULNERABILITY"),
        sc_row("_licconf", "LICENSE_CONFLICT"),
        sc_row("_licunk", "LICENSE_UNKNOWN"),
        sc_row("_unmaint", "UNMAINTAINED"),
    ]))
    note(f"<b>UNMAINTAINED cutoff discovered:</b> newest <code>last_updated</code> "
         f"still labelled unmaintained ≈ <b>{cutoff_hi.date() if pd.notna(cutoff_hi) else 'n/a'}</b> "
         "(the 2-years-before rule). Every rule reaches 100% recall — the conditions "
         "are <i>necessary</i> for risk — but precision is low, which sets up the "
         "real problem below.")

    h3("8.3 · The whole game is precision, not recall")
    anyc = m["_vuln"] | m["_licconf"] | m["_licunk"] | m["_unmaint"]
    y_true = m["is_risky"].astype(str).str.lower().eq("true")
    tp = int((anyc & y_true).sum())
    fp = int((anyc & ~y_true).sum())
    fn = int((~anyc & y_true).sum())
    tn = int((~anyc & ~y_true).sum())
    prec = tp / (tp + fp) * 100 if (tp + fp) else 0
    rec = tp / (tp + fn) * 100 if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    cards([
        ("Precision", f"{prec:.1f}%"),
        ("Recall", f"{rec:.1f}%"),
        ("F1", f"{f1:.1f}%"),
        ("Target", "P>75 R>70"),
    ])
    note(f"<b>Flagging every dependency that meets any condition gives R={rec:.0f}% "
         f"(zero false negatives — every risky dep meets a condition) but only "
         f"P={prec:.0f}%.</b> {fp} clean dependencies also meet a condition. "
         "Recall is free; the target you can miss is <b>precision</b>. Winning the "
         "hackathon = finding what separates those "
         f"{fp} clean-but-flagged deps from the {tp} truly risky ones.")
    cm = pd.DataFrame({"": ["Predicted risky", "Predicted clean"],
                       "Actually risky": [tp, fn],
                       "Actually clean": [fp, tn]})
    table(cm)

    h3("8.4 · The precision battleground — deps that meet a condition but are labelled clean")
    note("These are your false positives to hunt. If you find a signal that "
         "separates them, precision climbs above target. If none exists (injected "
         "noise), the honest move is to tune the risk-score threshold and document "
         "the trade-off.")
    battle = m[anyc & ~y_true][
        ["dep_id", "library", "version", "license", "dependency_type",
         "last_updated", "explanation"]].head(25)
    table(battle, cls="small")
    endsection()

    # ===================================================================== 9
    section("blueprint", "9 · Engine blueprint & takeaways",
            "What the data proves about how to build the scorer.")
    _blocks.append("""
    <ol class="takeaways">
      <li><b>Match CVEs by library NAME, not version.</b> The
          <code>affected_versions</code> ranges are noise (range matching = ~21%
          recall). Library-name presence in the CVE DB = 100% recall. This is the
          most counter-intuitive and most important finding.</li>
      <li><b>risk_type is decided by <code>dependency_type</code>.</b> A vulnerable
          library on a <code>direct</code> dep → VULNERABLE_DEPENDENCY; on a
          <code>transitive</code> dep → TRANSITIVE_VULNERABILITY. Same detection,
          different label.</li>
      <li><b>Recall is free; precision is the battle.</b> Every risky dep meets at
          least one condition (recall→100%), but ~105 clean deps also meet one. A
          naïve union scores P≈69% / R=100% / F1≈82% — recall clears the bar,
          precision (target &gt;75%) does not. Section 8.4 is your FP hunting list.</li>
      <li><b>Levers to lift precision:</b> use the fixed-version test (no fix or
          v&lt;fix) to drop patched deps; treat UNMAINTAINED/UNKNOWN as lower
          severity so a risk-score threshold can suppress weak signals; tune the
          threshold to trade a little recall for precision.</li>
      <li><b>License conflict only counts in <code>proprietary</code> apps</b>, and
          the UNMAINTAINED cutoff is ~2 years before the dataset date.</li>
      <li><b>Loader must handle cp1252</b> (labels file) — see section 0.</li>
    </ol>
    """)
    endsection()

    render()


# ------------------------------------------------------------------ render
def render():
    nav = "".join(f'<a href="#{sid}">{title}</a>' for sid, title in _sections)
    plotly_js = get_plotlyjs()
    now = "generated locally"  # avoid Date.now-style nondeterminism concerns
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SBOM Risk Scorer — EDA</title>
<script>{plotly_js}</script>
<style>
 :root{{--bg:#F1F3F5;--fg:#212529;--mut:#868E96;--acc:#4C6EF5;--card:#fff;--line:#DEE2E6}}
 *{{box-sizing:border-box}} body{{margin:0;font-family:Inter,system-ui,Segoe UI,sans-serif;
   background:var(--bg);color:var(--fg);line-height:1.5}}
 header{{background:linear-gradient(135deg,#1c2b5e,#4C6EF5);color:#fff;padding:34px 40px}}
 header h1{{margin:0 0 6px;font-size:26px}} header p{{margin:0;opacity:.9}}
 nav{{position:sticky;top:0;background:#fff;border-bottom:1px solid var(--line);
   padding:10px 40px;display:flex;flex-wrap:wrap;gap:14px;z-index:50;font-size:13px}}
 nav a{{color:var(--acc);text-decoration:none;white-space:nowrap}}
 nav a:hover{{text-decoration:underline}}
 main{{max-width:1100px;margin:0 auto;padding:24px 40px 80px}}
 section{{background:var(--card);border:1px solid var(--line);border-radius:12px;
   padding:22px 26px;margin:22px 0}}
 h2{{margin:0 0 4px;font-size:20px}} h3{{margin:22px 0 8px;font-size:15px;color:#343A40}}
 .sub{{color:var(--mut);margin:0 0 10px;font-size:13px}}
 .cards{{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0}}
 .card{{flex:1 1 120px;background:#F8F9FA;border:1px solid var(--line);border-radius:10px;
   padding:14px;text-align:center}}
 .cval{{font-size:22px;font-weight:700;color:var(--acc)}} .clab{{font-size:12px;color:var(--mut)}}
 .chart{{margin:14px 0;border:1px solid var(--line);border-radius:10px;overflow:hidden}}
 .note{{background:#FFF9DB;border-left:4px solid #F59F00;padding:10px 14px;border-radius:6px;
   margin:12px 0;font-size:13px}}
 .tbl{{overflow-x:auto;margin:10px 0}} table.dt{{border-collapse:collapse;width:100%;font-size:13px}}
 table.dt th{{background:#343A40;color:#fff;text-align:left;padding:7px 9px;position:sticky;top:0}}
 table.dt td{{border-bottom:1px solid var(--line);padding:6px 9px;vertical-align:top}}
 table.dt tr:nth-child(even){{background:#F8F9FA}}
 .small table.dt{{font-size:11px}} .takeaways li{{margin:8px 0}}
 code{{background:#E9ECEF;padding:1px 5px;border-radius:4px;font-size:12px}}
 footer{{text-align:center;color:var(--mut);font-size:12px;padding:30px}}
</style></head><body>
<header><h1>SBOM Risk Scorer — Exploratory Data Analysis</h1>
<p>Problem 10 · Software Supply Chain Risk · every angle of the dataset, {now}</p></header>
<nav>{nav}</nav><main>{''.join(_blocks)}</main>
<footer>Generated by eda/generate_eda.py — re-run to refresh.</footer>
</body></html>"""
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(html)
    print("wrote", OUT, f"({os.path.getsize(OUT)//1024} KB)")


if __name__ == "__main__":
    main()
