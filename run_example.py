"""
run_example.py  —  blast-radius-iam full pipeline demo
=======================================================
Parses example.tf, builds the reachability graph, detects
misconfigurations, scores them, compares against plain scanner,
proposes fixes, and runs an ablation.

Usage:
    python run_example.py
"""

import sys
import pathlib

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

from blastradius.parser_terraform import parse_terraform_file
from blastradius.graph_builder import build_graph, load_sensitivity_config, get_resource_sensitivity
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings, exposure_score
from blastradius.scoring import score_all_findings, ScoringConfig
from blastradius.ranking import rank_by_blast_radius, rank_by_scanner_severity
from blastradius.fixes import greedy_best_k_fixes
from blastradius.models import ScoredFinding

import networkx as nx

SEP  = "=" * 70
SEP2 = "-" * 70
TF   = pathlib.Path(__file__).resolve().parent / "example.tf"


# ── helpers ───────────────────────────────────────────────────────────────────

def kendall_tau(a, b):
    pos_a = {x: i for i, x in enumerate(a)}
    pos_b = {x: i for i, x in enumerate(b)}
    ids = list(pos_a)
    n   = len(ids)
    mx  = n * (n - 1) // 2
    if mx == 0:
        return 0.0
    inv = sum(
        1 for i in range(n) for j in range(i + 1, n)
        if (pos_a[ids[i]] < pos_a[ids[j]]) != (pos_b[ids[i]] < pos_b[ids[j]])
    )
    return round(inv / mx, 3)


# ── sections ──────────────────────────────────────────────────────────────────

def section(title, subtitle=""):
    print(f"\n{SEP}")
    print(title)
    if subtitle:
        print(subtitle)
    print(SEP)


def print_parsed(principals, resources, sens_cfg):
    section("STEP 1 — Parsed Terraform Config  (example.tf)")

    print(f"\n  Principals parsed: {len(principals)}")
    print(f"  {'Name':<30} {'Kind':<8} {'Trust':<40} {'Statements'}")
    print(f"  {SEP2}")
    for p in principals:
        trust = p.trust[0] if p.trust else "none"
        print(f"  {p.name:<30} {p.kind:<8} {trust:<40} {len(p.statements)} statement(s)")
        for st in p.statements:
            acts = ", ".join(st.actions[:3]) + (" ..." if len(st.actions) > 3 else "")
            res  = ", ".join(st.resources[:1]) + (" ..." if len(st.resources) > 1 else "")
            print(f"    {'':4} [{st.effect}]  actions={acts}")
            print(f"    {'':4}           resources={res}")

    print(f"\n  Resources parsed: {len(resources)}")
    print(f"  {'Name':<30} {'Type':<35} {'Sensitivity'}")
    print(f"  {SEP2}")
    for r in resources:
        sens = get_resource_sensitivity(r["name"], sens_cfg)
        print(f"  {r['name']:<30} {r['type']:<35} {sens}")


def print_graph(G):
    section("STEP 2 — Reachability Graph")

    print(f"\n  Nodes ({len(G.nodes)}):")
    print(f"  {'Name':<35} {'Kind':<12} {'Sensitivity'}")
    print(f"  {SEP2}")
    for node, data in sorted(G.nodes(data=True)):
        print(f"  {node:<35} {data.get('kind','?'):<12} {data.get('sensitivity', '-')}")

    edge_groups = {}
    for u, v, d in G.edges(data=True):
        etype = d.get("etype", "unknown")
        edge_groups.setdefault(etype, []).append((u, v))

    print(f"\n  Edges ({len(G.edges)}):")
    for etype, edges in sorted(edge_groups.items()):
        print(f"\n  [{etype}]  ({len(edges)})")
        for u, v in edges:
            print(f"    {u}  -->  {v}")

    print(f"\n  Live attack paths to crown-jewel resources:")
    crown_jewels = [n for n, d in G.nodes(data=True) if d.get("kind") == "resource"]
    entry_points = [n for n, d in G.nodes(data=True) if d.get("kind") in ("user", "external")]
    found = False
    for entry in entry_points:
        for target in crown_jewels:
            if nx.has_path(G, entry, target):
                path = nx.shortest_path(G, entry, target)
                print(f"    {'  ->  '.join(path)}")
                found = True
    if not found:
        print("    none found")


def print_findings(findings, G):
    section("STEP 3 — Detected Misconfigurations")

    print(f"\n  Total findings: {len(findings)}")
    print(f"  {'ID':<7} {'Rule':<22} {'Location':<28} {'Sev':<8} {'Exposed':<8} {'Exp.Score'}")
    print(f"  {SEP2}")
    for f in findings:
        exp = exposure_score(G, f.location)
        print(f"  {f.id:<7} {f.rule:<22} {f.location:<28} {f.scanner_severity:<8} {str(f.exposed):<8} {exp:.4f}")
        print(f"         -> {f.detail}")


def print_scores(scored):
    section(
        "STEP 4 — Blast-Radius Scores",
        "Formula: score = exposure_score x (w_sens x delta_sens + w_count x delta_count)"
    )

    print(f"\n  {'ID':<7} {'Rule':<22} {'Location':<28} {'Sev':<8} {'Score':>9}  {'Reach':<10} Exposed")
    print(f"  {SEP2}")
    for sf in rank_by_blast_radius(scored):
        f = sf.finding
        reach = f"{len(sf.reachable)} nodes"
        print(f"  {f.id:<7} {f.rule:<22} {f.location:<28} {f.scanner_severity:<8} {sf.score:>9.4f}  {reach:<10} {sf.exposed}")


def print_comparison(scored, findings):
    section("STEP 5 — Ranking Comparison: Plain Scanner vs Blast-Radius")

    scanner_ranked = rank_by_scanner_severity(findings)
    br_ranked      = rank_by_blast_radius(scored)
    sc_pos         = {f.id: i + 1 for i, f in enumerate(scanner_ranked)}

    print(f"\n  {'Rank':<6} {'Scanner':<36} {'Blast-Radius':<36} {'Delta':>6}  Note")
    print(f"  {SEP2}")
    for i, sf in enumerate(br_ranked, 1):
        f       = sf.finding
        sc_rank = sc_pos[f.id]
        delta   = sc_rank - i
        sc_f    = scanner_ranked[i - 1] if i <= len(scanner_ranked) else None
        sc_str  = f"{sc_f.location[:20]} ({sc_f.scanner_severity})" if sc_f else ""
        br_str  = f"{f.location[:20]} ({sf.score:.2f})"
        note    = f"PROMOTED +{delta}" if delta > 0 else (f"demoted {delta}" if delta < 0 else "")
        print(f"  {i:<6} {sc_str:<36} {br_str:<36} {delta:>+6}  {note}")

    sc_top = scanner_ranked[0]
    br_top = br_ranked[0]
    print(f"\n  Scanner    top-1: {sc_top.location} (severity={sc_top.scanner_severity})")
    print(f"  Blast-rad  top-1: {br_top.finding.location} (score={br_top.score:.4f}, exposed={br_top.exposed})")

    if sc_top.id != br_top.finding.id:
        print(f"\n  *** RANK INVERSION ***")
        print(f"  Scanner picks '{sc_top.location}' — flags it HIGH because Action:*")
        print(f"  Blast-radius picks '{br_top.finding.location}' — it is on the live attack path")
        print(f"  Fixing the scanner's pick does nothing (role is unreachable).")
        print(f"  Fixing blast-radius's pick cuts the entire attack path.")


def print_fixes(G, findings):
    section("STEP 6 — Greedy Top-2 Fixes (Maximum Risk Reduction)")

    cfg     = ScoringConfig()
    results = greedy_best_k_fixes(G, findings, k=2, cfg=cfg)

    print(f"\n  Initial total environment risk: {results['initial_risk']:.4f}")
    print(f"\n  {'Step':<6} {'Action':<22} {'Target':<28} {'Risk Drop':>10}  {'%':>6}  {'Remaining':>10}")
    print(f"  {SEP2}")
    for step in results["steps"]:
        fx = step["fix"]
        print(f"  {step['step']:<6} {fx.action_type:<22} {fx.target_node:<28} "
              f"{step['risk_reduction']:>10.4f}  {step['percent_gain']:>5.1f}%  {step['risk_remaining']:>10.4f}")
        print(f"         {fx.description[:66]}")

    print(f"\n  Final risk: {results['final_risk']:.4f}  "
          f"(reduced by {results['total_percent_reduction']:.1f}%)")


def print_ablation(G, findings):
    section(
        "STEP 7 — Ablation Study",
        "Kendall-tau distance from full model (0=identical, 1=fully reversed)"
    )

    cfg         = ScoringConfig()
    full_scored = score_all_findings(G, findings, cfg)
    full_order  = [sf.finding.id for sf in rank_by_blast_radius(full_scored)]

    variants = {
        "severity_only  (plain scanner, no graph)": [
            ScoredFinding(f, {}, float({"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(f.scanner_severity, 0)), False)
            for f in findings
        ],
        "exposure_only  (reachability, no sensitivity)": [
            ScoredFinding(f, {}, round(exposure_score(G, f.location), 4),
                          exposure_score(G, f.location) > 0)
            for f in findings
        ],
        "no_sensitivity (count + exposure only)": score_all_findings(
            G, findings,
            ScoringConfig(gamma=cfg.gamma, w_count=cfg.w_count,
                          w_sensitivity=0.0, exposed_epsilon=cfg.exposed_epsilon)
        ),
        "no_decay       (gamma=1.0, no path decay)": score_all_findings(
            G, findings,
            ScoringConfig(gamma=1.0, w_count=cfg.w_count,
                          w_sensitivity=cfg.w_sensitivity, exposed_epsilon=cfg.exposed_epsilon)
        ),
    }

    print(f"\n  {'Variant':<48} {'tau':>6}  {'Top-1 = full?':<16}  Meaning")
    print(f"  {SEP2}")
    for name, v_scored in variants.items():
        v_order = [sf.finding.id for sf in rank_by_blast_radius(v_scored)]
        tau     = kendall_tau(full_order, v_order)
        top1    = "YES" if v_order[0] == full_order[0] else "NO"
        meaning = "contributes signal" if tau > 0.01 else "no effect"
        print(f"  {name:<48} {tau:>6.3f}  {top1:<16}  {meaning}")

    print(f"\n  Full model top-1 finding: {full_order[0]}")
    print(f"  tau > 0 means that component changes the ranking.")
    print(f"  tau = 0 means removing it makes no difference.")


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{SEP}")
    print("blast-radius-iam  —  Full Pipeline")
    print(f"Input: {TF.name}")
    print(SEP)

    if not TF.exists():
        print(f"ERROR: {TF} not found.")
        sys.exit(1)

    sens_cfg   = load_sensitivity_config()
    principals, resources = parse_terraform_file(str(TF))
    G          = build_graph(principals, resources, sens_cfg)
    findings   = attach_findings(G, detect_misconfigurations(principals))
    cfg        = ScoringConfig()
    scored     = score_all_findings(G, findings, cfg)

    print_parsed(principals, resources, sens_cfg)
    print_graph(G)
    print_findings(findings, G)
    print_scores(scored)
    print_comparison(scored, findings)
    print_fixes(G, findings)
