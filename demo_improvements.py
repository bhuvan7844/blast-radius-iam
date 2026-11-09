"""
blast-radius-iam  —  Demonstration Script
==========================================
Runs entirely on data/synthetic/ which is committed to the repo.
No external datasets required.

Shows three things:
  1. Headline claim: a MEDIUM finding on an exposed role ranks above
     a HIGH finding on an isolated role (the central thesis)
  2. Ablation: each model component contributes measurable signal
  3. Ranking comparison: blast-radius vs plain scanner side by side

Run:
    python demo_improvements.py
"""

import sys
import math
import pathlib

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

from blastradius.models import Principal, Statement
from blastradius.graph_builder import build_graph, load_sensitivity_config, parse_terraform_directory
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings, exposure_score
from blastradius.scoring import score_all_findings, blast_radius, ScoringConfig
from blastradius.ranking import rank_by_blast_radius, rank_by_scanner_severity
from blastradius.models import ScoredFinding

SEP  = "=" * 65
SEP2 = "-" * 65


# ── PART 1: Headline claim ────────────────────────────────────────────────────

def part1_headline_claim():
    print(f"\n{SEP}")
    print("PART 1 — Headline Claim")
    print("Central thesis: a MEDIUM finding on an exposed role must rank")
    print("above a HIGH finding on an isolated role.")
    print(SEP)

    alice = Principal("alice", "user", "arn:aws:iam::123:user/alice", [], [])

    dev_role = Principal(
        name="dev-role", kind="role",
        arn="arn:aws:iam::123:role/dev-role",
        statements=[
            Statement("Allow", ["iam:PassRole"],        ["arn:aws:iam::123:role/admin-role"]),
            Statement("Allow", ["lambda:CreateFunction"],["*"]),
        ],
        trust=["*"],   # open trust -> scanner says MEDIUM
    )

    admin_role = Principal(
        name="admin-role", kind="role",
        arn="arn:aws:iam::123:role/admin-role",
        statements=[Statement("Allow", ["rds:*"], ["arn:aws:rds:::prod-customer-db"])],
        trust=["arn:aws:iam::123:role/dev-role"],
    )

    isolated_admin = Principal(
        name="isolated-admin", kind="role",
        arn="arn:aws:iam::123:role/isolated-admin",
        statements=[Statement("Allow", ["*"], ["*"])],
        trust=[],      # nobody can assume it -> scanner says HIGH
    )

    principals = [alice, dev_role, admin_role, isolated_admin]
    resources  = [{"name": "prod-customer-db", "type": "aws_db_instance"}]

    G        = build_graph(principals, resources)
    findings = attach_findings(G, detect_misconfigurations(principals))
    cfg      = ScoringConfig()
    scored   = score_all_findings(G, findings, cfg)

    dev_ot  = next(s for s in scored if s.finding.location == "dev-role"       and s.finding.rule == "open_trust")
    iso_wc  = next(s for s in scored if s.finding.location == "isolated-admin" and s.finding.rule == "wildcard_action")

    print(f"\n  Finding                        Rule              Severity   BR Score   Exposed")
    print(f"  {SEP2}")
    print(f"  {'dev-role (open trust)':<30} {'open_trust':<17} {'MEDIUM':<10} {dev_ot.score:>8.4f}   {dev_ot.exposed}")
    print(f"  {'isolated-admin (wildcard)':<30} {'wildcard_action':<17} {'HIGH':<10} {iso_wc.score:>8.4f}   {iso_wc.exposed}")

    scanner_top = rank_by_scanner_severity(findings)[0]
    br_top      = rank_by_blast_radius(scored)[0]

    print(f"\n  Scanner top-1 : {scanner_top.location} ({scanner_top.scanner_severity})")
    print(f"  Blast-radius top-1 : {br_top.finding.location} ({br_top.finding.scanner_severity})")

    if dev_ot.score > iso_wc.score:
        print("\n  RESULT: PASS — blast-radius correctly promotes the exposed")
        print("          MEDIUM finding above the isolated HIGH finding.")
    else:
        print("\n  RESULT: FAIL")


# ── PART 2: Ablation ─────────────────────────────────────────────────────────

def kendall_tau(a, b):
    pos_a = {x: i for i, x in enumerate(a)}
    pos_b = {x: i for i, x in enumerate(b)}
    ids   = list(pos_a)
    n     = len(ids)
    mx    = n * (n - 1) // 2
    if mx == 0:
        return 0.0
    inv = sum(
        1 for i in range(n) for j in range(i+1, n)
        if (pos_a[ids[i]] < pos_a[ids[j]]) != (pos_b[ids[i]] < pos_b[ids[j]])
    )
    return round(inv / mx, 3)


def score_exposure_only(G, findings, cfg):
    return [ScoredFinding(f, {}, round(exposure_score(G, f.location), 4),
                          exposure_score(G, f.location) > 0) for f in findings]

def score_no_sensitivity(G, findings, cfg):
    c = ScoringConfig(gamma=cfg.gamma, w_count=cfg.w_count,
                      w_sensitivity=0.0, exposed_epsilon=cfg.exposed_epsilon)
    return score_all_findings(G, findings, c)

def score_no_decay(G, findings, cfg):
    c = ScoringConfig(gamma=1.0, w_count=cfg.w_count,
                      w_sensitivity=cfg.w_sensitivity, exposed_epsilon=cfg.exposed_epsilon)
    return score_all_findings(G, findings, c)


def part2_ablation():
    print(f"\n{SEP}")
    print("PART 2 — Ablation: what does each component contribute?")
    print("Metric: Kendall-tau distance from full model (0=identical, 1=reversed)")
    print(SEP)

    synthetic = pathlib.Path(__file__).resolve().parent / "data" / "synthetic"
    sens_cfg  = load_sensitivity_config()
    cfg       = ScoringConfig()

    principals, resources = parse_terraform_directory(str(synthetic))
    G        = build_graph(principals, resources, sens_cfg)
    findings = attach_findings(G, detect_misconfigurations(principals))

    if not findings:
        print("  No findings in synthetic dataset.")
        return

    full_order = [sf.finding.id for sf in rank_by_blast_radius(score_all_findings(G, findings, cfg))]

    variants = {
        "exposure_only  (no sensitivity, no decay)": score_exposure_only,
        "no_sensitivity (count + exposure only)":    score_no_sensitivity,
        "no_decay       (gamma=1.0)":                score_no_decay,
    }

    print(f"\n  {'Variant':<45} {'tau from full':>14}  Interpretation")
    print(f"  {SEP2}")
    for name, fn in variants.items():
        v_order = [sf.finding.id for sf in rank_by_blast_radius(fn(G, findings, cfg))]
        tau     = kendall_tau(full_order, v_order)
        interp  = "adds signal" if tau > 0.01 else "no effect"
        print(f"  {name:<45} {tau:>14.3f}  {interp}")

    print(f"\n  Higher tau = that component is driving ranking changes.")
    print(f"  If tau=0, removing that component changes nothing.")


# ── PART 3: Ranking comparison ────────────────────────────────────────────────

def part3_ranking_comparison():
    print(f"\n{SEP}")
    print("PART 3 — Ranking comparison on synthetic dataset")
    print("Side by side: scanner severity vs blast-radius")
    print(SEP)

    synthetic = pathlib.Path(__file__).resolve().parent / "data" / "synthetic"
    sens_cfg  = load_sensitivity_config()
    cfg       = ScoringConfig()

    principals, resources = parse_terraform_directory(str(synthetic))
    G        = build_graph(principals, resources, sens_cfg)
    findings = attach_findings(G, detect_misconfigurations(principals))

    if not findings:
        print("  No findings.")
        return

    scored         = score_all_findings(G, findings, cfg)
    scanner_ranked = rank_by_scanner_severity(findings)
    br_ranked      = rank_by_blast_radius(scored)

    print(f"\n  {'Rank':<6} {'Scanner top findings':<35} {'Blast-radius top findings':<35}")
    print(f"  {SEP2}")
    for i in range(min(8, len(findings))):
        sf = scanner_ranked[i]
        br = br_ranked[i]
        sc_str = f"{sf.location[:20]} ({sf.scanner_severity})"
        br_str = f"{br.finding.location[:20]} ({br.score:.2f})"
        marker = " <--" if sf.id != br.finding.id else ""
        print(f"  {i+1:<6} {sc_str:<35} {br_str:<35}{marker}")

    inversions = sum(
        1 for i in range(len(findings))
        for j in range(i+1, len(findings))
        if ([f.id for f in scanner_ranked].index(findings[i].id) <
            [f.id for f in scanner_ranked].index(findings[j].id)) !=
           ([sf.finding.id for sf in br_ranked].index(findings[i].id) <
            [sf.finding.id for sf in br_ranked].index(findings[j].id))
    )
    max_inv = len(findings) * (len(findings) - 1) // 2
    tau     = round(inversions / max_inv, 3) if max_inv else 0.0
    print(f"\n  Kendall-tau distance: {tau}  ({inversions}/{max_inv} pairs in different order)")
    print(f"  '<--' marks positions where the two methods disagree.")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\nblast-radius-iam  —  Demonstration of Improvements")
    print("Uses only data/synthetic/ (committed to repo, no setup needed)")

    part1_headline_claim()
    part2_ablation()
    part3_ranking_comparison()

    print(f"\n{SEP}")
    print("Done. All three parts ran on committed synthetic data only.")
    print(SEP)
