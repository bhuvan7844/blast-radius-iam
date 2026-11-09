"""
Ablation Study: What drives the blast-radius ranking?
------------------------------------------------------
Compares five model variants on each dataset (directory-level parsing):

  full          - full model (exposure_score x (w_sens x delta_sens + w_count x delta_count))
  exposure_only - replace score with raw exposure_score, ignore sensitivity/reach
  severity_only - plain scanner severity (baseline)
  no_sensitivity- w_sensitivity=0 (count term only)
  no_decay      - gamma=1.0 (no path-length decay)

Metrics per variant vs full model:
  tau   - normalised Kendall-tau distance from full ranking (0=identical)
  top1  - % files where top-1 finding matches full model's top-1
"""

import sys
import math
import pathlib
from typing import List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from blastradius.graph_builder import build_graph, load_sensitivity_config, parse_terraform_directory
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings, exposure_score
from blastradius.scoring import blast_radius, ScoringConfig, score_all_findings
from blastradius.ranking import rank_by_blast_radius, rank_by_scanner_severity, SEVERITY_ORDER
from blastradius.models import Finding, ScoredFinding
import networkx as nx

DATA_ROOT = pathlib.Path(__file__).resolve().parents[1] / "data"
DATASETS = {
    "synthetic":      DATA_ROOT / "synthetic",
    "iam_vulnerable": DATA_ROOT / "iam_vulnerable",
    "terragoat":      DATA_ROOT / "terragoat",
    "cloudgoat":      DATA_ROOT / "cloudgoat",
}


def kendall_tau(rank_a: List[str], rank_b: List[str]) -> float:
    pos_a = {fid: i for i, fid in enumerate(rank_a)}
    pos_b = {fid: i for i, fid in enumerate(rank_b)}
    ids = list(pos_a.keys())
    n = len(ids)
    max_inv = n * (n - 1) // 2
    if max_inv == 0:
        return 0.0
    inv = sum(
        1 for i in range(n) for j in range(i + 1, n)
        if (pos_a[ids[i]] < pos_a[ids[j]]) != (pos_b[ids[i]] < pos_b[ids[j]])
    )
    return round(inv / max_inv, 3)


# ── Variant scoring functions ─────────────────────────────────────────────────

def score_exposure_only(G: nx.DiGraph, findings: List[Finding], cfg: ScoringConfig) -> List[ScoredFinding]:
    """Score = raw exposure_score only; ignores sensitivity and reach."""
    results = []
    for f in findings:
        exp = exposure_score(G, f.location)
        results.append(ScoredFinding(
            finding=f,
            reachable={},
            score=round(exp, 4),
            exposed=exp > 0.0,
        ))
    return results


def score_no_sensitivity(G: nx.DiGraph, findings: List[Finding], cfg: ScoringConfig) -> List[ScoredFinding]:
    """w_sensitivity=0: count term only."""
    c = ScoringConfig(gamma=cfg.gamma, w_count=cfg.w_count, w_sensitivity=0.0,
                      exposed_epsilon=cfg.exposed_epsilon)
    return score_all_findings(G, findings, c)


def score_no_decay(G: nx.DiGraph, findings: List[Finding], cfg: ScoringConfig) -> List[ScoredFinding]:
    """gamma=1.0: no path-length decay."""
    c = ScoringConfig(gamma=1.0, w_count=cfg.w_count, w_sensitivity=cfg.w_sensitivity,
                      exposed_epsilon=cfg.exposed_epsilon)
    return score_all_findings(G, findings, c)


def score_severity_only(G: nx.DiGraph, findings: List[Finding], cfg: ScoringConfig) -> List[ScoredFinding]:
    """Plain scanner severity as score."""
    return [
        ScoredFinding(finding=f, reachable={},
                      score=float(SEVERITY_ORDER.get(f.scanner_severity, 0)),
                      exposed=False)
        for f in findings
    ]


VARIANTS = {
    "exposure_only":  score_exposure_only,
    "severity_only":  score_severity_only,
    "no_sensitivity": score_no_sensitivity,
    "no_decay":       score_no_decay,
}


def run_ablation():
    from blastradius.scoring import load_scoring_config
    sens_cfg    = load_sensitivity_config()
    scoring_cfg = load_scoring_config()

    # Header
    col = 16
    variants = list(VARIANTS.keys())
    header = f"{'Dataset':<18}" + "".join(f"{'tau_'+v:>{col}}" for v in variants) + \
             "".join(f"{'top1_'+v:>{col}}" for v in variants)
    print("\nAblation: tau and top-1 vs full model (directory-level parsing)")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    totals: Dict[str, Dict[str, float]] = {v: {"tau_sum": 0.0, "top1_sum": 0, "count": 0} for v in variants}

    for ds_name, ds_root in DATASETS.items():
        if not ds_root.exists():
            continue

        try:
            principals, resources = parse_terraform_directory(str(ds_root))
            G = build_graph(principals, resources, sens_cfg)
            findings = attach_findings(G, detect_misconfigurations(principals))
        except Exception as e:
            print(f"{ds_name:<18}  [error: {e}]")
            continue

        if not findings:
            print(f"{ds_name:<18}  [no findings]")
            continue

        # Full model ranking (reference)
        full_scored  = score_all_findings(G, findings, scoring_cfg)
        full_order   = [sf.finding.id for sf in rank_by_blast_radius(full_scored)]

        row = f"{ds_name:<18}"
        tau_vals, top1_vals = [], []

        for v_name, v_fn in VARIANTS.items():
            v_scored = v_fn(G, findings, scoring_cfg)
            v_order  = [sf.finding.id for sf in rank_by_blast_radius(v_scored)]
            tau      = kendall_tau(full_order, v_order)
            top1     = int(v_order[0] == full_order[0]) if full_order and v_order else 1
            tau_vals.append(f"{tau:.3f}")
            top1_vals.append("yes" if top1 else "no")
            totals[v_name]["tau_sum"] += tau
            totals[v_name]["top1_sum"] += top1
            totals[v_name]["count"] += 1

        row += "".join(f"{v:>{col}}" for v in tau_vals)
        row += "".join(f"{v:>{col}}" for v in top1_vals)
        print(row)

    # Summary row
    print("-" * len(header))
    avg_tau  = [f"{totals[v]['tau_sum']/max(totals[v]['count'],1):.3f}" for v in variants]
    avg_top1 = [f"{totals[v]['top1_sum']/max(totals[v]['count'],1)*100:.0f}%" for v in variants]
    row = f"{'AVERAGE':<18}"
    row += "".join(f"{v:>{col}}" for v in avg_tau)
    row += "".join(f"{v:>{col}}" for v in avg_top1)
    print(row)

    print("""
Key:
  tau   - normalised Kendall-tau distance from full model ranking.
          0 = identical to full model, 1 = fully reversed.
          High tau means that variant drives most of the ranking.
  top1  - does this variant agree with full model on the #1 finding?

Interpretation:
  exposure_only tau ~ 0  -> exposure is doing all the work
  no_sensitivity tau > 0 -> sensitivity term adds signal
  no_decay tau > 0       -> path decay adds signal
  severity_only tau high -> blast-radius diverges meaningfully from scanner
""")


if __name__ == "__main__":
    run_ablation()
