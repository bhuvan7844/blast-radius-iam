"""
Sensitivity Analysis for Blast-Radius Scoring Weights
------------------------------------------------------
Varies gamma, w_sensitivity, and w_count across a range and checks
whether the top-k finding ranking stays stable across all datasets:
synthetic, iam_vulnerable, terragoat, cloudgoat.
"""

import sys
import pathlib
import itertools
from typing import List, Dict, Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from blastradius.parser_terraform import parse_terraform_file
from blastradius.graph_builder import build_graph, load_sensitivity_config
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings
from blastradius.scoring import blast_radius, ScoringConfig
from blastradius.ranking import rank_by_blast_radius

# ── Weight ranges to sweep ────────────────────────────────────────────────────
GAMMA_VALUES         = [0.6, 0.7, 0.8, 0.9]
W_SENSITIVITY_VALUES = [0.5, 1.0, 1.5, 2.0]
W_COUNT_VALUES       = [0.5, 1.0, 1.5, 2.0]
TOP_K                = 3
TOTAL_COMBOS         = len(GAMMA_VALUES) * len(W_SENSITIVITY_VALUES) * len(W_COUNT_VALUES)

# ── Datasets ──────────────────────────────────────────────────────────────────
DATA_ROOT = pathlib.Path(__file__).resolve().parents[1] / "data"
DATASETS = {
    "synthetic":      DATA_ROOT / "synthetic",
    "iam_vulnerable": DATA_ROOT / "iam_vulnerable",
    "terragoat":      DATA_ROOT / "terragoat",
    "cloudgoat":      DATA_ROOT / "cloudgoat",
}


def get_top_k_ids(findings, G, cfg, k) -> List[str]:
    scored = [blast_radius(G, f, cfg) for f in findings]
    ranked = rank_by_blast_radius(scored)
    return [sf.finding.id for sf in ranked[:k]]


def analyse_dataset(ds_name: str, ds_root: pathlib.Path, sens_cfg: dict) -> Dict[str, Any]:
    tf_files = sorted(ds_root.rglob("*.tf"))
    ds_stable = ds_unstable = parsed_ok = skipped = 0
    sample_unstable = []

    for tf_path in tf_files:
        try:
            principals, resources = parse_terraform_file(str(tf_path))
        except Exception:
            skipped += 1
            continue

        G = build_graph(principals, resources, sens_cfg)
        findings = attach_findings(G, detect_misconfigurations(principals))

        if not findings:
            skipped += 1
            continue

        parsed_ok += 1
        baseline_top_k = get_top_k_ids(findings, G, ScoringConfig(), TOP_K)

        for gamma, w_s, w_c in itertools.product(GAMMA_VALUES, W_SENSITIVITY_VALUES, W_COUNT_VALUES):
            cfg = ScoringConfig(gamma=gamma, w_sensitivity=w_s, w_count=w_c)
            top_k = get_top_k_ids(findings, G, cfg, TOP_K)
            overlap = len(set(baseline_top_k) & set(top_k))
            if overlap < min(TOP_K, len(findings)):
                ds_unstable += 1
                if len(sample_unstable) < 3:
                    sample_unstable.append({
                        "file": tf_path.name,
                        "gamma": gamma, "w_s": w_s, "w_c": w_c,
                        "baseline": baseline_top_k, "new": top_k,
                    })
            else:
                ds_stable += 1

    total = ds_stable + ds_unstable
    return {
        "tf_files": len(tf_files),
        "parsed_ok": parsed_ok,
        "skipped": skipped,
        "total_combos": total,
        "stable": ds_stable,
        "unstable": ds_unstable,
        "stability_pct": round(ds_stable / total * 100, 1) if total > 0 else 0.0,
        "sample_unstable": sample_unstable,
    }


def run_analysis():
    sens_cfg = load_sensitivity_config()
    results: Dict[str, Any] = {}

    for ds_name, ds_root in DATASETS.items():
        if not ds_root.exists():
            print(f"\n{ds_name}: directory not found, skipping")
            continue
        print(f"\nAnalysing {ds_name} ...")
        r = analyse_dataset(ds_name, ds_root, sens_cfg)
        results[ds_name] = r

        print(f"  .tf files: {r['tf_files']}  |  with findings: {r['parsed_ok']}  |  skipped: {r['skipped']}")
        print(f"  Stable: {r['stable']}/{r['total_combos']} ({r['stability_pct']}%)")

        if r["sample_unstable"]:
            print(f"  Sample unstable combinations:")
            for s in r["sample_unstable"]:
                print(f"    [{s['file']}] gamma={s['gamma']} w_s={s['w_s']} w_c={s['w_c']} "
                      f"baseline={s['baseline']} -> {s['new']}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print("SUMMARY")
    print(f"{'='*65}")
    print(f"{'Dataset':<18} {'Files':>6} {'With Findings':>14} {'Stability %':>12} {'Stable':>8} {'Unstable':>10}")
    print("-" * 65)
    for ds, r in results.items():
        print(f"{ds:<18} {r['tf_files']:>6} {r['parsed_ok']:>14} {r['stability_pct']:>11}% "
              f"{r['stable']:>8} {r['unstable']:>10}")

    overall_stable   = sum(r["stable"] for r in results.values())
    overall_unstable = sum(r["unstable"] for r in results.values())
    overall_total    = overall_stable + overall_unstable
    overall_pct      = round(overall_stable / overall_total * 100, 1) if overall_total > 0 else 0.0
    print("-" * 65)
    print(f"{'OVERALL':<18} {'':>6} {'':>14} {overall_pct:>11}% {overall_stable:>8} {overall_unstable:>10}")


if __name__ == "__main__":
    run_analysis()
