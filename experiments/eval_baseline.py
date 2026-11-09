"""
Baseline Comparison: Blast-Radius Ranking vs Plain Scanner Severity
--------------------------------------------------------------------
For each .tf file that produces findings, computes:
  - Scanner baseline ranking (HIGH > MEDIUM > LOW)
  - Blast-radius ranking (by score)
  - Rank inversions: findings that moved up or down
  - Top-1 agreement: does both methods agree on the most critical finding?
  - Kendall-tau distance between the two rankings

Runs across all four datasets and prints a summary table.
"""

import sys
import pathlib
import itertools
from typing import List, Dict, Any, Tuple

# Force UTF-8 output on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from blastradius.parser_terraform import parse_terraform_file
from blastradius.graph_builder import build_graph, load_sensitivity_config, parse_terraform_directory
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings
from blastradius.scoring import score_all_findings, load_scoring_config
from blastradius.ranking import rank_by_blast_radius, rank_by_scanner_severity, generate_ranking_comparison

DATA_ROOT = pathlib.Path(__file__).resolve().parents[1] / "data"
DATASETS = {
    "synthetic":      DATA_ROOT / "synthetic",
    "iam_vulnerable": DATA_ROOT / "iam_vulnerable",
    "terragoat":      DATA_ROOT / "terragoat",
    "cloudgoat":      DATA_ROOT / "cloudgoat",
}

# Use directory-level parsing so cross-file resources join the graph
USE_DIR_PARSE = True


def kendall_tau_distance(rank_a: List[str], rank_b: List[str]) -> int:
    """
    Counts the number of pairwise inversions between two rankings.
    A pair (i, j) is inverted if their relative order differs between rank_a and rank_b.
    Range: 0 (identical) to n*(n-1)/2 (completely reversed).
    """
    pos_a = {fid: i for i, fid in enumerate(rank_a)}
    pos_b = {fid: i for i, fid in enumerate(rank_b)}
    ids = list(pos_a.keys())
    inversions = 0
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a, b = ids[i], ids[j]
            if (pos_a[a] < pos_a[b]) != (pos_b[a] < pos_b[b]):
                inversions += 1
    return inversions


def analyse_dir(ds_root: pathlib.Path, sens_cfg: dict, scoring_cfg) -> Dict[str, Any]:
    """Analyse an entire dataset directory as one merged graph."""
    principals, resources = parse_terraform_directory(str(ds_root))
    G = build_graph(principals, resources, sens_cfg)
    findings = attach_findings(G, detect_misconfigurations(principals))
    if not findings:
        return {}

    scored = score_all_findings(G, findings, scoring_cfg)
    scanner_order = [f.id for f in rank_by_scanner_severity(findings)]
    br_order = [sf.finding.id for sf in rank_by_blast_radius(scored)]

    n = len(findings)
    max_inversions = n * (n - 1) // 2
    inversions = kendall_tau_distance(scanner_order, br_order)
    tau_normalised = round(inversions / max_inversions, 3) if max_inversions > 0 else 0.0
    top1_agree = (scanner_order[0] == br_order[0]) if scanner_order and br_order else True

    comparison = generate_ranking_comparison(scored)
    promoted = [r for r in comparison if r["rank_delta"] > 0 and r["exposed"]]
    demoted  = [r for r in comparison if r["rank_delta"] < 0 and not r["exposed"]]

    return {
        "file": ds_root.name,
        "n_findings": n,
        "n_exposed": sum(1 for f in findings if f.exposed),
        "inversions": inversions,
        "max_inversions": max_inversions,
        "tau_normalised": tau_normalised,
        "top1_agree": top1_agree,
        "promoted": len(promoted),
        "demoted": len(demoted),
        "scanner_top1": scanner_order[0] if scanner_order else "-",
        "br_top1": br_order[0] if br_order else "-",
    }


def analyse_file(tf_path: pathlib.Path, sens_cfg: dict, scoring_cfg) -> Dict[str, Any]:
    principals, resources = parse_terraform_file(str(tf_path))
    G = build_graph(principals, resources, sens_cfg)
    findings = attach_findings(G, detect_misconfigurations(principals))
    if not findings:
        return {}

    scored = score_all_findings(G, findings, scoring_cfg)

    # Scanner baseline order
    scanner_order = [f.id for f in rank_by_scanner_severity(findings)]
    # Blast-radius order
    br_order = [sf.finding.id for sf in rank_by_blast_radius(scored)]

    n = len(findings)
    max_inversions = n * (n - 1) // 2
    inversions = kendall_tau_distance(scanner_order, br_order)
    tau_normalised = round(inversions / max_inversions, 3) if max_inversions > 0 else 0.0

    # Top-1 agreement
    top1_agree = (scanner_order[0] == br_order[0]) if scanner_order and br_order else True

    # Promoted: exposed findings that moved up vs scanner
    comparison = generate_ranking_comparison(scored)
    promoted   = [r for r in comparison if r["rank_delta"] > 0 and r["exposed"]]
    demoted    = [r for r in comparison if r["rank_delta"] < 0 and not r["exposed"]]

    return {
        "file": tf_path.name,
        "n_findings": n,
        "n_exposed": sum(1 for f in findings if f.exposed),
        "inversions": inversions,
        "max_inversions": max_inversions,
        "tau_normalised": tau_normalised,
        "top1_agree": top1_agree,
        "promoted": len(promoted),
        "demoted": len(demoted),
        "scanner_top1": scanner_order[0] if scanner_order else "-",
        "br_top1": br_order[0] if br_order else "-",
    }


def run_comparison():
    sens_cfg    = load_sensitivity_config()
    scoring_cfg = load_scoring_config()

    all_results: Dict[str, List[Dict]] = {}

    for ds_name, ds_root in DATASETS.items():
        if not ds_root.exists():
            continue

        ds_results = []
        if USE_DIR_PARSE:
            try:
                r = analyse_dir(ds_root, sens_cfg, scoring_cfg)
                if r:
                    ds_results.append(r)
            except Exception:
                pass
        else:
            for tf_path in sorted(ds_root.rglob("*.tf")):
                try:
                    r = analyse_file(tf_path, sens_cfg, scoring_cfg)
                    if r:
                        ds_results.append(r)
                except Exception:
                    continue

        all_results[ds_name] = ds_results

        if not ds_results:
            print(f"\n{ds_name}: no files with findings")
            continue

        total_files      = len(ds_results)
        total_inversions = sum(r["inversions"] for r in ds_results)
        total_max        = sum(r["max_inversions"] for r in ds_results)
        avg_tau          = round(total_inversions / total_max, 3) if total_max > 0 else 0.0
        top1_agree_pct   = round(sum(1 for r in ds_results if r["top1_agree"]) / total_files * 100, 1)
        total_promoted   = sum(r["promoted"] for r in ds_results)
        total_demoted    = sum(r["demoted"] for r in ds_results)

        print(f"\n{'='*70}")
        print(f"Dataset: {ds_name}  ({total_files} files with findings)")
        print(f"{'='*70}")
        print(f"  Avg Kendall-tau distance (normalised): {avg_tau:.3f}  "
              f"(0=identical, 1=fully reversed)")
        print(f"  Top-1 agreement with scanner:          {top1_agree_pct}%")
        print(f"  Findings promoted (exposed, moved up): {total_promoted}")
        print(f"  Findings demoted  (isolated, moved dn): {total_demoted}")

        # Show the most interesting inversions (top-1 disagreements)
        disagreements = [r for r in ds_results if not r["top1_agree"]]
        if disagreements:
            print(f"\n  Top-1 disagreements ({len(disagreements)} files):")
            for r in disagreements[:5]:
                print(f"    [{r['file']}] scanner={r['scanner_top1']} -> br={r['br_top1']}  "
                      f"(exposed={r['n_exposed']}/{r['n_findings']})")

    # ── Overall summary ───────────────────────────────────────────────────────
    all_flat = [r for ds in all_results.values() for r in ds]
    if not all_flat:
        print("\nNo results.")
        return

    total_files      = len(all_flat)
    total_inversions = sum(r["inversions"] for r in all_flat)
    total_max        = sum(r["max_inversions"] for r in all_flat)
    avg_tau          = round(total_inversions / total_max, 3) if total_max > 0 else 0.0
    top1_agree_pct   = round(sum(1 for r in all_flat if r["top1_agree"]) / total_files * 100, 1)
    total_promoted   = sum(r["promoted"] for r in all_flat)
    total_demoted    = sum(r["demoted"] for r in all_flat)

    print(f"\n{'='*70}")
    print("OVERALL SUMMARY")
    print(f"{'='*70}")
    print(f"{'Dataset':<18} {'Files':>6} {'Avg τ':>8} {'Top-1 Agree':>12} {'Promoted':>10} {'Demoted':>9}")
    print("-" * 70)
    for ds_name, ds_results in all_results.items():
        if not ds_results:
            continue
        t_inv = sum(r["inversions"] for r in ds_results)
        t_max = sum(r["max_inversions"] for r in ds_results)
        tau   = round(t_inv / t_max, 3) if t_max > 0 else 0.0
        t1    = round(sum(1 for r in ds_results if r["top1_agree"]) / len(ds_results) * 100, 1)
        prom  = sum(r["promoted"] for r in ds_results)
        dem   = sum(r["demoted"] for r in ds_results)
        print(f"{ds_name:<18} {len(ds_results):>6} {tau:>8.3f} {t1:>11}% {prom:>10} {dem:>9}")
    print("-" * 70)
    print(f"{'OVERALL':<18} {total_files:>6} {avg_tau:>8.3f} {top1_agree_pct:>11}% "
          f"{total_promoted:>10} {total_demoted:>9}")

    print(f"""
Key:
  Avg τ (Kendall-tau): normalised pairwise inversion rate between scanner and
                       blast-radius rankings. 0 = identical, 1 = fully reversed.
  Top-1 Agree:         % of files where both methods agree on the #1 finding.
  Promoted:            exposed findings that blast-radius moved UP vs scanner.
  Demoted:             isolated findings that blast-radius moved DOWN vs scanner.
""")


if __name__ == "__main__":
    run_comparison()
