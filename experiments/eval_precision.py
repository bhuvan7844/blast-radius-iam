"""
Ground Truth Evaluation: Precision@K on iam_vulnerable
-------------------------------------------------------
iam_vulnerable contains labeled privesc scenarios — each .tf file in
privesc-paths/ is a named attack path to admin. This gives us real ground truth.

Ground truth rule:
  A finding is a TRUE POSITIVE if its location node name contains the
  scenario identifier extracted from the privesc filename.
  e.g. privesc1-CreateNewPolicyVersion.tf  ->  "privesc1-createNewPolicyVersion"
       any finding on node "privesc1-CreateNewPolicyVersion-user" or
       "privesc1-CreateNewPolicyVersion-role" is a true positive.

Metrics:
  precision@k  - of top-k findings, what fraction are true positives?
  recall@k     - of all true positives, what fraction appear in top-k?
  avg_rank     - average rank of true positives (lower = better)

Compares blast-radius ranking vs plain scanner severity ranking.
"""

import sys
import pathlib
from typing import List, Set, Dict, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from blastradius.graph_builder import build_graph, load_sensitivity_config, parse_terraform_directory
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings
from blastradius.scoring import score_all_findings, load_scoring_config
from blastradius.ranking import rank_by_blast_radius, rank_by_scanner_severity
from blastradius.models import Finding, ScoredFinding

IAM_VULNERABLE = pathlib.Path(__file__).resolve().parents[1] / "data" / "iam_vulnerable"
PRIVESC_DIR    = IAM_VULNERABLE / "modules" / "free-resources" / "privesc-paths"


def extract_scenario_id(tf_filename: str) -> str:
    """
    privesc1-CreateNewPolicyVersion.tf  ->  'privesc1-createnewpolicyversion'
    privesc-AssumeRole.tf               ->  'privesc-assumerole'
    """
    return tf_filename.replace(".tf", "").lower()


def build_ground_truth(privesc_dir: pathlib.Path) -> Set[str]:
    """
    Returns a set of scenario ids extracted from all privesc .tf filenames.
    A finding is a true positive if its location contains any of these ids.
    """
    ids = set()
    for tf in privesc_dir.glob("privesc*.tf"):
        ids.add(extract_scenario_id(tf.name))
    return ids


def is_true_positive(location: str, ground_truth_ids: Set[str]) -> bool:
    """
    A finding is a true positive if its node name contains a labeled scenario id.
    e.g. 'privesc1-CreateNewPolicyVersion-user' contains 'privesc1-createnewpolicyversion'
    """
    loc_lower = location.lower()
    return any(gid in loc_lower for gid in ground_truth_ids)


def precision_at_k(ranked_findings: List[Finding], ground_truth_ids: Set[str], k: int) -> float:
    top_k = ranked_findings[:k]
    if not top_k:
        return 0.0
    hits = sum(1 for f in top_k if is_true_positive(f.location, ground_truth_ids))
    return round(hits / len(top_k), 3)


def recall_at_k(ranked_findings: List[Finding], ground_truth_ids: Set[str], k: int) -> float:
    total_tp = sum(1 for f in ranked_findings if is_true_positive(f.location, ground_truth_ids))
    if total_tp == 0:
        return 0.0
    top_k_hits = sum(
        1 for f in ranked_findings[:k]
        if is_true_positive(f.location, ground_truth_ids)
    )
    return round(top_k_hits / total_tp, 3)


def average_rank_of_tp(ranked_findings: List[Finding], ground_truth_ids: Set[str]) -> float:
    """Average rank (1-indexed) of true positive findings. Lower is better."""
    ranks = [
        i + 1 for i, f in enumerate(ranked_findings)
        if is_true_positive(f.location, ground_truth_ids)
    ]
    return round(sum(ranks) / len(ranks), 1) if ranks else float("inf")


def run_evaluation():
    if not IAM_VULNERABLE.exists():
        print("iam_vulnerable dataset not found at", IAM_VULNERABLE)
        return

    ground_truth_ids = build_ground_truth(PRIVESC_DIR)
    print(f"Ground truth: {len(ground_truth_ids)} labeled privesc scenarios")
    print(f"Example ids:  {sorted(ground_truth_ids)[:3]} ...")

    # Build merged graph across all files
    sens_cfg    = load_sensitivity_config()
    scoring_cfg = load_scoring_config()

    principals, resources = parse_terraform_directory(str(IAM_VULNERABLE))
    G        = build_graph(principals, resources, sens_cfg)
    findings = attach_findings(G, detect_misconfigurations(principals))
    scored   = score_all_findings(G, findings, scoring_cfg)

    total_tp = sum(1 for f in findings if is_true_positive(f.location, ground_truth_ids))
    print(f"\nTotal findings: {len(findings)}")
    print(f"True positives (on labeled paths): {total_tp}")
    print(f"True negatives (not on labeled paths): {len(findings) - total_tp}")

    # Two ranked lists
    br_ranked      = [sf.finding for sf in rank_by_blast_radius(scored)]
    scanner_ranked = rank_by_scanner_severity(findings)

    # Evaluate at multiple K values
    ks = [1, 3, 5, 10, 20]

    print(f"\n{'':─<62}")
    print(f"{'Metric':<28} " + "".join(f"{'K='+str(k):>8}" for k in ks))
    print(f"{'':─<62}")

    # Precision@K
    print(f"\n  Precision@K (fraction of top-K that are true positives):")
    br_prec = [precision_at_k(br_ranked, ground_truth_ids, k) for k in ks]
    sc_prec = [precision_at_k(scanner_ranked, ground_truth_ids, k) for k in ks]
    print(f"  {'blast-radius':<24} " + "".join(f"{v:>8.3f}" for v in br_prec))
    print(f"  {'scanner severity':<24} " + "".join(f"{v:>8.3f}" for v in sc_prec))
    print(f"  {'delta (br - scanner)':<24} " + "".join(
        f"{(b-s):>+8.3f}" for b, s in zip(br_prec, sc_prec)
    ))

    # Recall@K
    print(f"\n  Recall@K (fraction of all true positives found in top-K):")
    br_rec = [recall_at_k(br_ranked, ground_truth_ids, k) for k in ks]
    sc_rec = [recall_at_k(scanner_ranked, ground_truth_ids, k) for k in ks]
    print(f"  {'blast-radius':<24} " + "".join(f"{v:>8.3f}" for v in br_rec))
    print(f"  {'scanner severity':<24} " + "".join(f"{v:>8.3f}" for v in sc_rec))
    print(f"  {'delta (br - scanner)':<24} " + "".join(
        f"{(b-s):>+8.3f}" for b, s in zip(br_rec, sc_rec)
    ))

    # Average rank of true positives
    br_avg_rank = average_rank_of_tp(br_ranked, ground_truth_ids)
    sc_avg_rank = average_rank_of_tp(scanner_ranked, ground_truth_ids)
    print(f"\n  Average rank of true positives (lower = better):")
    print(f"  blast-radius:     {br_avg_rank}")
    print(f"  scanner severity: {sc_avg_rank}")
    print(f"  delta:            {round(sc_avg_rank - br_avg_rank, 1):+.1f}  "
          f"({'blast-radius wins' if br_avg_rank < sc_avg_rank else 'scanner wins' if sc_avg_rank < br_avg_rank else 'tie'})")

    # Show top-10 blast-radius findings with TP/FP label
    print(f"\n  Top-10 blast-radius findings:")
    print(f"  {'Rank':<6}{'ID':<8}{'Rule':<22}{'Location':<42}{'Score':>8}  Label")
    print(f"  {'':─<92}")
    for i, f in enumerate(br_ranked[:10], 1):
        tp = is_true_positive(f.location, ground_truth_ids)
        sf = next((s for s in scored if s.finding.id == f.id), None)
        score_str = f"{sf.score:.4f}" if sf else "n/a"
        label = "TP" if tp else "FP"
        print(f"  {i:<6}{f.id:<8}{f.rule:<22}{f.location:<42}{score_str:>8}  {label}")

    # Show top-10 scanner findings with TP/FP label
    print(f"\n  Top-10 scanner severity findings:")
    print(f"  {'Rank':<6}{'ID':<8}{'Rule':<22}{'Location':<42}{'Severity':>8}  Label")
    print(f"  {'':─<92}")
    for i, f in enumerate(scanner_ranked[:10], 1):
        tp = is_true_positive(f.location, ground_truth_ids)
        print(f"  {i:<6}{f.id:<8}{f.rule:<22}{f.location:<42}{f.scanner_severity:>8}  {'TP' if tp else 'FP'}")

    print(f"\n{'':─<62}")
    print("Key:")
    print("  TP = finding is on a labeled privesc path (ground truth positive)")
    print("  FP = finding is NOT on a labeled privesc path")
    print("  Precision@K > scanner means blast-radius surfaces real attacks higher")
    print("  Recall@K    > scanner means blast-radius finds more attacks in top-K")


if __name__ == "__main__":
    run_evaluation()
