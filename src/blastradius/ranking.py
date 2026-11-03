from typing import List, Dict, Any
from blastradius.models import Finding, ScoredFinding

SEVERITY_ORDER = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def rank_by_blast_radius(scored: List[ScoredFinding]) -> List[ScoredFinding]:
    """Sorts scored findings descending by computed blast-radius score."""
    return sorted(
        scored,
        key=lambda s: (s.score, SEVERITY_ORDER.get(s.finding.scanner_severity, 0)),
        reverse=True,
    )


def rank_by_scanner_severity(findings: List[Finding]) -> List[Finding]:
    """Baseline ranking: sorts findings by generic scanner severity (HIGH > MEDIUM > LOW)."""
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.scanner_severity, 0),
        reverse=True,
    )


def generate_ranking_comparison(scored_findings: List[ScoredFinding]) -> List[Dict[str, Any]]:
    """
    Produces a side-by-side comparison between traditional scanner rank
    and Blast-Radius rank, highlighting rank changes.
    """
    # 1. Baseline rank
    baseline_sorted = sorted(
        scored_findings,
        key=lambda s: SEVERITY_ORDER.get(s.finding.scanner_severity, 0),
        reverse=True,
    )
    baseline_rank_map = {s.finding.id: rank + 1 for rank, s in enumerate(baseline_sorted)}

    # 2. Blast radius rank
    br_sorted = rank_by_blast_radius(scored_findings)

    comparison = []
    for br_rank, sf in enumerate(br_sorted, start=1):
        f = sf.finding
        base_rank = baseline_rank_map.get(f.id, br_rank)
        rank_delta = base_rank - br_rank  # positive = promoted, negative = demoted
        comparison.append({
            "br_rank": br_rank,
            "base_rank": base_rank,
            "rank_delta": rank_delta,
            "id": f.id,
            "rule": f.rule,
            "location": f.location,
            "scanner_severity": f.scanner_severity,
            "br_score": sf.score,
            "exposed": sf.exposed,
            "reachable_resources": len([r for r, d in sf.reachable.items() if d > 0]),
            "detail": f.detail,
        })

    return comparison

