import math
import os
import yaml
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import networkx as nx
from blastradius.models import Finding, ScoredFinding
from blastradius.attach import is_exposed


@dataclass
class ScoringConfig:
    gamma: float = 0.8
    w_count: float = 1.0
    w_sensitivity: float = 1.0
    exposed_epsilon: float = 0.05


def load_scoring_config(config_path: Optional[str] = None) -> ScoringConfig:
    """Loads weights and scoring constants from YAML, or uses defaults."""
    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return ScoringConfig(
                gamma=float(data.get("gamma", 0.8)),
                w_count=float(data.get("w_count", 1.0)),
                w_sensitivity=float(data.get("w_sensitivity", 1.0)),
                exposed_epsilon=float(data.get("exposed_epsilon", 0.05)),
            )

    # Check default config locations
    for candidate in ["configs/weight.yaml", "configs/weights.yaml"]:
        if os.path.exists(candidate):
            return load_scoring_config(candidate)

    return ScoringConfig()


def blast_radius(G: nx.DiGraph, finding: Finding, cfg: Optional[ScoringConfig] = None) -> ScoredFinding:
    """
    Computes the blast radius score for a single finding:
    Score = exposure * (w_sensitivity * sum(s(r) * gamma^(d-1)) + w_count * log(1 + |reach|))
    """
    if cfg is None:
        cfg = ScoringConfig()

    v = finding.location
    if v not in G:
        return ScoredFinding(finding=finding, reachable={}, score=0.0, exposed=False)

    # Shortest paths to all nodes reachable from finding's location
    dist = nx.single_source_shortest_path_length(G, v)

    # All reachable resources and intermediate roles (excluding self)
    reach = {
        n: d for n, d in dist.items()
        if n != v and G.nodes[n].get("kind") in ("resource", "role")
    }

    # Sum of sensitivities with path-length decay: gamma^(d - 1)
    sens_sum = sum(
        G.nodes[n].get("sensitivity", 3) * (cfg.gamma ** (d - 1))
        for n, d in reach.items()
        if G.nodes[n].get("kind") == "resource"
    )

    # Determine exposure dynamically on the current graph G
    exposed = is_exposed(G, v)
    exposure_factor = 1.0 if exposed else cfg.exposed_epsilon

    # Formula from project specification
    raw_score = exposure_factor * (
        cfg.w_sensitivity * sens_sum + cfg.w_count * math.log1p(len(reach))
    )

    return ScoredFinding(
        finding=finding,
        reachable=reach,
        score=round(raw_score, 2),
        exposed=exposed,
    )


def score_all_findings(
    G: nx.DiGraph,
    findings: List[Finding],
    cfg: Optional[ScoringConfig] = None,
) -> List[ScoredFinding]:
    """Scores all findings against the reachability graph G."""
    if cfg is None:
        cfg = load_scoring_config()
    return [blast_radius(G, f, cfg) for f in findings]
