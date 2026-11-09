import math
import os
import yaml
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Set, Tuple
import networkx as nx
from blastradius.models import Finding, ScoredFinding
from blastradius.attach import exposure_score


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


def _finding_edges(G: nx.DiGraph, finding: Finding) -> List[Tuple[str, str, dict]]:
    """
    Returns the graph edges that this specific finding enables.
    - open_trust      -> incoming can_assume edges to the node
    - excess_permission -> outgoing can_escalate edges from the node
    - wildcard_*      -> outgoing can_access edges from the node
    """
    loc = finding.location
    if loc not in G:
        return []
    if finding.rule == "open_trust":
        return [(u, v, d) for u, v, d in G.in_edges(loc, data=True) if d.get("etype") == "can_assume"]
    if finding.rule == "excess_permission":
        return [(u, v, d) for u, v, d in G.out_edges(loc, data=True) if d.get("etype") == "can_escalate"]
    # wildcard_action / wildcard_resource
    return [(u, v, d) for u, v, d in G.out_edges(loc, data=True) if d.get("etype") == "can_access"]


def _reachable_value(G: nx.DiGraph, node: str, cfg: "ScoringConfig") -> float:
    """Sum of sensitivity × decay for all reachable role/resource nodes from `node`."""
    if node not in G:
        return 0.0
    dist = nx.single_source_shortest_path_length(G, node)
    total = 0.0
    for n, d in dist.items():
        if n == node:
            continue
        kind = G.nodes[n].get("kind")
        if kind in ("resource", "role"):
            sens = G.nodes[n].get("sensitivity", 3)
            total += sens * (cfg.gamma ** (d - 1))
    return total


def _reachable_from_entries(G: nx.DiGraph, cfg: "ScoringConfig") -> float:
    """
    Total reachable value visible from all entry points (user/external nodes).
    Used as the 'with' baseline for open_trust counterfactual.
    """
    entry_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") in ("user", "external")]
    seen: Dict[str, int] = {}
    for entry in entry_nodes:
        for n, d in nx.single_source_shortest_path_length(G, entry).items():
            if n == entry:
                continue
            if G.nodes[n].get("kind") in ("resource", "role"):
                if n not in seen or d < seen[n]:
                    seen[n] = d
    return sum(G.nodes[n].get("sensitivity", 3) * (cfg.gamma ** (d - 1)) for n, d in seen.items())


def blast_radius(G: nx.DiGraph, finding: Finding, cfg: Optional["ScoringConfig"] = None) -> ScoredFinding:
    """
    Counterfactual blast-radius score for a finding:
      score = exposure x (w_sensitivity x delta_sens + w_count x delta_count)
    where delta = value_with_finding_edges - value_without_finding_edges.

    For open_trust (incoming can_assume edges): the counterfactual is measured
    from the entry-point perspective — removing the trust edges cuts off the
    attacker's path to everything downstream of this node.

    For excess_permission / wildcard_* (outgoing edges): the counterfactual is
    measured from the node itself — removing outgoing edges reduces what the
    node can reach.
    """
    if cfg is None:
        cfg = ScoringConfig()

    v = finding.location
    if v not in G:
        return ScoredFinding(finding=finding, reachable={}, score=0.0, exposed=False)

    edges = _finding_edges(G, finding)
    H = G.copy()
    for u, w, _ in edges:
        H.remove_edge(u, w)

    exp_score = exposure_score(G, v)

    if finding.rule == "open_trust":
        # Removing can_assume edges into v doesn't change what v can reach from itself.
        # The correct counterfactual: how much total attacker-visible value is lost
        # when the entry path to v is cut?
        val_with    = _reachable_from_entries(G, cfg)
        val_without = _reachable_from_entries(H, cfg)
        delta_sens  = max(0.0, val_with - val_without)
        # reach_with: what v itself can reach (for the reachable field)
        dist_with = nx.single_source_shortest_path_length(G, v)
        reach_with = {
            n: d for n, d in dist_with.items()
            if n != v and G.nodes[n].get("kind") in ("resource", "role")
        }
        delta_count = max(0.0, math.log1p(len(reach_with)))
    else:
        # For outgoing-edge findings: measure delta from the node itself
        dist_with    = nx.single_source_shortest_path_length(G, v)
        dist_without = nx.single_source_shortest_path_length(H, v)
        reach_with = {
            n: d for n, d in dist_with.items()
            if n != v and G.nodes[n].get("kind") in ("resource", "role")
        }
        reach_without = {
            n: d for n, d in dist_without.items()
            if n != v and H.nodes[n].get("kind") in ("resource", "role")
        }
        sens_with    = sum(G.nodes[n].get("sensitivity", 3) * (cfg.gamma ** (d - 1)) for n, d in reach_with.items())
        sens_without = sum(H.nodes[n].get("sensitivity", 3) * (cfg.gamma ** (d - 1)) for n, d in reach_without.items())
        delta_sens  = max(0.0, sens_with - sens_without)
        delta_count = max(0.0, math.log1p(len(reach_with)) - math.log1p(len(reach_without)))

    raw_score = exp_score * (cfg.w_sensitivity * delta_sens + cfg.w_count * delta_count)

    return ScoredFinding(
        finding=finding,
        reachable=reach_with,
        score=round(raw_score, 4),
        exposed=exp_score > cfg.exposed_epsilon,
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
