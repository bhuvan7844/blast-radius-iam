from typing import List, Dict, Any, Optional
import networkx as nx
from blastradius.models import Finding

# Weight given to each entry-point type when computing exposure score
_ENTRY_WEIGHTS = {"external": 1.0, "user": 0.5}


def exposure_score(G: nx.DiGraph, node_name: str) -> float:
    """
    Graded exposure: sum of entry-point weights for all distinct entry points
    that can reach `node_name`, scaled by 1/(1 + shortest_distance).
    Returns a value in (0, 1] for exposed nodes, 0.0 for unexposed.
    Self-paths are excluded.
    """
    if node_name not in G:
        return 0.0

    total = 0.0
    for n, d in G.nodes(data=True):
        if n == node_name:
            continue
        weight = _ENTRY_WEIGHTS.get(d.get("kind", ""), 0.0)
        if weight == 0.0:
            continue
        if nx.has_path(G, n, node_name):
            dist = nx.shortest_path_length(G, n, node_name)
            total += weight * (1.0 / (1.0 + dist))

    # Normalise to (0, 1] — cap at 1.0 so it stays a multiplier
    return min(1.0, total)


def is_exposed(G: nx.DiGraph, node_name: str) -> bool:
    """Boolean convenience wrapper around exposure_score."""
    return exposure_score(G, node_name) > 0.0


def get_exposure_path(G: nx.DiGraph, node_name: str) -> Optional[List[str]]:
    """Returns the shortest path from an entry point to the node, if exposed."""
    if node_name not in G:
        return None

    entry_points = [
        n for n, d in G.nodes(data=True)
        if d.get("kind") in ("user", "external")
        and n != node_name
    ]

    shortest: Optional[List[str]] = None
    for entry in entry_points:
        if nx.has_path(G, entry, node_name):
            path = nx.shortest_path(G, entry, node_name)
            if shortest is None or len(path) < len(shortest):
                shortest = path

    return shortest


def attach_findings(G: nx.DiGraph, findings: List[Finding]) -> List[Finding]:
    """Maps findings to graph nodes and attaches exposure information."""
    for f in findings:
        loc = f.location
        if loc in G:
            f.node = loc
            f.exposed = is_exposed(G, loc)
        else:
            f.node = None
            f.exposed = False
    return findings

