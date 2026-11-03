from typing import List, Dict, Any, Optional
import networkx as nx
from blastradius.models import Finding


def is_exposed(G: nx.DiGraph, node_name: str) -> bool:
    """
    Checks if a node is reachable from any entry point.
    Entry points are external/internet nodes or user identities.
    """
    if node_name not in G:
        return False

    entry_points = [
        n for n, d in G.nodes(data=True)
        if d.get("kind") in ("user", "external")
    ]

    for entry in entry_points:
        if nx.has_path(G, entry, node_name):
            return True
    return False


def get_exposure_path(G: nx.DiGraph, node_name: str) -> Optional[List[str]]:
    """Returns the shortest path from an entry point to the node, if exposed."""
    if node_name not in G:
        return None

    entry_points = [
        n for n, d in G.nodes(data=True)
        if d.get("kind") in ("user", "external")
    ]

    shortest: Optional[List[str]] = None
    for entry in entry_points:
        if nx.has_path(G, entry, node_name):
            path = nx.shortest_path(G, entry, node_name)
            if shortest is None or len(path) < len(shortest):
                shortest = path

    return shortest


def attach_findings(G: nx.DiGraph, findings: List[Finding]) -> List[Finding]:
    """
    Maps findings to graph nodes, verifying node existence and attaching
    exposure information.
    """
    attached: List[Finding] = []

    for f in findings:
        loc = f.location
        if loc in G:
            f.node = loc
            f.exposed = is_exposed(G, loc)
        else:
            f.node = None
            f.exposed = False
        attached.append(f)

    return attached

