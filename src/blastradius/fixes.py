from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any, Optional
import networkx as nx
from blastradius.models import Finding
from blastradius.scoring import blast_radius, ScoringConfig, load_scoring_config


@dataclass
class Fix:
    finding_id: str
    target_node: str
    action_type: str            # "tighten_trust" | "remove_escalation" | "narrow_permissions"
    description: str
    edges_to_remove: List[Tuple[str, str]] = field(default_factory=list)


def generate_candidate_fixes(G: nx.DiGraph, findings: List[Finding]) -> List[Fix]:
    """
    Synthesizes concrete remediation fixes for each misconfiguration:
    - open_trust: removes incoming can_assume edges from EXTERNAL/users
    - excess_permission: removes outgoing can_escalate edges from the node
    - wildcard_action / wildcard_resource: removes broad can_access edges
    """
    fixes: List[Fix] = []

    for f in findings:
        loc = f.location
        if loc not in G:
            continue

        if f.rule == "open_trust":
            # Remove all incoming can_assume edges to this role
            edges = [
                (u, v) for u, v, d in G.in_edges(loc, data=True)
                if d.get("etype") == "can_assume"
            ]
            if edges:
                fixes.append(Fix(
                    finding_id=f.id,
                    target_node=loc,
                    action_type="tighten_trust",
                    description=f"Tighten trust policy on '{loc}': restrict Principal to specific authorized accounts/roles (cuts {len(edges)} assume edges)",
                    edges_to_remove=edges,
                ))

        elif f.rule == "excess_permission":
            # Remove outgoing escalation edges
            edges = [
                (u, v) for u, v, d in G.out_edges(loc, data=True)
                if d.get("etype") == "can_escalate"
            ]
            if edges:
                fixes.append(Fix(
                    finding_id=f.id,
                    target_node=loc,
                    action_type="remove_escalation",
                    description=f"Remove privilege escalation permissions from '{loc}' (e.g. PassRole/CreatePolicyVersion; cuts {len(edges)} escalation paths)",
                    edges_to_remove=edges,
                ))

        elif f.rule in ("wildcard_action", "wildcard_resource"):
            # Direct resource access edges from this node
            edges = [
                (u, v) for u, v, d in G.out_edges(loc, data=True)
                if d.get("etype") == "can_access"
            ]
            if edges:
                fixes.append(Fix(
                    finding_id=f.id,
                    target_node=loc,
                    action_type="narrow_permissions",
                    description=f"Scope down wildcard permissions on '{loc}' to minimal least-privilege actions/resources",
                    edges_to_remove=edges,
                ))

    return fixes


def apply_fix(G: nx.DiGraph, fix: Fix) -> nx.DiGraph:
    """Returns a copy of graph G with the fix applied (edges removed)."""
    H = G.copy()
    for u, v in fix.edges_to_remove:
        if H.has_edge(u, v):
            H.remove_edge(u, v)
    return H


def total_environment_risk(
    G: nx.DiGraph,
    findings: List[Finding],
    cfg: Optional[ScoringConfig] = None,
) -> float:
    """Calculates the sum of blast-radius scores across all findings in the current graph."""
    if cfg is None:
        cfg = load_scoring_config()
    total = sum(blast_radius(G, f, cfg).score for f in findings)
    return round(total, 2)


def compute_fix_reduction(
    G: nx.DiGraph,
    findings: List[Finding],
    fix: Fix,
    cfg: Optional[ScoringConfig] = None,
) -> float:
    """Measures the exact reduction in total environment risk if a fix is applied."""
    if cfg is None:
        cfg = load_scoring_config()
    before = total_environment_risk(G, findings, cfg)
    after = total_environment_risk(apply_fix(G, fix), findings, cfg)
    return round(max(0.0, before - after), 2)


def greedy_best_k_fixes(
    G: nx.DiGraph,
    findings: List[Finding],
    k: int = 3,
    cfg: Optional[ScoringConfig] = None,
) -> Dict[str, Any]:
    """
    Greedy fix selection algorithm:
    Sequentially picks the fix that yields the largest marginal risk reduction,
    re-evaluating graph reachability after each choice to account for overlapping paths.
    """
    if cfg is None:
        cfg = load_scoring_config()

    candidates = generate_candidate_fixes(G, findings)
    initial_risk = total_environment_risk(G, findings, cfg)
    current_risk = initial_risk
    current_G = G.copy()

    chosen_fixes = []
    step_history = []

    for step in range(k):
        if not candidates or current_risk <= 0:
            break

        # Evaluate marginal reduction for each candidate on current graph
        best_fix: Optional[Fix] = None
        best_reduction = -1.0

        for fix in candidates:
            red = compute_fix_reduction(current_G, findings, fix, cfg)
            if red > best_reduction:
                best_reduction = red
                best_fix = fix

        if best_fix is None or best_reduction <= 0:
            break

        # Apply best fix
        current_G = apply_fix(current_G, best_fix)
        new_risk = total_environment_risk(current_G, findings, cfg)
        marginal_drop = round(current_risk - new_risk, 2)
        current_risk = new_risk

        pct_reduction = round((marginal_drop / initial_risk * 100), 1) if initial_risk > 0 else 0.0

        chosen_fixes.append(best_fix)
        step_history.append({
            "step": step + 1,
            "fix": best_fix,
            "risk_reduction": marginal_drop,
            "risk_remaining": current_risk,
            "percent_gain": pct_reduction,
        })

        candidates = [c for c in candidates if c.finding_id != best_fix.finding_id]

    total_pct_reduction = round(
        ((initial_risk - current_risk) / initial_risk * 100), 1
    ) if initial_risk > 0 else 0.0

    return {
        "initial_risk": initial_risk,
        "final_risk": current_risk,
        "total_reduction": round(initial_risk - current_risk, 2),
        "total_percent_reduction": total_pct_reduction,
        "chosen_fixes": chosen_fixes,
        "steps": step_history,
        "remediated_graph": current_G,
    }

