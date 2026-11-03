import pytest
import networkx as nx
from blastradius.models import Principal, Statement
from blastradius.graph_builder import build_graph
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings
from blastradius.scoring import ScoringConfig
from blastradius.fixes import (
    generate_candidate_fixes,
    apply_fix,
    total_environment_risk,
    compute_fix_reduction,
    greedy_best_k_fixes,
)


def test_fix_simulation_worked_example():
    """
    Validates that fix simulation correctly targets the open trust policy
    on dev-role and substantially reduces the environment risk.
    """
    alice = Principal(
        name="alice",
        kind="user",
        arn="arn:aws:iam::123:user/alice",
        statements=[],
        trust=[],
    )

    dev_role = Principal(
        name="dev-role",
        kind="role",
        arn="arn:aws:iam::123:role/dev-role",
        statements=[
            Statement(
                effect="Allow",
                actions=["iam:PassRole"],
                resources=["arn:aws:iam::123:role/admin-role"],
            ),
            Statement(
                effect="Allow",
                actions=["lambda:CreateFunction"],
                resources=["*"],
            ),
        ],
        trust=["*"],  # open trust
    )

    admin_role = Principal(
        name="admin-role",
        kind="role",
        arn="arn:aws:iam::123:role/admin-role",
        statements=[
            Statement(
                effect="Allow",
                actions=["rds:*"],
                resources=["arn:aws:rds:::prod-customer-db"],
            )
        ],
        trust=["arn:aws:iam::123:role/dev-role"],
    )

    resources = [{"name": "prod-customer-db", "type": "aws_db_instance"}]
    principals = [alice, dev_role, admin_role]

    G = build_graph(principals, resources)
    findings = detect_misconfigurations(principals)
    attached = attach_findings(G, findings)

    cfg = ScoringConfig(gamma=0.8, w_count=1.0, w_sensitivity=1.0, exposed_epsilon=0.05)
    initial_risk = total_environment_risk(G, attached, cfg)
    assert initial_risk > 0

    # Generate candidate fixes
    fixes = generate_candidate_fixes(G, attached)
    assert len(fixes) > 0

    # Run greedy top-k selection for budget k=1
    result = greedy_best_k_fixes(G, attached, k=1, cfg=cfg)

    assert len(result["chosen_fixes"]) == 1
    top_fix = result["chosen_fixes"][0]

    # The top fix should target dev-role
    assert top_fix.target_node == "dev-role"
    assert result["total_percent_reduction"] > 0
    assert result["final_risk"] < initial_risk

    # Remediated graph should no longer allow alice to reach prod-customer-db
    H = result["remediated_graph"]
    assert not nx.has_path(H, "alice", "prod-customer-db")

