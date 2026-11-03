import pytest
import networkx as nx
from blastradius.models import Principal, Statement
from blastradius.graph_builder import build_graph, get_resource_sensitivity, load_sensitivity_config


def test_sensitivity_scoring():
    cfg = load_sensitivity_config()
    assert get_resource_sensitivity("prod-customer-db", cfg) == 10
    assert get_resource_sensitivity("my-rds-cluster", cfg) == 9
    assert get_resource_sensitivity("dev-test-bucket", cfg) == 2
    assert get_resource_sensitivity("random-other-resource", cfg) == 3


def test_worked_example_graph():
    """
    Tests the paper's headline worked example:
    alice (user) -> dev-role (open trust, PassRole+CreateFunction) -> admin-role -> prod-db
    Also an isolated-admin-role that has no incoming edges.
    """
    # 1. Low-privilege user Alice
    alice = Principal(
        name="alice",
        kind="user",
        arn="arn:aws:iam::123:user/alice",
        statements=[],
        trust=[],
    )

    # 2. dev-role: open trust (*), permissions to PassRole (targeting admin-role) and CreateFunction
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
                actions=["lambda:CreateFunction", "lambda:InvokeFunction"],
                resources=["*"],
            ),
        ],
        trust=["*"],  # open trust
    )

    # 3. admin-role: trusted by lambda service (or assumed via escalation), has full DB access
    admin_role = Principal(
        name="admin-role",
        kind="role",
        arn="arn:aws:iam::123:role/admin-role",
        statements=[
            Statement(
                effect="Allow",
                actions=["s3:*", "rds:*"],
                resources=["arn:aws:rds:::prod-customer-db"],
            )
        ],
        trust=["arn:aws:iam::123:role/dev-role"],
    )

    # 4. isolated-admin-role: high permissions but no incoming edges
    isolated_admin = Principal(
        name="isolated-admin",
        kind="role",
        arn="arn:aws:iam::123:role/isolated-admin",
        statements=[
            Statement(
                effect="Allow",
                actions=["*"],
                resources=["*"],
            )
        ],
        trust=[],  # isolated, no one can assume or pass
    )

    resources = [
        {"name": "prod-customer-db", "type": "aws_db_instance"},
        {"name": "dev-bucket", "type": "aws_s3_bucket"},
    ]

    principals = [alice, dev_role, admin_role, isolated_admin]
    G = build_graph(principals, resources)

    # Verify nodes
    assert "alice" in G
    assert "dev-role" in G
    assert "admin-role" in G
    assert "isolated-admin" in G
    assert "prod-customer-db" in G
    assert "EXTERNAL" in G

    # Open trust creates edge EXTERNAL -> dev-role and alice -> dev-role
    assert G.has_edge("EXTERNAL", "dev-role")
    assert G.has_edge("alice", "dev-role")

    # dev-role has PassRole + CreateFunction -> escalation edge to admin-role
    assert G.has_edge("dev-role", "admin-role")
    assert G[dev_role.name][admin_role.name]["etype"] == "can_escalate"

    # admin-role has access to prod-customer-db
    assert G.has_edge("admin-role", "prod-customer-db")
    assert G[admin_role.name]["prod-customer-db"]["etype"] == "can_access"

    # Whole chain from alice to prod-customer-db must exist!
    assert nx.has_path(G, "alice", "prod-customer-db")
    path = nx.shortest_path(G, "alice", "prod-customer-db")
    assert path == ["alice", "dev-role", "admin-role", "prod-customer-db"]

    # Isolated admin must have 0 incoming edges
    assert G.in_degree("isolated-admin") == 0
    assert not nx.has_path(G, "alice", "isolated-admin")
    assert not nx.has_path(G, "EXTERNAL", "isolated-admin")
