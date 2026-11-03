import pytest
import networkx as nx
from blastradius.models import Principal, Statement, Finding
from blastradius.graph_builder import build_graph
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings
from blastradius.scoring import blast_radius, score_all_findings, ScoringConfig
from blastradius.ranking import rank_by_blast_radius, rank_by_scanner_severity, generate_ranking_comparison


def test_headline_claim_rank_inversion():
    """
    Sanity test for the paper's central thesis:
    Open trust on dev-role (scanner severity: MEDIUM) MUST rank above
    wildcard action on isolated-admin (scanner severity: HIGH).
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
        trust=["*"],  # open trust (scanner MEDIUM)
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
        trust=[],  # isolated (scanner HIGH)
    )

    resources = [{"name": "prod-customer-db", "type": "aws_db_instance"}]
    principals = [alice, dev_role, admin_role, isolated_admin]

    G = build_graph(principals, resources)
    findings = detect_misconfigurations(principals)
    attached = attach_findings(G, findings)

    cfg = ScoringConfig(gamma=0.8, w_count=1.0, w_sensitivity=1.0, exposed_epsilon=0.05)
    scored = score_all_findings(G, attached, cfg)

    # Traditional scanner ranking: isolated-admin (HIGH) ranks ABOVE dev-role (MEDIUM)
    trad_ranked = rank_by_scanner_severity(attached)
    trad_top = trad_ranked[0]
    assert trad_top.location == "isolated-admin"
    assert trad_top.scanner_severity == "HIGH"

    # Blast-radius ranking: dev-role (reaching prod-customer-db) ranks ABOVE isolated-admin!
    br_ranked = rank_by_blast_radius(scored)
    br_top = br_ranked[0]

    dev_open_trust = next(
        s for s in scored if s.finding.location == "dev-role" and s.finding.rule == "open_trust"
    )
    isolated_wildcard = next(
        s for s in scored if s.finding.location == "isolated-admin" and s.finding.rule == "wildcard_action"
    )

    # Assert headline claim: dev-role score is significantly higher than isolated-admin score
    assert dev_open_trust.score > isolated_wildcard.score
    assert dev_open_trust.exposed is True
    assert isolated_wildcard.exposed is False

    # Comparison comparison generates proper rank deltas
    comparison = generate_ranking_comparison(scored)
    dev_entry = next(c for c in comparison if c["location"] == "dev-role" and c["rule"] == "open_trust")
    isolated_entry = next(c for c in comparison if c["location"] == "isolated-admin")

    assert dev_entry["br_rank"] < isolated_entry["br_rank"]

