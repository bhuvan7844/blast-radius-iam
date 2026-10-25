import networkx as nx
from blastradius.graph_builder import build_graph
from blastradius.models import Principal, Statement


class DummyResource:

  def __init__(self, name):
    self.name = name


def test_worked_example_path():
  # Define test entities
  alice = Principal(
      name="alice",
      kind="user",
      arn="arn:aws:iam::123:user/alice",
      statements=[],
  )

  dev_role = Principal(
      name="dev-role",
      kind="role",
      arn="arn:aws:iam::123:role/dev-role",
      statements=[
          Statement(
              effect="Allow",
              actions=["iam:AttachRolePolicy"],
              resources=["*"],
          )
      ],
      trust=["arn:aws:iam::123:user/alice"],
  )

  admin_role = Principal(
      name="admin-role",
      kind="role",
      arn="arn:aws:iam::123:role/admin-role",
      statements=[
          Statement(
              effect="Allow",
              actions=["s3:*"],
              resources=["arn:aws:s3:::prod-db/*"],
          )
      ],
      trust=[],  # Isolated trust
  )

  prod_db = DummyResource("arn:aws:s3:::prod-db/data")

  principals = [alice, dev_role, admin_role]
  resources = [prod_db]

  def dummy_sensitivity(name):
    return 10 if "prod" in name else 1

  # Build graph
  G = build_graph(principals, resources, dummy_sensitivity)

  # Assert paths exist
  assert nx.has_path(G, "alice", "dev-role")  # via can_assume
  assert nx.has_path(
      G, "dev-role", "admin-role"
  )  # via can_escalate (AttachRolePolicy)
  assert nx.has_path(G, "admin-role", prod_db.name)  # via can_access
  assert nx.has_path(G, "alice", prod_db.name)  # Full attack path from user


def test_isolated_node_has_no_incoming_edges():
  isolated_role = Principal(
      name="isolated-role",
      kind="role",
      arn="arn:aws:iam::123:role/isolated-role",
      statements=[],
      trust=[],
  )

  G = build_graph([isolated_role], [], lambda x: 1)
  assert G.in_degree("isolated-role") == 0