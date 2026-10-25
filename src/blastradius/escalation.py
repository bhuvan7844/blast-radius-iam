import networkx as nx

# Define privilege escalation primitives
ESCALATION_RULES = [
    {
        "name": "AttachRolePolicy",
        "actions": ["iam:AttachRolePolicy", "iam:PutRolePolicy"],
        "target_kind": "role",
    },
    {
        "name": "AttachUserPolicy",
        "actions": ["iam:AttachUserPolicy", "iam:PutUserPolicy"],
        "target_kind": "user",
    },
    {
        "name": "UpdateAssumeRolePolicy",
        "actions": ["iam:UpdateAssumeRolePolicy"],
        "target_kind": "role",
    },
]


def has_action(principal, required_action: str) -> bool:
  """Checks if a principal has a specific action allowed in its statements."""
  for st in principal.statements:
    if st.effect == "Allow":
      for act in st.actions:
        if act == "*" or act.lower() == required_action.lower():
          return True
  return False


def add_escalation_edges(G: nx.DiGraph, principals: list):
  """Evaluates principals against known escalation primitives and adds can_escalate edges."""
  for p in principals:
    # 1. Direct role/user policy attachment & assume policy updates
    for rule in ESCALATION_RULES:
      for act in rule["actions"]:
        if has_action(p, act):
          for target in principals:
            if target.kind == rule["target_kind"] and target.name != p.name:
              G.add_edge(p.name, target.name, etype="can_escalate")

    # 2. PassRole + Lambda execution primitive
    if (
        has_action(p, "iam:PassRole")
        and has_action(p, "lambda:CreateFunction")
        and has_action(p, "lambda:InvokeFunction")
    ):
      for target in [target for target in principals if target.kind == "role"]:
        if target.name != p.name:
          G.add_edge(p.name, target.name, etype="can_escalate")

    # 3. PassRole + EC2 RunInstances primitive
    if has_action(p, "iam:PassRole") and has_action(p, "ec2:RunInstances"):
      for target in [target for target in principals if target.kind == "role"]:
        if target.name != p.name:
          G.add_edge(p.name, target.name, etype="can_escalate")