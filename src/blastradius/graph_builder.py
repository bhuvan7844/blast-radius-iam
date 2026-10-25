from fnmatch import fnmatch
import networkx as nx
from blastradius.escalation import add_escalation_edges


def action_matches(pattern: str, action: str) -> bool:
  """Matches action patterns like 's3:*' against 's3:GetObject'."""
  return fnmatch(action.lower(), pattern.lower())


def resource_matches(pattern: str, resource_name: str) -> bool:
  """Matches resource ARN patterns against resource names/ARNs."""
  return fnmatch(resource_name.lower(), pattern.lower())


def allowed(principal, resource) -> bool:
  """Returns True if principal has an Allow statement for resource without an overriding Deny."""
  has_allow = False

  # Check Allow statements
  for st in principal.statements:
    if st.effect == "Allow":
      # Simplified match for data access actions and resource matching
      for r_pattern in st.resources:
        if resource_matches(r_pattern, resource.name) or r_pattern == "*":
          has_allow = True
          break

  if not has_allow:
    return False

  # Check Deny statements (Explicit Deny overrides Allow)
  for st in principal.statements:
    if st.effect == "Deny":
      for r_pattern in st.resources:
        if resource_matches(r_pattern, resource.name) or r_pattern == "*":
          return False

  return True


def lookup_by_arn(arn: str, principals: list):
  """Finds a principal object matching a given ARN or name."""
  for p in principals:
    if p.arn == arn or p.name == arn:
      return p
  return None


def build_graph(principals: list, resources: list, sensitivity_fn) -> nx.DiGraph:
  """Constructs the directed graph representing access, trust, and escalation paths."""
  G = nx.DiGraph()

  # 1. Add special entry point for external/internet access
  G.add_node("EXTERNAL", kind="external")

  # 2. Add Principal nodes (Users & Roles)
  for p in principals:
    G.add_node(p.name, kind=p.kind, obj=p)

  # 3. Add Resource nodes
  for r in resources:
    G.add_node(r.name, kind="resource", sensitivity=sensitivity_fn(r.name))

  # 4. Add 'can_access' edges (Principal -> Resource)
  for p in principals:
    for r in resources:
      if allowed(p, r):
        G.add_edge(p.name, r.name, etype="can_access")

  # 5. Add 'can_assume' edges based on Trust Policies
  for role in [p for p in principals if p.kind == "role"]:
    for who in role.trust:
      if who == "*":
        G.add_edge("EXTERNAL", role.name, etype="can_assume")
        for u in principals:
          if u.name != role.name:
            G.add_edge(u.name, role.name, etype="can_assume")
      else:
        src = lookup_by_arn(who, principals)
        if src:
          G.add_edge(src.name, role.name, etype="can_assume")

  # 6. Add privilege escalation edges
  add_escalation_edges(G, principals)

  return G