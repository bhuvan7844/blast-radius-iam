from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class Statement:
    effect: str                 # "Allow" / "Deny"
    actions: List[str]          # e.g. ["s3:GetObject", "iam:*"]
    resources: List[str]        # e.g. ["arn:aws:s3:::prod-db/*", "*"]
    source: str = ""            # policy name/file source

@dataclass
class Principal:
    name: str
    kind: str                   # "user" | "role"
    arn: str
    statements: List[Statement] = field(default_factory=list)   # permissions HAS
    trust: List[str] = field(default_factory=list)              # roles only: who may assume it

@dataclass
class Finding:
    id: str                     # e.g. "F001"
    rule: str                   # "wildcard_action" | "wildcard_resource" | "open_trust" | "excess_permission"
    scanner_severity: str       # "HIGH" | "MEDIUM" | "LOW"
    location: str               # node name (user/role) the finding sits on
    statement_ref: Optional[int] = None   # statement index
    detail: str = ""

@dataclass
class ScoredFinding:
    finding: Finding
    reachable: Dict[str, int]   # {resource_name: distance}
    score: float
    exposed: bool               # can an entry point reach this node?