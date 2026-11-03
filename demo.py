import os
import sys
import pathlib

# Ensure 'src' is always on sys.path for direct script execution
_SRC_DIR = pathlib.Path(__file__).resolve().parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import networkx as nx

from blastradius.models import Principal, Statement
from blastradius.graph_builder import build_graph, load_sensitivity_config
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings, get_exposure_path
from blastradius.parser_terraform import parse_terraform_file

console = Console()


def run_live_demo():
    console.print(Panel.fit("[bold cyan]Blast-Radius IAM - Live Pipeline Demonstration[/bold cyan]\nPhases 1 to 5: Parsing -> Graph Construction -> Rule Detection -> Exposure Attachment"))

    # 1. Setup Worked Example Principals
    alice = Principal(
        name="alice",
        kind="user",
        arn="arn:aws:iam::123456789012:user/alice",
        statements=[],
        trust=[],
    )

    dev_role = Principal(
        name="dev-role",
        kind="role",
        arn="arn:aws:iam::123456789012:role/dev-role",
        statements=[
            Statement(
                effect="Allow",
                actions=["iam:PassRole"],
                resources=["arn:aws:iam::123456789012:role/admin-role"],
                source="DevPolicy",
            ),
            Statement(
                effect="Allow",
                actions=["lambda:CreateFunction", "lambda:InvokeFunction"],
                resources=["*"],
                source="DevPolicy",
            ),
        ],
        trust=["*"],  # Open trust policy
    )

    admin_role = Principal(
        name="admin-role",
        kind="role",
        arn="arn:aws:iam::123456789012:role/admin-role",
        statements=[
            Statement(
                effect="Allow",
                actions=["rds:*", "s3:*"],
                resources=["arn:aws:rds:::prod-customer-db", "*"],
                source="AdminPolicy",
            )
        ],
        trust=["arn:aws:iam::123456789012:role/dev-role"],
    )

    isolated_admin = Principal(
        name="isolated-admin",
        kind="role",
        arn="arn:aws:iam::123456789012:role/isolated-admin",
        statements=[
            Statement(
                effect="Allow",
                actions=["*"],
                resources=["*"],
                source="SuperAdminPolicy",
            )
        ],
        trust=[],  # No one can assume this role
    )

    resources = [
        {"name": "prod-customer-db", "type": "aws_db_instance"},
        {"name": "dev-scratch-bucket", "type": "aws_s3_bucket"},
    ]

    principals = [alice, dev_role, admin_role, isolated_admin]

    # --- Section A: Display Parsed Principals & Policies ---
    console.print("\n[bold yellow]1. Parsed Principals & Statements:[/bold yellow]")
    princ_table = Table(title="IAM Principals in Environment", show_header=True, header_style="bold magenta")
    princ_table.add_column("Principal Name", style="cyan")
    princ_table.add_column("Kind", style="white")
    princ_table.add_column("Trust Policy", style="yellow")
    princ_table.add_column("Allowed Actions", style="green")

    for p in principals:
        acts = []
        for s in p.statements:
            acts.append(f"{', '.join(s.actions)} on {', '.join(s.resources)}")
        princ_table.add_row(
            p.name,
            p.kind,
            ", ".join(p.trust) if p.trust else "[dim](none)[/dim]",
            "\n".join(acts) if acts else "[dim](none)[/dim]",
        )
    console.print(princ_table)

    # --- Section B: Build Reachability Graph ---
    console.print("\n[bold yellow]2. Constructing Directed Reachability Graph...[/bold yellow]")
    cfg = load_sensitivity_config()
    G = build_graph(principals, resources, cfg)

    graph_table = Table(title="Graph Nodes & Inferred Sensitivities", show_header=True, header_style="bold blue")
    graph_table.add_column("Node Name", style="cyan")
    graph_table.add_column("Node Kind", style="white")
    graph_table.add_column("Sensitivity (1-10)", justify="center", style="bold red")

    for node, data in G.nodes(data=True):
        sens = data.get("sensitivity", "-")
        graph_table.add_row(node, data.get("kind", "unknown"), str(sens))
    console.print(graph_table)

    # Show Edges
    edge_table = Table(title="Graph Relationships / Edges", show_header=True, header_style="bold green")
    edge_table.add_column("Source", style="cyan")
    edge_table.add_column("Relationship", style="bold yellow")
    edge_table.add_column("Target", style="cyan")
    edge_table.add_column("Details / Reason", style="dim white")

    for u, v, data in G.edges(data=True):
        edge_table.add_row(u, f"--[{data.get('etype')}]-->", v, data.get("reason", ""))
    console.print(edge_table)

    # Attack Paths from Alice
    console.print("\n[bold yellow]3. Attack Path Analysis from Entry Point ('alice'):[/bold yellow]")
    if nx.has_path(G, "alice", "prod-customer-db"):
        path = nx.shortest_path(G, "alice", "prod-customer-db")
        path_str = " -> ".join([f"[bold red]{n}[/bold red]" if n == "prod-customer-db" else f"[bold cyan]{n}[/bold cyan]" for n in path])
        console.print(Panel(f"[bold green]CRITICAL PATH FOUND:[/bold green] {path_str}\n"
                            f"Explanation: alice assumes open dev-role -> escalates to admin-role via PassRole+CreateFunction -> reaches crown jewel prod-customer-db!", title="Escalation Chain"))

    # --- Section C: Run Misconfiguration Detector ---
    console.print("\n[bold yellow]4. Running Misconfiguration Detector (including Excess Permissions):[/bold yellow]")
    findings = detect_misconfigurations(principals)

    # --- Section D: Attach Findings & Compute Exposure ---
    attached_findings = attach_findings(G, findings)

    findings_table = Table(title="Detected Findings with Exposure Status", show_header=True, header_style="bold red")
    findings_table.add_column("ID", style="dim")
    findings_table.add_column("Rule", style="bold yellow")
    findings_table.add_column("Scanner Sev", style="magenta")
    findings_table.add_column("Location", style="cyan")
    findings_table.add_column("Exposed?", justify="center", style="bold")
    findings_table.add_column("Detail", style="white")

    for f in attached_findings:
        exp_badge = "[bold green]YES[/bold green]" if f.exposed else "[bold red]NO (Isolated)[/bold red]"
        findings_table.add_row(
            f.id,
            f.rule,
            f.scanner_severity,
            f.location,
            exp_badge,
            f.detail,
        )
    console.print(findings_table)

    console.print(Panel("[bold green]Key Takeaway for Blast-Radius Prioritization:[/bold green]\n"
                        "- Standard scanners label isolated-admin's Action: * as [bold red]HIGH[/bold red], but it is [bold red]NOT exposed[/bold red] (0 incoming attack paths).\n"
                        "- Standard scanners label dev-role's open trust policy as only [bold yellow]MEDIUM[/bold yellow], but it IS [bold green]EXPOSED[/bold green] and enables an escalation path to prod-customer-db!\n"
                        "- Blast-radius scoring (Phase 6) flips this ranking so the real risk is fixed first.", title="Phase 5 Conclusion"))


if __name__ == "__main__":
    run_live_demo()
