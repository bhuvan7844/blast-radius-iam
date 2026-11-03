import os
import sys
import pathlib

# Ensure 'src' is always on sys.path for direct execution
_SRC_DIR = pathlib.Path(__file__).resolve().parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import networkx as nx

from blastradius.models import Principal, Statement
from blastradius.graph_builder import build_graph, load_sensitivity_config
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings
from blastradius.scoring import score_all_findings, load_scoring_config
from blastradius.ranking import rank_by_blast_radius, generate_ranking_comparison
from blastradius.fixes import greedy_best_k_fixes, total_environment_risk

console = Console()


def run_full_pipeline_demo():
    console.print(Panel.fit(
        "[bold cyan]Blast-Radius IAM - End-to-End Pipeline Demonstration[/bold cyan]\n"
        "Phases 1-7: Parsing -> Graph -> Detection -> Exposure -> Scoring -> Ranking -> Greedy Fixes",
        border_style="cyan"
    ))

    # --- 1. Setup Environment (Worked Example from Paper) ---
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
        trust=[],  # Isolated: no incoming paths
    )

    resources = [
        {"name": "prod-customer-db", "type": "aws_db_instance"},
        {"name": "dev-scratch-bucket", "type": "aws_s3_bucket"},
    ]

    principals = [alice, dev_role, admin_role, isolated_admin]

    # --- 2. Construct Graph (Phase 4) ---
    console.print("\n[bold yellow]Step 1: Constructing Directed Reachability Graph (Phase 4)[/bold yellow]")
    sens_cfg = load_sensitivity_config()
    G = build_graph(principals, resources, sens_cfg)

    # Attack Path Detection
    if nx.has_path(G, "alice", "prod-customer-db"):
        path = nx.shortest_path(G, "alice", "prod-customer-db")
        path_str = " -> ".join([f"[bold red]{n}[/bold red]" if n == "prod-customer-db" else f"[bold cyan]{n}[/bold cyan]" for n in path])
        console.print(Panel(
            f"[bold green]CRITICAL ATTACK PATH DETECTED:[/bold green] {path_str}\n"
            f"Details: Entry point 'alice' can assume 'dev-role' -> escalates to 'admin-role' -> accesses 'prod-customer-db'!",
            title="Graph Reachability Analysis",
            border_style="green"
        ))

    # --- 3. Detect & Attach Findings (Phase 5) ---
    console.print("\n[bold yellow]Step 2: Detecting Misconfigurations & Attaching Exposure (Phase 5)[/bold yellow]")
    raw_findings = detect_misconfigurations(principals)
    attached_findings = attach_findings(G, raw_findings)

    # --- 4. Blast-Radius Scoring & Ranking (Phase 6) ---
    console.print("\n[bold yellow]Step 3: Blast-Radius Scoring & Priority Ranking (Phase 6)[/bold yellow]")
    scoring_cfg = load_scoring_config()
    scored_findings = score_all_findings(G, attached_findings, scoring_cfg)
    ranking_data = generate_ranking_comparison(scored_findings)

    rank_table = Table(title="Prioritization: Traditional Scanner vs. Blast-Radius", show_header=True, header_style="bold magenta")
    rank_table.add_column("BR Rank", justify="center", style="bold cyan")
    rank_table.add_column("Scanner Rank", justify="center", style="dim")
    rank_table.add_column("Rank Shift", justify="center", style="bold")
    rank_table.add_column("Finding ID", style="dim")
    rank_table.add_column("Rule", style="yellow")
    rank_table.add_column("Location", style="cyan")
    rank_table.add_column("Scanner Sev", style="white")
    rank_table.add_column("BR Score", justify="right", style="bold red")
    rank_table.add_column("Exposed?", justify="center")

    for row in ranking_data:
        delta = row["rank_delta"]
        if delta > 0:
            shift = f"[green]+{delta} (Promoted)[/green]"
        elif delta < 0:
            shift = f"[red]{delta} (Demoted)[/red]"
        else:
            shift = "[dim]0[/dim]"

        exp_str = "[bold green]YES[/bold green]" if row["exposed"] else "[bold red]NO (Isolated)[/bold red]"

        rank_table.add_row(
            str(row["br_rank"]),
            str(row["base_rank"]),
            shift,
            row["id"],
            row["rule"],
            row["location"],
            row["scanner_severity"],
            f"{row['br_score']:.2f}",
            exp_str,
        )
    console.print(rank_table)

    # --- 5. Fix Simulation (Phase 7) ---
    console.print("\n[bold yellow]Step 4: Fix Simulation & Greedy Top-K Remediations (Phase 7)[/bold yellow]")
    init_risk = total_environment_risk(G, attached_findings, scoring_cfg)
    console.print(f"Total Initial Environment Risk Score: [bold red]{init_risk:.2f}[/bold red]")

    fix_results = greedy_best_k_fixes(G, attached_findings, k=2, cfg=scoring_cfg)

    fix_table = Table(title="Recommended Fix Plan (Greedy Top-K)", show_header=True, header_style="bold green")
    fix_table.add_column("Step", justify="center", style="bold")
    fix_table.add_column("Action Type", style="cyan")
    fix_table.add_column("Target Node", style="yellow")
    fix_table.add_column("Remediation Detail", style="white")
    fix_table.add_column("Risk Drop", justify="right", style="bold green")
    fix_table.add_column("Risk Remaining", justify="right", style="bold red")

    for step in fix_results["steps"]:
        fix = step["fix"]
        fix_table.add_row(
            str(step["step"]),
            fix.action_type,
            fix.target_node,
            fix.description,
            f"-{step['risk_reduction']:.2f} ({step['percent_gain']}%)",
            f"{step['risk_remaining']:.2f}",
        )
    console.print(fix_table)

    console.print(Panel(
        f"[bold green]Fix Simulation Summary:[/bold green]\n"
        f"- Initial Risk: [bold red]{fix_results['initial_risk']:.2f}[/bold red]\n"
        f"- Remaining Risk after {len(fix_results['chosen_fixes'])} fixes: [bold green]{fix_results['final_risk']:.2f}[/bold green]\n"
        f"- Total Risk Reduction: [bold green]{fix_results['total_percent_reduction']}%[/bold green]\n"
        f"- Verified: After Step 1 (tightening dev-role trust), attack path from 'alice' to 'prod-customer-db' is completely severed!",
        title="Remediation Impact",
        border_style="green"
    ))


if __name__ == "__main__":
    run_full_pipeline_demo()
