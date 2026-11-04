import argparse
import sys
import pathlib
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import networkx as nx

# Ensure package import works when running as script
_SRC_DIR = pathlib.Path(__file__).resolve().parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from blastradius.models import Principal, Statement
from blastradius.graph_builder import build_graph, load_sensitivity_config
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings
from blastradius.scoring import score_all_findings, load_scoring_config
from blastradius.ranking import rank_by_blast_radius, generate_ranking_comparison
from blastradius.fixes import greedy_best_k_fixes, total_environment_risk
from blastradius.parser_terraform import parse_terraform_file

console = Console()

def _run_pipeline(principals, resources, budget=None):
    """Run the full analysis pipeline on given principals/resources.
    Returns a dict with useful objects for further reporting.
    """
    sens_cfg = load_sensitivity_config()
    G = build_graph(principals, resources, sens_cfg)
    raw_findings = detect_misconfigurations(principals)
    attached = attach_findings(G, raw_findings)
    scoring_cfg = load_scoring_config()
    scored = score_all_findings(G, attached, scoring_cfg)
    ranking = generate_ranking_comparison(scored)
    init_risk = total_environment_risk(G, attached, scoring_cfg)
    fix_results = None
    if budget is not None:
        fix_results = greedy_best_k_fixes(G, attached, k=budget, cfg=scoring_cfg)
    return {
        "graph": G,
        "findings": attached,
        "scored": scored,
        "ranking": ranking,
        "initial_risk": init_risk,
        "fix_results": fix_results,
    }

def cmd_analyze(args):
    principals, resources = parse_terraform_file(args.path)
    result = _run_pipeline(principals, resources)
    console.print(Panel("[bold cyan]Analysis Complete[/bold cyan]", border_style="cyan"))
    console.print(f"Graph nodes: {len(result['graph'])}, edges: {len(result['graph'].edges)}")

def cmd_score(args):
    principals, resources = parse_terraform_file(args.path)
    result = _run_pipeline(principals, resources)
    # Show ranking table
    rank_table = Table(title="Blast‑Radius Ranking", show_header=True, header_style="bold magenta")
    rank_table.add_column("BR Rank", style="cyan", justify="center")
    rank_table.add_column("Finding ID", style="dim")
    rank_table.add_column("Rule", style="yellow")
    rank_table.add_column("BR Score", style="bold red", justify="right")
    for row in result["ranking"]:
        rank_table.add_row(str(row["br_rank"]), row["id"], row["rule"], f"{row['br_score']:.2f}")
    console.print(rank_table)

def cmd_fix(args):
    principals, resources = parse_terraform_file(args.path)
    result = _run_pipeline(principals, resources, budget=args.budget)
    if not result["fix_results"]:
        console.print("[red]No fixes generated[/red]")
        return
    fix = result["fix_results"]
    fix_table = Table(title="Greedy Top‑K Fixes", show_header=True, header_style="green")
    fix_table.add_column("Step", justify="center")
    fix_table.add_column("Action Type")
    fix_table.add_column("Target Node")
    fix_table.add_column("Detail")
    fix_table.add_column("Risk Drop", justify="right")
    for step in fix["steps"]:
        f = step["fix"]
        fix_table.add_row(str(step["step"]), f.action_type, f.target_node, f.description, f"-{step['risk_reduction']:.2f}")
    console.print(fix_table)
    console.print(f"Initial risk: {fix['initial_risk']:.2f}, final risk: {fix['final_risk']:.2f}")

def cmd_demo(_):
    # Re‑use existing demo logic from the repository root (demo.py)
    try:
        import pathlib, sys
        # Add the repository root (two levels up from this file) to sys.path
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        from demo import run_full_pipeline_demo
        run_full_pipeline_demo()
    except Exception as e:
        console.print(f"[red]Demo failed: {e}[/red]")

def cmd_benchmark(_):
    """Run synthetic benchmark cases and show Blast‑Radius advantage.
    This mirrors the Phase 8‑9 loop in demo.py but prints a concise summary
    for each case, including total risk, number of exposed findings, and
    top‑3 ranking entries.
    """
    import pathlib
    from blastradius.parser_terraform import parse_terraform_file
    synthetic_root = pathlib.Path(__file__).resolve().parents[2] / "data" / "synthetic"
    for case_dir in sorted([d for d in synthetic_root.iterdir() if d.is_dir() and d.name not in ["terraform_example"]]):
        console.print(f"\n[bold magenta]Benchmark: {case_dir.name}[/bold magenta]")
        tf_files = list(case_dir.rglob("*.tf"))
        if not tf_files:
            continue
        principals, resources = parse_terraform_file(str(tf_files[0]))
        result = _run_pipeline(principals, resources)
        # Exposed findings count
        exposed = sum(1 for f in result["findings"] if getattr(f, "exposed", False))
        console.print(f"[bold cyan]Total risk:[/bold cyan] {result['initial_risk']:.2f}, Exposed findings: {exposed}")
        # Top‑3 rankings
        rank_tbl = Table(title="Top Findings", show_header=True, header_style="magenta")
        rank_tbl.add_column("Rank", style="cyan")
        rank_tbl.add_column("Finding ID")
        rank_tbl.add_column("Rule")
        rank_tbl.add_column("Score", justify="right")
        for row in result["ranking"][:3]:
            rank_tbl.add_row(str(row["br_rank"]), row["id"], row["rule"], f"{row['br_score']:.2f}")
        console.print(rank_tbl)
    console.print(Panel("[bold green]Benchmark Completed[/bold green]", border_style="green"))


def main():
    parser = argparse.ArgumentParser(prog="blastradius", description="Blast‑Radius IAM analysis CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Parse input and build graph")
    analyze.add_argument("path", help="Path to Terraform or JSON file")
    analyze.set_defaults(func=cmd_analyze)

    score = subparsers.add_parser("score", help="Run full analysis and show rankings")
    score.add_argument("path", help="Path to Terraform or JSON file")
    score.set_defaults(func=cmd_score)

    fix = subparsers.add_parser("fix", help="Run analysis and propose greedy fixes")
    fix.add_argument("path", help="Path to Terraform or JSON file")
    fix.add_argument("--budget", type=int, default=2, help="Number of top‑k fixes to propose")
    fix.set_defaults(func=cmd_fix)

    demo = subparsers.add_parser("demo", help="Run the end‑to‑end demo (phases 1‑7)")
    demo.set_defaults(func=cmd_demo)

    benchmark = subparsers.add_parser("benchmark", help="Run synthetic benchmark suite (Phase 8‑9)")
    benchmark.set_defaults(func=cmd_benchmark)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()


