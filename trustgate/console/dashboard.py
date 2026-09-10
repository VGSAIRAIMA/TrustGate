"""TrustGate Rich Terminal Console Dashboard (Stage 16).

Provides live colored terminal panels for MCP tool integrity verification,
displaying server identity, risk scores, policy decisions, and line-level diffs.

All output is explicitly directed to stderr so stdout remains pure JSON-RPC
for standard MCP clients (Claude Desktop / Claude Code / Antigravity).
Zero browser / web-server dependencies.
"""

from io import StringIO
from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from trustgate.mechanisms.output_sanitizer import SanitizeResult, SanitizerAction
from trustgate.policy.engine import PolicyAction, PolicyDecision

# Default console writing to stderr to protect stdout JSON-RPC channel
default_console = Console(stderr=True)


def get_decision_color(action: PolicyAction | str) -> str:
    """Return color name for policy actions: green for ALLOW, yellow for HOLD, red for BLOCK."""
    act_str = str(action).upper()
    if "ALLOW" in act_str:
        return "green"
    elif "HOLD" in act_str:
        return "yellow"
    elif "BLOCK" in act_str:
        return "red"
    return "cyan"


def format_signals_table(signals: dict[str, Any]) -> Table:
    """Format active security signals into a clean tabular display."""
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
    table.add_column("Indicator", style="bold")
    table.add_column("Status")

    if "registry_flagged" in signals:
        status = "[red]FLAGGED (typosquat/mismatch)[/red]" if signals["registry_flagged"] else "[green]CLEAN[/green]"
        table.add_row("Registry Check:", status)

    if "fingerprint_changed" in signals:
        status = "[yellow]MUTATED (diff detected)[/yellow]" if signals["fingerprint_changed"] else "[green]MATCH (pinned hash)[/green]"
        table.add_row("Fingerprint Vault:", status)

    if "regex_flagged" in signals:
        status = "[red]TRIPPED (injection signature)[/red]" if signals["regex_flagged"] else "[green]CLEAN[/green]"
        table.add_row("Regex Patterns:", status)

    if "llm_flagged" in signals:
        if signals["llm_flagged"]:
            conf = signals.get("llm_confidence", 0.0)
            status = f"[red]MALICIOUS ({conf:.0%} confidence)[/red]"
        else:
            status = "[green]CLEAN / INCONCLUSIVE[/green]"
        table.add_row("LLM Semantic:", status)

    if "is_output_injection" in signals:
        status = "[red]INJECTION DETECTED[/red]" if signals["is_output_injection"] else "[green]CLEAN[/green]"
        table.add_row("Output Sanitizer:", status)

    return table


def create_decision_panel(
    decision: PolicyDecision,
    server: str = "",
    tool_name: str = "",
) -> Panel:
    """Construct a Rich Panel representing a TrustGate policy decision.

    Color-coded:
    - ALLOW: green
    - HOLD: yellow
    - BLOCK: red
    """
    server_name = server or decision.server or "unknown-server"
    t_name = tool_name or decision.tool_name or ""
    color = get_decision_color(decision.action)

    elements: list[Any] = []

    # 1. Summary Meta Table
    meta_table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
    meta_table.add_column("Key", style="dim")
    meta_table.add_column("Value", style="bold")

    meta_table.add_row("Server:", f"[cyan]{server_name}[/cyan]")
    if t_name:
        meta_table.add_row("Tool:", f"[white]{t_name}[/white]")
    meta_table.add_row("Risk Score:", f"[{color}]{decision.risk_score} / 100[/{color}]")
    meta_table.add_row(
        "Decision:",
        f"[bold {color}]{decision.action.value}[/bold {color}]",
    )

    elements.append(meta_table)
    elements.append(Text(""))

    # 2. Security Signals Breakdown
    if decision.signals:
        elements.append(Text("Inspection Signals:", style="bold underline"))
        elements.append(format_signals_table(decision.signals))
        elements.append(Text(""))

    # 3. Specific Reasons
    if decision.reasons:
        elements.append(Text("Policy Triggers:", style="bold underline"))
        for reason in decision.reasons:
            elements.append(Text(f"  • {reason}", style=f"{color}"))
        elements.append(Text(""))

    # 4. Unified Diff (if mutation occurred)
    if decision.diff and decision.diff.strip():
        elements.append(Text("Manifest Mutation Diff:", style="bold underline"))
        syntax_diff = Syntax(
            decision.diff.strip(),
            "diff",
            theme="monokai",
            line_numbers=False,
            word_wrap=True,
        )
        diff_panel = Panel(
            syntax_diff,
            title="[yellow]Contract Changes[/yellow]",
            border_style="yellow",
            expand=True,
        )
        elements.append(diff_panel)

    title = f"🛡️  [bold]TrustGate Security Policy — [{color}]{decision.action.value}[/{color}][/bold]"
    return Panel(
        Group(*elements),
        title=title,
        border_style=color,
        padding=(1, 2),
        expand=False,
    )


def create_sanitization_panel(
    result: SanitizeResult,
    server: str = "",
    tool_name: str = "",
) -> Panel:
    """Construct a Rich Panel representing an output sanitization decision."""
    server_name = server or "unknown-server"
    t_name = tool_name or "tool_call"

    if result.passed:
        color = "green"
        badge = "PASS"
    elif result.was_redacted:
        color = "yellow"
        badge = "REDACTED"
    else:
        color = "red"
        badge = "ESCALATE FOR REVIEW"

    elements: list[Any] = []

    meta_table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
    meta_table.add_column("Key", style="dim")
    meta_table.add_column("Value", style="bold")
    meta_table.add_row("Server:", f"[cyan]{server_name}[/cyan]")
    meta_table.add_row("Tool Output:", f"[white]{t_name}[/white]")
    meta_table.add_row("Action:", f"[bold {color}]{badge}[/bold {color}]")
    meta_table.add_row("Risk Score:", f"[{color}]{result.risk_score} / 100[/{color}]")

    elements.append(meta_table)
    elements.append(Text(""))

    if result.reason:
        elements.append(Text(f"Details: {result.reason}", style=color))
        elements.append(Text(""))

    if result.redacted_spans:
        elements.append(Text("Redacted Injections:", style="bold underline"))
        for span in result.redacted_spans:
            elements.append(Text(f"  [-] {span}", style="red strike"))
        elements.append(Text(""))

    title = f"🧹  [bold]TrustGate Output Sanitizer — [{color}]{badge}[/{color}][/bold]"
    return Panel(
        Group(*elements),
        title=title,
        border_style=color,
        padding=(1, 2),
        expand=False,
    )


def show_event(
    decision: PolicyDecision,
    server: str = "",
    tool_name: str = "",
    console: Console | None = None,
) -> Panel:
    """Display policy decision panel to console (defaulting to stderr)."""
    c = console or default_console
    panel = create_decision_panel(decision, server=server, tool_name=tool_name)
    c.print(panel)
    return panel


def show_sanitization_event(
    result: SanitizeResult,
    server: str = "",
    tool_name: str = "",
    console: Console | None = None,
) -> Panel:
    """Display output sanitization panel to console (defaulting to stderr)."""
    c = console or default_console
    panel = create_sanitization_panel(result, server=server, tool_name=tool_name)
    c.print(panel)
    return panel
