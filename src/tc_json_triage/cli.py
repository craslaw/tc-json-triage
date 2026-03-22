"""CLI entry point for tc-json-triage."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from tc_json_triage.mapping.correlator import correlate_all
from tc_json_triage.output.sarif_annotator import annotate_sarif
from tc_json_triage.output.summary import format_summary_json, format_summary_markdown
from tc_json_triage.parsers.sarif import parse_sarif
from tc_json_triage.parsers.threat_model import parse_threat_model


@click.command()
@click.option(
    "--threat-model",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to .tc.json threat model file.",
)
@click.option(
    "--sarif",
    "sarif_files",
    required=True,
    multiple=True,
    type=click.Path(exists=True),
    help="Path to SARIF scan result file or directory (can be repeated).",
)
@click.option(
    "--output-format",
    type=click.Choice(["summary", "json", "sarif"]),
    default="summary",
    help="Output format (default: summary).",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Output file path (default: stdout).",
)
def main(
    threat_model: str,
    sarif_files: tuple[str, ...],
    output_format: str,
    output_path: str | None,
) -> None:
    """Correlate security scan findings against a threat-composer threat model."""
    # Expand any directory paths to SARIF files within them
    expanded = []
    for p in sarif_files:
        path = Path(p)
        if path.is_dir():
            matches = sorted(path.glob("*.sarif")) + sorted(path.glob("*.sarif.json"))
            if not matches:
                click.echo(f"Warning: no SARIF files found in {p}", err=True)
            expanded.extend(str(m) for m in matches)
        else:
            expanded.append(p)
    sarif_files = tuple(expanded)

    # Parse threat model
    model = parse_threat_model(threat_model)
    click.echo(
        f"Loaded threat model: {len(model.threats)} threats, {len(model.mitigations)} mitigations",
        err=True,
    )

    # Parse all SARIF files
    all_findings = []
    for sarif_path in sarif_files:
        findings = parse_sarif(sarif_path)
        click.echo(f"Parsed {sarif_path}: {len(findings)} findings", err=True)
        all_findings.extend(findings)

    if not all_findings:
        click.echo("No findings to triage.", err=True)
        return

    # Correlate
    results = correlate_all(all_findings, model)

    # Output
    if output_format == "sarif":
        if len(sarif_files) != 1:
            click.echo(
                "Error: SARIF output requires exactly one --sarif input file.",
                err=True,
            )
            sys.exit(1)
        annotated = annotate_sarif(sarif_files[0], results)
        output_text = json.dumps(annotated, indent=2)
    elif output_format == "json":
        output_text = format_summary_json(results)
    else:
        output_text = format_summary_markdown(results)

    if output_path:
        Path(output_path).write_text(output_text)
        click.echo(f"Output written to {output_path}", err=True)
    else:
        click.echo(output_text)


if __name__ == "__main__":
    main()
