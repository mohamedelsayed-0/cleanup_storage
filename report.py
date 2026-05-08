from __future__ import annotations

from datetime import datetime
from pathlib import Path

from scanner import ScanResult
from utils import RISK_REVIEW, RISK_SAFE, bytes_to_human, display_path, markdown_escape


def write_report(result: ScanResult, output_path: Path) -> None:
    output_path = output_path.expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_report(result), encoding="utf-8")


def build_report(result: ScanResult) -> str:
    total = sum(target.size_bytes for target in result.targets if target.risk != "DANGEROUS")
    safe = [target for target in result.targets if target.risk == RISK_SAFE and target.recommended]
    review = [target for target in result.targets if target.risk == RISK_REVIEW]

    lines: list[str] = [
        "# Cleanup Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Total Potential Recoverable Space",
        "",
        bytes_to_human(total),
        "",
        "---",
        "",
        "## Ranked Cleanup Suggestions",
        "",
        "| Rank | Category | Size | Risk | Path | Reason |",
        "|---|---|---:|---|---|---|",
    ]

    for index, target in enumerate(result.targets, start=1):
        path_label = _target_path_label(target)
        lines.append(
            "| "
            + " | ".join(
                [
                    str(index),
                    markdown_escape(target.name),
                    bytes_to_human(target.size_bytes),
                    target.risk,
                    markdown_escape(path_label),
                    markdown_escape(target.reason),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## Large Files Over 1 GB",
            "",
            "| File | Size | Last Modified |",
            "|---|---:|---|",
        ]
    )

    for file in result.large_files:
        if file.size_bytes < 1024**3:
            continue
        lines.append(
            f"| {markdown_escape(display_path(file.path))} | {bytes_to_human(file.size_bytes)} | {file.modified_at.strftime('%Y-%m-%d %H:%M')} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## Large Directories",
            "",
            "| Folder | Size |",
            "|---|---:|",
        ]
    )

    for target in result.large_directories:
        if target.path.is_file():
            continue
        lines.append(f"| {markdown_escape(_target_path_label(target))} | {bytes_to_human(target.size_bytes)} |")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Recommended Safe Deletions",
            "",
        ]
    )

    if safe:
        lines.extend(f"- {target.name}: `{display_path(target.path)}` ({bytes_to_human(target.size_bytes)})" for target in safe)
    else:
        lines.append("- None found above the configured threshold.")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Recommended Review Targets",
            "",
        ]
    )

    if review:
        lines.extend(f"- {target.name}: `{_target_path_label(target)}` ({bytes_to_human(target.size_bytes)})" for target in review)
    else:
        lines.append("- None found above the configured threshold.")

    lines.extend(_organizer_section(result))

    if result.warnings:
        lines.extend(["", "---", "", "## Scan Warnings", ""])
        lines.extend(f"- {warning}" for warning in result.warnings)

    lines.append("")
    return "\n".join(lines)


def _target_path_label(target) -> str:
    if len(target.paths) == 1:
        return display_path(target.path)
    return f"{len(target.paths)} paths, starting at {display_path(target.path)}"


def _organizer_section(result: ScanResult) -> list[str]:
    lines = [
        "",
        "---",
        "",
        "## Recommended Organizer",
        "",
        "These are review-only organization buckets. The tool does not move files automatically.",
        "",
        "| Bucket | Size | Files | Recommendation |",
        "|---|---:|---:|---|",
    ]

    if not result.organizer_buckets:
        lines.append("| None | 0 B | 0 | No large files matched the organizer rules. |")
        return lines

    for bucket in result.organizer_buckets:
        lines.append(
            f"| {markdown_escape(bucket.name)} | {bytes_to_human(bucket.size_bytes)} | {len(bucket.files)} | {markdown_escape(bucket.action)} |"
        )

    lines.extend(["", "### Top Organizer Files", "", "| File | Bucket | Size | Last Modified |", "|---|---|---:|---|"])
    top_files = sorted(
        [file for bucket in result.organizer_buckets for file in bucket.files],
        key=lambda item: item.size_bytes,
        reverse=True,
    )[:25]
    for file in top_files:
        lines.append(
            f"| {markdown_escape(display_path(file.path))} | {markdown_escape(file.category)} | {bytes_to_human(file.size_bytes)} | {file.modified_at.strftime('%Y-%m-%d %H:%M')} |"
        )

    return lines
