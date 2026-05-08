#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from cleaner import Cleaner
from report import write_report
from scanner import DEFAULT_LARGE_FILE_BYTES, DEFAULT_MIN_TARGET_BYTES, StorageScanner
from utils import RISK_SAFE, CleanupTarget, bytes_to_human, display_path


def main() -> int:
    args = parse_args()

    scanner = StorageScanner(
        scan_roots=args.scan_root,
        min_target_bytes=args.min_target_mb * 1024 * 1024,
        large_file_bytes=int(args.large_file_gb * 1024**3),
        max_depth=args.max_depth,
    )
    result = scanner.scan()
    targets = result.targets

    write_report(result, args.report)
    print(f"\nCleanup report written to {display_path(args.report)}")
    print_targets(targets)

    if args.dry_run:
        print("\nDry run enabled. No deletion prompt was shown.")
        return 0

    selected = prompt_for_selection(targets)
    if not selected:
        print("No cleanup targets selected.")
        return 0

    show_selection(selected)
    if input("\nType DELETE to confirm: ").strip() != "DELETE":
        print("Cancelled. Nothing was deleted.")
        return 0

    cleaner = Cleaner(args.log)
    results = cleaner.delete_targets(selected)
    recovered = sum(item.recovered_bytes for item in results)

    print("\nDeletion summary:")
    for item in results:
        if item.deleted_paths:
            print(f"- Deleted {item.target.name}: {bytes_to_human(item.recovered_bytes)}")
        for skipped in item.skipped_paths:
            print(f"- Skipped {skipped}")

    print(f"\nTotal recovered: {bytes_to_human(recovered)}")
    print(f"Cleanup log written to {display_path(args.log)}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safely scan for developer-focused Mac storage cleanup candidates.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and write the report without prompting for deletion.",
    )
    parser.add_argument(
        "--scan-root",
        action="append",
        type=Path,
        help="Additional or replacement developer root to scan. Can be passed multiple times.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("cleanup_report.md"),
        help="Markdown report output path.",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("cleanup_log.txt"),
        help="Deletion log path.",
    )
    parser.add_argument(
        "--min-target-mb",
        type=int,
        default=DEFAULT_MIN_TARGET_BYTES // (1024 * 1024),
        help="Minimum cleanup target size in MB.",
    )
    parser.add_argument(
        "--large-file-gb",
        type=float,
        default=DEFAULT_LARGE_FILE_BYTES / 1024**3,
        help="Minimum file size for the large-file report.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=8,
        help="Maximum recursive scan depth for developer roots.",
    )
    return parser.parse_args()


def print_targets(targets: list[CleanupTarget]) -> None:
    print("\nPotential cleanup targets:")
    if not targets:
        print("No cleanup targets found above the configured threshold.")
        return

    for index, target in enumerate(targets, start=1):
        marker = "*" if target.recommended else " "
        deletable = "" if target.deletable else " (manual)"
        print(
            f"[{index:>2}] {marker} {target.name:<36} "
            f"{bytes_to_human(target.size_bytes):>10}  {target.risk:<8} "
            f"{display_path(target.path)}{deletable}"
        )

    print("\n* recommended by the scanner")


def prompt_for_selection(targets: list[CleanupTarget]) -> list[CleanupTarget]:
    if not targets:
        return []

    print(
        "\nSelect targets to delete:\n"
        "Example: 1 2 5\n"
        "Type \"all\" for all recommended SAFE items\n"
        "Type \"none\" to cancel\n"
    )
    raw = input("> ").strip().lower()
    if raw in {"", "none", "cancel"}:
        return []
    if raw == "all":
        return [target for target in targets if target.risk == RISK_SAFE and target.recommended and target.deletable]

    selected: list[CleanupTarget] = []
    for part in raw.replace(",", " ").split():
        if not part.isdigit():
            print(f"Ignoring invalid selection: {part}")
            continue
        index = int(part)
        if index < 1 or index > len(targets):
            print(f"Ignoring out-of-range selection: {index}")
            continue
        target = targets[index - 1]
        if not target.deletable:
            print(f"Ignoring manual-only target: {target.name}")
            continue
        selected.append(target)

    return selected


def show_selection(selected: list[CleanupTarget]) -> None:
    total = sum(target.size_bytes for target in selected)
    print("\nYou selected:")
    for index, target in enumerate(selected, start=1):
        print(f"\n[{index}] {target.name} ({bytes_to_human(target.size_bytes)}, {target.risk})")
        paths = list(target.paths)
        for path in paths[:20]:
            print(f"    {display_path(path)}")
        if len(paths) > 20:
            print(f"    ... and {len(paths) - 20} more paths")

    print(f"\nEstimated recovery: {bytes_to_human(total)}")


if __name__ == "__main__":
    raise SystemExit(main())
