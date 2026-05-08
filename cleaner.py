from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from utils import (
    RISK_DANGEROUS,
    CleanupTarget,
    bytes_to_human,
    directory_size,
    display_path,
    is_protected_exact_path,
    is_source_repo_root,
    is_system_protected_path,
)


@dataclass(frozen=True)
class DeletionResult:
    target: CleanupTarget
    recovered_bytes: int
    deleted_paths: tuple[Path, ...]
    skipped_paths: tuple[str, ...]


class Cleaner:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path.expanduser()

    def delete_targets(self, targets: list[CleanupTarget]) -> list[DeletionResult]:
        results: list[DeletionResult] = []
        for target in targets:
            result = self._delete_target(target)
            results.append(result)
            if result.deleted_paths:
                self._log_result(result)
        return results

    def _delete_target(self, target: CleanupTarget) -> DeletionResult:
        skipped: list[str] = []
        deleted: list[Path] = []
        recovered = 0

        if not target.deletable:
            return DeletionResult(target, 0, tuple(), (f"{target.name} is report-only and must be cleaned manually.",))
        if target.risk == RISK_DANGEROUS:
            return DeletionResult(target, 0, tuple(), (f"{target.name} is marked DANGEROUS.",))

        for path in target.paths:
            allowed, reason = self._is_safe_delete_path(path)
            if not allowed:
                skipped.append(f"{display_path(path)}: {reason}")
                continue
            if not path.exists():
                skipped.append(f"{display_path(path)}: path no longer exists")
                continue

            size_before = _path_size(path)
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            except OSError as exc:
                skipped.append(f"{display_path(path)}: {exc}")
                continue

            recovered += size_before
            deleted.append(path)

        return DeletionResult(target, recovered, tuple(deleted), tuple(skipped))

    def _is_safe_delete_path(self, path: Path) -> tuple[bool, str]:
        if is_protected_exact_path(path):
            return False, "protected user or system root"
        if is_system_protected_path(path):
            return False, "system path"
        if path.is_symlink():
            return False, "symlink"
        if path.name in {".git", ".svn", ".hg"}:
            return False, "source control metadata"
        if path.is_dir() and is_source_repo_root(path):
            return False, "git repository root"
        return True, ""

    def _log_result(self, result: DeletionResult) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}]",
            f"Deleted {result.target.name}",
            f"Recovered {bytes_to_human(result.recovered_bytes)}",
        ]
        lines.extend(f"- {display_path(path)}" for path in result.deleted_paths)
        lines.append("")
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")


def _path_size(path: Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    return directory_size(path)
