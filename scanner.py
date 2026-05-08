from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from organizer import build_organizer_buckets
from utils import (
    HOME,
    RISK_REVIEW,
    RISK_SAFE,
    CleanupTarget,
    LargeFile,
    bytes_to_human,
    directory_size,
    display_path,
    file_modified_at,
    is_protected_exact_path,
    is_source_repo_root,
    iter_existing,
    parse_human_size,
    safe_resolve,
    should_prune_scan_dir,
)


DEFAULT_MIN_TARGET_BYTES = 100 * 1024 * 1024
DEFAULT_LARGE_FILE_BYTES = 1024**3
DEFAULT_MAX_DEPTH = 8


@dataclass(frozen=True)
class ScanResult:
    targets: list[CleanupTarget]
    large_files: list[LargeFile]
    large_directories: list[CleanupTarget]
    organizer_buckets: list
    warnings: list[str]


class StorageScanner:
    def __init__(
        self,
        scan_roots: list[Path] | None = None,
        min_target_bytes: int = DEFAULT_MIN_TARGET_BYTES,
        large_file_bytes: int = DEFAULT_LARGE_FILE_BYTES,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> None:
        self.scan_roots = [safe_resolve(path) for path in scan_roots] if scan_roots else self._default_dev_roots()
        self.min_target_bytes = min_target_bytes
        self.large_file_bytes = large_file_bytes
        self.max_depth = max_depth
        self.warnings: list[str] = []
        self._seen_paths: set[Path] = set()

    def scan(self) -> ScanResult:
        targets: list[CleanupTarget] = []
        targets.extend(self._scan_known_cache_paths())
        targets.extend(self._scan_conda_envs())
        targets.extend(self._scan_library_cache_children())
        targets.extend(self._scan_dev_junk())
        targets.extend(self._scan_docker())

        large_files = self._scan_large_files()
        targets.extend(self._targets_for_download_files(large_files))

        targets = self._dedupe_targets(targets)
        targets.sort(key=lambda item: item.size_bytes, reverse=True)
        large_dirs = [target for target in targets if target.size_bytes >= self.min_target_bytes and len(target.paths) == 1]
        organizer_buckets = build_organizer_buckets(large_files)

        return ScanResult(
            targets=targets,
            large_files=large_files,
            large_directories=large_dirs,
            organizer_buckets=organizer_buckets,
            warnings=self.warnings,
        )

    def _default_dev_roots(self) -> list[Path]:
        candidates = [
            HOME / "Projects",
            HOME / "Developer",
            HOME / "Code",
            HOME / "src",
            HOME / "workspace",
            HOME / "Desktop" / "Projects",
        ]
        return [path for path in candidates if path.exists()]

    def _add_target(
        self,
        targets: list[CleanupTarget],
        *,
        name: str,
        path: Path,
        risk: str,
        recommended: bool,
        category: str,
        reason: str,
        size_bytes: int | None = None,
        paths: tuple[Path, ...] | None = None,
        deletable: bool = True,
        details: dict[str, str] | None = None,
    ) -> None:
        expanded = safe_resolve(path)
        if not expanded.exists() and not str(path).startswith("<"):
            return
        if expanded.exists() and is_protected_exact_path(expanded):
            return
        if expanded.exists() and is_source_repo_root(expanded):
            return

        if size_bytes is None:
            size_bytes = directory_size(expanded) if expanded.is_dir() else expanded.stat().st_size
        if size_bytes <= 0:
            return

        if size_bytes < self.min_target_bytes and category not in {"developer-junk-small", "docker"}:
            return

        targets.append(
            CleanupTarget(
                name=name,
                path=expanded,
                size_bytes=size_bytes,
                risk=risk,
                recommended=recommended,
                category=category,
                reason=reason,
                paths=paths or (expanded,),
                deletable=deletable,
                details=details or {},
            )
        )

    def _scan_known_cache_paths(self) -> list[CleanupTarget]:
        targets: list[CleanupTarget] = []

        known_paths = [
            ("HuggingFace cache", HOME / ".cache" / "huggingface", RISK_REVIEW, True, "cache", "Downloaded models and datasets can usually be restored later."),
            ("Torch cache", HOME / ".cache" / "torch", RISK_SAFE, True, "cache", "Torch downloads rebuild on demand."),
            ("pip cache", HOME / "Library" / "Caches" / "pip", RISK_SAFE, True, "cache", "pip package downloads rebuild on demand."),
            ("pip cache", HOME / ".cache" / "pip", RISK_SAFE, True, "cache", "pip package downloads rebuild on demand."),
            ("Homebrew cache", HOME / "Library" / "Caches" / "Homebrew", RISK_SAFE, True, "cache", "Homebrew cache can be re-downloaded if needed."),
            ("Xcode DerivedData", HOME / "Library" / "Developer" / "Xcode" / "DerivedData", RISK_SAFE, True, "cache", "Xcode build artifacts rebuild on demand."),
            ("User logs", HOME / "Library" / "Logs", RISK_SAFE, False, "logs", "Logs are usually removable, but keeping recent logs can help debugging."),
        ]

        for name, path, risk, recommended, category, reason in known_paths:
            self._add_target(
                targets,
                name=name,
                path=path,
                risk=risk,
                recommended=recommended,
                category=category,
                reason=reason,
            )

        return targets

    def _scan_conda_envs(self) -> list[CleanupTarget]:
        targets: list[CleanupTarget] = []
        env_roots = [HOME / "miniconda3" / "envs", HOME / "anaconda3" / "envs", HOME / ".conda" / "envs"]

        for env_root in iter_existing(env_roots):
            try:
                envs = [child for child in env_root.iterdir() if child.is_dir() and not child.is_symlink()]
            except (OSError, PermissionError):
                continue
            for env in envs:
                self._add_target(
                    targets,
                    name=f"Conda env: {env.name}",
                    path=env,
                    risk=RISK_REVIEW,
                    recommended=False,
                    category="environment",
                    reason="Conda environments may be active project dependencies; review before deleting.",
                )

        return targets

    def _scan_library_cache_children(self) -> list[CleanupTarget]:
        targets: list[CleanupTarget] = []
        cache_root = HOME / "Library" / "Caches"
        if not cache_root.exists():
            return targets

        known_names = {"pip", "homebrew"}
        try:
            children = [child for child in cache_root.iterdir() if child.is_dir() and not child.is_symlink()]
        except (OSError, PermissionError):
            return targets

        for child in children:
            if child.name.lower() in known_names:
                continue
            self._add_target(
                targets,
                name=f"App cache: {child.name}",
                path=child,
                risk=RISK_REVIEW,
                recommended=False,
                category="cache",
                reason="App caches are often rebuildable, but deleting them can slow the next launch.",
            )

        return targets

    def _scan_dev_junk(self) -> list[CleanupTarget]:
        targets: list[CleanupTarget] = []
        pycache_paths: list[Path] = []
        pycache_size = 0

        for root in self.scan_roots:
            if not root.exists():
                continue
            for path, depth in self._walk_dirs(root):
                name = path.name
                if name == "node_modules":
                    self._add_target(
                        targets,
                        name=f"node_modules: {path.parent.name}",
                        path=path,
                        risk=RISK_REVIEW,
                        recommended=True,
                        category="developer-junk",
                        reason="Node dependencies are large and can be restored with npm, pnpm, or yarn.",
                    )
                    continue
                if name in {".venv", "venv"}:
                    self._add_target(
                        targets,
                        name=f"Python venv: {path.parent.name}/{name}",
                        path=path,
                        risk=RISK_REVIEW,
                        recommended=False,
                        category="environment",
                        reason="Virtual environments may be project-specific; review before deleting.",
                    )
                    continue
                if name == "__pycache__":
                    size = directory_size(path)
                    if size > 0:
                        pycache_paths.append(path)
                        pycache_size += size
                    continue

        if pycache_paths:
            targets.append(
                CleanupTarget(
                    name="Python __pycache__ folders",
                    path=pycache_paths[0],
                    size_bytes=pycache_size,
                    risk=RISK_SAFE,
                    recommended=True,
                    category="developer-junk-small",
                    reason="Python bytecode caches are regenerated automatically.",
                    paths=tuple(pycache_paths),
                    deletable=True,
                    details={"count": str(len(pycache_paths))},
                )
            )

        return targets

    def _walk_dirs(self, root: Path):
        stack: list[tuple[Path, int]] = [(safe_resolve(root), 0)]
        while stack:
            current, depth = stack.pop()
            if depth > self.max_depth:
                continue
            if current.is_symlink() or should_prune_scan_dir(current):
                continue
            yield current, depth

            if current.name in {"node_modules", ".venv", "venv", "__pycache__"}:
                continue

            try:
                children = [child for child in current.iterdir() if child.is_dir()]
            except (OSError, PermissionError):
                continue

            for child in children:
                stack.append((child, depth + 1))

    def _scan_large_files(self) -> list[LargeFile]:
        files: list[LargeFile] = []
        roots = [HOME / "Downloads", *self.scan_roots]

        for root in roots:
            if not root.exists() or should_prune_scan_dir(root):
                continue
            for file_path in self._walk_files(root):
                try:
                    size = file_path.stat().st_size
                except (OSError, PermissionError):
                    continue
                suffix = file_path.suffix.lower()
                is_large = size >= self.large_file_bytes
                is_review_archive = root == HOME / "Downloads" and suffix in {".dmg", ".zip", ".pkg"} and size >= self.min_target_bytes
                if is_large or is_review_archive:
                    files.append(
                        LargeFile(
                            path=file_path,
                            size_bytes=size,
                            modified_at=file_modified_at(file_path),
                            category=self._file_category(file_path),
                        )
                    )

        files.sort(key=lambda item: item.size_bytes, reverse=True)
        return files

    def _walk_files(self, root: Path):
        stack: list[tuple[Path, int]] = [(safe_resolve(root), 0)]
        while stack:
            current, depth = stack.pop()
            if depth > self.max_depth:
                continue
            if current.is_symlink():
                continue
            if current.is_file():
                yield current
                continue
            if should_prune_scan_dir(current):
                continue
            if current.name in {"node_modules", ".venv", "venv", "__pycache__"}:
                continue
            try:
                for child in current.iterdir():
                    stack.append((child, depth + 1))
            except (OSError, PermissionError):
                continue

    def _file_category(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix in {".dmg", ".pkg"}:
            return "installer"
        if suffix in {".zip", ".tar", ".gz", ".tgz", ".rar", ".7z"}:
            return "archive"
        if suffix in {".mp4", ".mov", ".mkv", ".avi"}:
            return "video"
        return "large-file"

    def _targets_for_download_files(self, large_files: list[LargeFile]) -> list[CleanupTarget]:
        targets: list[CleanupTarget] = []
        for item in large_files:
            if item.path in self._seen_paths:
                continue
            if item.path.parent != HOME / "Downloads":
                continue
            self._add_target(
                targets,
                name=f"{item.category.title()} file: {item.path.name}",
                path=item.path,
                size_bytes=item.size_bytes,
                risk=RISK_REVIEW,
                recommended=False,
                category=item.category,
                reason="Large Downloads files should be reviewed before deletion.",
            )
        return targets

    def _scan_docker(self) -> list[CleanupTarget]:
        if not shutil.which("docker"):
            return []

        try:
            result = subprocess.run(
                ["docker", "system", "df"],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []

        if result.returncode != 0 or not result.stdout.strip():
            return []

        reclaimable = self._parse_docker_reclaimable(result.stdout)
        if reclaimable <= 0:
            return []

        return [
            CleanupTarget(
                name="Docker reclaimable data",
                path=Path("<docker system df>"),
                size_bytes=reclaimable,
                risk=RISK_REVIEW,
                recommended=False,
                category="docker",
                reason="Docker prune operations can remove images, containers, volumes, and build cache; review manually.",
                paths=tuple(),
                deletable=False,
                details={"preview": result.stdout.strip()},
            )
        ]

    def _parse_docker_reclaimable(self, output: str) -> int:
        total = 0
        for line in output.splitlines()[1:]:
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) < 5:
                continue
            reclaimable = parts[4].split(" ", 1)[0]
            total += parse_human_size(reclaimable)
        return total

    def _dedupe_targets(self, targets: list[CleanupTarget]) -> list[CleanupTarget]:
        deduped: list[CleanupTarget] = []
        seen: set[str] = set()
        for target in targets:
            key = "|".join(sorted(display_path(path) for path in target.paths)) or target.name
            if key in seen:
                continue
            seen.add(key)
            deduped.append(target)
        return deduped
