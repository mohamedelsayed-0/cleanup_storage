#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable


RISK_SAFE = "SAFE"
RISK_REVIEW = "REVIEW"
RISK_DANGEROUS = "DANGEROUS"

HOME = Path.home()
DEFAULT_MIN_TARGET_BYTES = 100 * 1024 * 1024
DEFAULT_LARGE_FILE_BYTES = 1024**3
DEFAULT_MAX_DEPTH = 8

PROTECTED_EXACT_PATHS = {
    HOME,
    HOME / "Documents",
    HOME / "Desktop",
    HOME / "Pictures",
    HOME / "Movies",
    HOME / "Music",
    HOME / "Applications",
    Path("/"),
    Path("/System"),
    Path("/Library"),
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/Applications"),
}

PROTECTED_SCAN_ROOTS = {
    HOME / "Documents",
    HOME / "Desktop",
    HOME / "Pictures",
    HOME / "Movies",
    HOME / "Music",
    HOME / "Applications",
    Path("/System"),
    Path("/Library"),
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/Applications"),
}

ORGANIZER_ACTIONS = {
    "installer": "Review installers. Most old .dmg and .pkg files can be deleted after installation.",
    "archive": "Review archives. Keep only source archives that cannot be downloaded again.",
    "screenshot": "Review old screenshots. Archive the few useful ones and delete debugging or throwaway captures.",
    "video": "Move wanted videos to a media folder or external storage; delete throwaway captures.",
    "pdf": "Review old PDFs. Keep course material and papers you still use; remove duplicate downloads.",
    "large-file": "Review manually. Large files are not safe to classify automatically.",
}

SCREENSHOT_NAME_PATTERNS = ("screenshot", "screen shot")
SCREENSHOT_EXTENSIONS = {".png", ".jpg", ".jpeg"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".mkv", ".avi", ".webm"}
INSTALLER_EXTENSIONS = {".dmg", ".pkg"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz"}
PDF_EXTENSIONS = {".pdf"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".heic", ".webp"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".txt", ".md"}
CODE_ARCHIVE_EXTENSIONS = {".xcodeproj", ".xcworkspace"}
MODEL_EXTENSIONS = {".safetensors", ".ckpt", ".pt", ".pth", ".bin", ".gguf", ".onnx"}


@dataclass(frozen=True)
class CleanupTarget:
    name: str
    path: Path
    size_bytes: int
    risk: str
    recommended: bool
    category: str
    reason: str
    paths: tuple[Path, ...] = field(default_factory=tuple)
    deletable: bool = True
    details: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.paths:
            object.__setattr__(self, "paths", (self.path,))

    @property
    def size_gb(self) -> float:
        return self.size_bytes / (1024**3)

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": display_path(self.path),
            "size_gb": round(self.size_gb, 2),
            "risk": self.risk,
            "recommended": self.recommended,
            "category": self.category,
            "reason": self.reason,
            "deletable": self.deletable,
        }


@dataclass(frozen=True)
class LargeFile:
    path: Path
    size_bytes: int
    modified_at: datetime
    accessed_at: datetime
    category: str


@dataclass(frozen=True)
class OrganizerBucket:
    name: str
    action: str
    size_bytes: int
    files: tuple[LargeFile, ...]


@dataclass(frozen=True)
class StorageBucket:
    name: str
    size_bytes: int
    count: int
    recommendation: str


@dataclass(frozen=True)
class ScanResult:
    targets: list[CleanupTarget]
    large_files: list[LargeFile]
    large_directories: list[CleanupTarget]
    organizer_buckets: list[OrganizerBucket]
    downloads_breakdown: list[StorageBucket]
    storage_heatmap: list[StorageBucket]
    warnings: list[str]


@dataclass(frozen=True)
class DeletionResult:
    target: CleanupTarget
    recovered_bytes: int
    deleted_paths: tuple[Path, ...]
    skipped_paths: tuple[str, ...]


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
    print_storage_heatmap(result.storage_heatmap)
    print_organizer_summary(result.organizer_buckets, args.report)

    if args.dry_run:
        print("\nDry run enabled. No deletion prompt was shown.")
        return 0

    selected = prompt_for_selection(targets)
    if not selected:
        print("No cleanup targets selected.")
        return 0

    show_selection(selected)
    if input("\nType DELETE to confirm deletion of the selected targets: ").strip() != "DELETE":
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
        help="Developer root to scan for node_modules, virtualenvs, __pycache__, and large files. Can be passed multiple times.",
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
        default=DEFAULT_MAX_DEPTH,
        help="Maximum recursive scan depth for developer roots.",
    )
    return parser.parse_args()


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

    def scan(self) -> ScanResult:
        targets: list[CleanupTarget] = []
        targets.extend(self._scan_known_cache_paths())
        targets.extend(self._scan_conda_envs())
        targets.extend(self._scan_library_cache_children())
        targets.extend(self._scan_dev_junk())
        targets.extend(self._scan_hidden_mac_storage())
        targets.extend(self._scan_ai_models())
        targets.extend(self._scan_git_bloat())
        targets.extend(self._scan_docker())

        download_targets, download_files, downloads_breakdown = self._scan_downloads()
        media_targets, media_files = self._scan_user_media()
        targets.extend(download_targets)
        targets.extend(media_targets)

        large_files = dedupe_large_files([*self._scan_large_files(), *download_files, *media_files])

        targets = self._dedupe_targets(targets)
        targets.sort(key=lambda item: item.size_bytes, reverse=True)
        large_dirs = [target for target in targets if target.size_bytes >= self.min_target_bytes and target.path.is_dir()]
        organizer_buckets = build_organizer_buckets(large_files)
        storage_heatmap = build_storage_heatmap(targets, downloads_breakdown)

        return ScanResult(
            targets=targets,
            large_files=large_files,
            large_directories=large_dirs,
            organizer_buckets=organizer_buckets,
            downloads_breakdown=downloads_breakdown,
            storage_heatmap=storage_heatmap,
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
            try:
                size_bytes = directory_size(expanded) if expanded.is_dir() else expanded.stat().st_size
            except OSError:
                return
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
                details=confidence_details(category, risk, reason, recommended),
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
            for path in self._walk_dirs(root):
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
            yield current

            if current.name in {"node_modules", ".venv", "venv", "__pycache__"}:
                continue

            try:
                children = [child for child in current.iterdir() if child.is_dir()]
            except (OSError, PermissionError):
                continue
            for child in children:
                stack.append((child, depth + 1))

    def _scan_downloads(self) -> tuple[list[CleanupTarget], list[LargeFile], list[StorageBucket]]:
        root = HOME / "Downloads"
        targets: list[CleanupTarget] = []
        files: list[LargeFile] = []
        bucket_sizes: dict[str, int] = defaultdict(int)
        bucket_counts: dict[str, int] = defaultdict(int)

        if not root.exists():
            return targets, files, []

        for file_path in self._walk_review_files(root, max_depth=4):
            try:
                stat = file_path.stat()
            except (OSError, PermissionError):
                continue

            category = self._file_category(file_path)
            size = stat.st_size
            bucket_sizes[category] += size
            bucket_counts[category] += 1

            large_file = LargeFile(
                path=file_path,
                size_bytes=size,
                modified_at=datetime.fromtimestamp(stat.st_mtime),
                accessed_at=datetime.fromtimestamp(stat.st_atime),
                category=category,
            )

            if size >= self.large_file_bytes or self._is_interesting_download(file_path, size):
                files.append(large_file)

            target = self._download_target_for_file(file_path, size, category, large_file)
            if target:
                targets.append(target)

        buckets = [
            StorageBucket(
                name=name.replace("-", " ").title(),
                size_bytes=bucket_sizes[name],
                count=bucket_counts[name],
                recommendation=downloads_recommendation(name),
            )
            for name in sorted(bucket_sizes, key=lambda key: bucket_sizes[key], reverse=True)
        ]
        return targets, files, buckets

    def _scan_user_media(self) -> tuple[list[CleanupTarget], list[LargeFile]]:
        targets: list[CleanupTarget] = []
        files: list[LargeFile] = []
        scan_roots = [
            HOME / "Desktop",
            HOME / "Pictures" / "Screenshots",
            HOME / "Movies",
        ]

        for root in scan_roots:
            if not root.exists():
                continue
            depth = 1 if root == HOME / "Desktop" else 5
            for file_path in self._walk_review_files(root, max_depth=depth):
                try:
                    stat = file_path.stat()
                except (OSError, PermissionError):
                    continue

                category = self._file_category(file_path)
                if category not in {"screenshot", "video", "pdf"}:
                    continue

                item = LargeFile(
                    path=file_path,
                    size_bytes=stat.st_size,
                    modified_at=datetime.fromtimestamp(stat.st_mtime),
                    accessed_at=datetime.fromtimestamp(stat.st_atime),
                    category=category,
                )

                should_track = category == "screenshot" or stat.st_size >= self.min_target_bytes
                if should_track:
                    files.append(item)

                target = self._media_target_for_file(file_path, stat.st_size, category, item)
                if target:
                    targets.append(target)

        screenshot_targets = self._group_old_screenshots([file for file in files if file.category == "screenshot"])
        targets.extend(screenshot_targets)
        return targets, files

    def _download_target_for_file(self, path: Path, size: int, category: str, file: LargeFile) -> CleanupTarget | None:
        if size < self.min_target_bytes:
            return None

        details = file_score_details(path, category, file)
        reason = "Large Downloads files should be reviewed before deletion."
        recommended = False

        if category == "installer":
            app_match = matching_installed_app(path)
            if app_match:
                details["installed_app"] = app_match
                details["confidence"] = "88%"
                recommended = True
                reason = f"Installer appears re-downloadable and {app_match} is already installed."
            elif age_days(file.modified_at) >= 30:
                details["confidence"] = "72%"
                recommended = True
                reason = "Old installer files are usually removable after installation."
        elif category == "archive":
            extracted = matching_extracted_folder(path)
            if extracted:
                details["extracted_folder"] = display_path(extracted)
                details["confidence"] = "82%"
                recommended = True
                reason = "Archive appears to have a matching extracted folder."
            elif age_days(file.modified_at) >= 90:
                details["confidence"] = "58%"
                reason = "Old archives can be large, but may contain source material; review first."
        elif category == "video":
            if age_days(file.modified_at) >= 180:
                details["confidence"] = "48%"
                reason = "Large old video. Confirm it is not a lecture, project export, or personal recording."
        elif category == "pdf":
            if unused_days(file.accessed_at) >= 180:
                details["confidence"] = "42%"
                reason = "Large PDF not accessed recently. Review before deleting."

        return CleanupTarget(
            name=f"{category.title()} file: {path.name}",
            path=path,
            size_bytes=size,
            risk=RISK_REVIEW,
            recommended=recommended,
            category=category,
            reason=reason,
            details=details,
        )

    def _media_target_for_file(self, path: Path, size: int, category: str, file: LargeFile) -> CleanupTarget | None:
        if category == "screenshot":
            return None
        if size < self.large_file_bytes and category != "pdf":
            return None
        if category == "pdf" and (size < self.min_target_bytes or unused_days(file.accessed_at) < 180):
            return None

        details = file_score_details(path, category, file)
        reason = "Large media/document file should be reviewed before deletion."
        if category == "video":
            reason = "Large video or screen recording. Review age and usefulness before deleting."
        elif category == "pdf":
            reason = "Large PDF not opened recently. Review before deleting."

        return CleanupTarget(
            name=f"{category.title()} file: {path.name}",
            path=path,
            size_bytes=size,
            risk=RISK_REVIEW,
            recommended=False,
            category=category,
            reason=reason,
            details=details,
        )

    def _group_old_screenshots(self, screenshots: list[LargeFile]) -> list[CleanupTarget]:
        if not screenshots:
            return []

        older_than_30 = [item for item in screenshots if age_days(item.modified_at) >= 30]
        older_than_60 = [item for item in screenshots if age_days(item.modified_at) >= 60]
        never_reopened = [item for item in screenshots if item.accessed_at <= item.modified_at]
        grouped_size = sum(item.size_bytes for item in older_than_60)

        if not older_than_60 or grouped_size <= 0:
            return []

        details = {
            "confidence": "64%",
            "re_downloadable": "no",
            "total_screenshots": str(len(screenshots)),
            "older_than_30_days": str(len(older_than_30)),
            "older_than_60_days": str(len(older_than_60)),
            "never_accessed_after_creation": str(len(never_reopened)),
        }
        return [
            CleanupTarget(
                name="Old screenshots",
                path=older_than_60[0].path,
                size_bytes=grouped_size,
                risk=RISK_REVIEW,
                recommended=False,
                category="screenshot",
                reason="Old screenshots often become low-value clutter, but they may contain notes or personal context.",
                paths=tuple(item.path for item in older_than_60),
                details=details,
            )
        ]

    def _is_interesting_download(self, path: Path, size: int) -> bool:
        category = self._file_category(path)
        if size >= self.min_target_bytes:
            return category in {"installer", "archive", "video", "pdf", "screenshot", "image", "dataset", "large-file"}
        return category in {"installer", "archive"}

    def _walk_review_files(self, root: Path, max_depth: int):
        stack: list[tuple[Path, int]] = [(safe_resolve(root), 0)]
        while stack:
            current, depth = stack.pop()
            if depth > max_depth or current.is_symlink():
                continue
            if current.is_file():
                yield current
                continue
            if is_system_protected_path(current):
                continue
            if current.name in {".git", ".svn", ".hg", "node_modules", ".venv", "venv", "__pycache__"}:
                continue
            try:
                for child in current.iterdir():
                    stack.append((child, depth + 1))
            except (OSError, PermissionError):
                continue

    def _scan_hidden_mac_storage(self) -> list[CleanupTarget]:
        targets: list[CleanupTarget] = []
        targets.extend(self._scan_messages_attachments())
        targets.extend(self._scan_application_support())
        targets.extend(self._scan_applications())
        targets.extend(self._scan_xcode_developer_data())
        return targets

    def _scan_messages_attachments(self) -> list[CleanupTarget]:
        path = HOME / "Library" / "Messages" / "Attachments"
        if not path.exists():
            return []
        size = directory_size(path)
        if size < self.min_target_bytes:
            return []
        return [
            CleanupTarget(
                name="Messages attachments",
                path=path,
                size_bytes=size,
                risk=RISK_REVIEW,
                recommended=False,
                category="messages",
                reason="Message attachments can be huge, but may include personal media; review in Messages or Finder before deleting.",
                deletable=False,
                details={
                    "confidence": "35%",
                    "re_downloadable": "no",
                    "cleanup_style": "manual review",
                },
            )
        ]

    def _scan_application_support(self) -> list[CleanupTarget]:
        root = HOME / "Library" / "Application Support"
        targets: list[CleanupTarget] = []
        if not root.exists():
            return targets
        try:
            children = [child for child in root.iterdir() if child.is_dir() and not child.is_symlink()]
        except (OSError, PermissionError):
            return targets

        for child in children:
            size = directory_size(child)
            if size < self.min_target_bytes:
                continue
            targets.append(
                CleanupTarget(
                    name=f"Application Support: {child.name}",
                    path=child,
                    size_bytes=size,
                    risk=RISK_REVIEW,
                    recommended=False,
                    category="application-support",
                    reason="Large Application Support folders can hold app data, accounts, and caches; inspect the app before deleting.",
                    deletable=False,
                    details={
                        "confidence": "20%",
                        "re_downloadable": "maybe",
                        "cleanup_style": "manual app-specific cleanup",
                    },
                )
            )
        return targets

    def _scan_applications(self) -> list[CleanupTarget]:
        root = Path("/Applications")
        targets: list[CleanupTarget] = []
        if not root.exists():
            return targets
        try:
            apps = [child for child in root.iterdir() if child.suffix.lower() == ".app" and not child.is_symlink()]
        except (OSError, PermissionError):
            return targets

        for app in apps:
            size = directory_size(app)
            if size < self.min_target_bytes:
                continue
            targets.append(
                CleanupTarget(
                    name=f"Application: {app.stem}",
                    path=app,
                    size_bytes=size,
                    risk=RISK_REVIEW,
                    recommended=False,
                    category="application",
                    reason="Large installed app. Uninstall manually if you no longer use it.",
                    deletable=False,
                    details={
                        "confidence": "15%",
                        "re_downloadable": "maybe",
                        "cleanup_style": "manual uninstall",
                    },
                )
            )
        return targets

    def _scan_xcode_developer_data(self) -> list[CleanupTarget]:
        known = [
            ("Xcode archives", HOME / "Library" / "Developer" / "Xcode" / "Archives", "Project archives may be important releases; review in Xcode Organizer."),
            ("Xcode device support", HOME / "Library" / "Developer" / "Xcode" / "iOS DeviceSupport", "Old device support data can be removed after review."),
            ("CoreSimulator data", HOME / "Library" / "Developer" / "CoreSimulator", "Simulator devices and runtimes can be recreated but may contain app data."),
        ]
        targets: list[CleanupTarget] = []
        for name, path, reason in known:
            if not path.exists():
                continue
            size = directory_size(path)
            if size < self.min_target_bytes:
                continue
            targets.append(
                CleanupTarget(
                    name=name,
                    path=path,
                    size_bytes=size,
                    risk=RISK_REVIEW,
                    recommended=False,
                    category="xcode",
                    reason=reason,
                    deletable=False,
                    details={
                        "confidence": "55%",
                        "re_downloadable": "maybe",
                        "cleanup_style": "manual Xcode cleanup",
                    },
                )
            )
        return targets

    def _scan_ai_models(self) -> list[CleanupTarget]:
        targets: list[CleanupTarget] = []
        model_roots = [
            ("Ollama models", HOME / ".ollama" / "models", "Ollama models can usually be pulled again, but confirm you do not need them offline."),
            ("HuggingFace model files", HOME / ".cache" / "huggingface", "Downloaded model files can usually be re-downloaded."),
            ("Torch model files", HOME / ".cache" / "torch", "Torch checkpoints and model files can usually be re-downloaded."),
        ]

        for name, root, reason in model_roots:
            if not root.exists():
                continue
            root_size = directory_size(root)
            if root_size >= self.min_target_bytes and name == "Ollama models":
                targets.append(
                    CleanupTarget(
                        name=name,
                        path=root,
                        size_bytes=root_size,
                        risk=RISK_REVIEW,
                        recommended=True,
                        category="ai-models",
                        reason=reason,
                        details={
                            "confidence": "70%",
                            "re_downloadable": "yes",
                            "cleanup_style": "model cache",
                        },
                    )
                )

            for file_path in self._walk_review_files(root, max_depth=8):
                if file_path.suffix.lower() not in MODEL_EXTENSIONS:
                    continue
                try:
                    stat = file_path.stat()
                except (OSError, PermissionError):
                    continue
                if stat.st_size < self.min_target_bytes:
                    continue
                item = LargeFile(
                    path=file_path,
                    size_bytes=stat.st_size,
                    modified_at=datetime.fromtimestamp(stat.st_mtime),
                    accessed_at=datetime.fromtimestamp(stat.st_atime),
                    category="ai-model",
                )
                targets.append(
                    CleanupTarget(
                        name=f"AI model: {file_path.name}",
                        path=file_path,
                        size_bytes=stat.st_size,
                        risk=RISK_REVIEW,
                        recommended=False,
                        category="ai-models",
                        reason=reason,
                        details=file_score_details(file_path, "ai-model", item)
                        | {
                            "confidence": "64%",
                            "re_downloadable": "yes",
                        },
                    )
                )
        return targets

    def _scan_git_bloat(self) -> list[CleanupTarget]:
        targets: list[CleanupTarget] = []
        seen: set[Path] = set()
        for root in self.scan_roots:
            if not root.exists():
                continue
            for path in self._walk_dirs(root):
                if not (path / ".git").exists():
                    continue
                resolved = safe_resolve(path)
                if resolved in seen:
                    continue
                seen.add(resolved)
                repo_size = directory_size(path)
                git_size = directory_size(path / ".git")
                if repo_size < self.min_target_bytes and git_size < self.min_target_bytes:
                    continue
                targets.append(
                    CleanupTarget(
                        name=f"Git repo bloat: {path.name}",
                        path=path,
                        size_bytes=repo_size,
                        risk=RISK_REVIEW,
                        recommended=False,
                        category="git-repo",
                        reason="Large source repository detected. Do not delete automatically; check binaries, datasets, build outputs, or Git LFS.",
                        deletable=False,
                        details={
                            "confidence": "10%",
                            "re_downloadable": "no",
                            "repo_size": bytes_to_human(repo_size),
                            "git_metadata": bytes_to_human(git_size),
                            "cleanup_style": "manual repo cleanup",
                        },
                    )
                )
        return targets

    def _scan_large_files(self) -> list[LargeFile]:
        files: list[LargeFile] = []
        roots = [*self.scan_roots]

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
                            accessed_at=file_accessed_at(file_path),
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
        if is_screenshot(path):
            return "screenshot"
        if suffix in INSTALLER_EXTENSIONS:
            return "installer"
        if suffix in ARCHIVE_EXTENSIONS:
            return "archive"
        if suffix in VIDEO_EXTENSIONS:
            return "video"
        if suffix in PDF_EXTENSIONS:
            return "pdf"
        if suffix in IMAGE_EXTENSIONS:
            return "image"
        if suffix in DOCUMENT_EXTENSIONS:
            return "document"
        if suffix in {".csv", ".tsv", ".json", ".jsonl", ".parquet", ".sqlite", ".db"}:
            return "dataset"
        return "large-file"

    def _targets_for_download_files(self, large_files: list[LargeFile]) -> list[CleanupTarget]:
        targets: list[CleanupTarget] = []
        for item in large_files:
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

            size_before = path_size(path)
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


def build_organizer_buckets(files: list[LargeFile]) -> list[OrganizerBucket]:
    grouped: dict[str, list[LargeFile]] = defaultdict(list)
    for file in files:
        grouped[file.category].append(file)

    buckets: list[OrganizerBucket] = []
    for category, items in grouped.items():
        items.sort(key=lambda item: item.size_bytes, reverse=True)
        buckets.append(
            OrganizerBucket(
                name=category.replace("-", " ").title(),
                action=ORGANIZER_ACTIONS.get(category, ORGANIZER_ACTIONS["large-file"]),
                size_bytes=sum(item.size_bytes for item in items),
                files=tuple(items),
            )
        )

    buckets.sort(key=lambda bucket: bucket.size_bytes, reverse=True)
    return buckets


def build_storage_heatmap(targets: list[CleanupTarget], downloads_breakdown: list[StorageBucket]) -> list[StorageBucket]:
    grouped_size: dict[str, int] = defaultdict(int)
    grouped_count: dict[str, int] = defaultdict(int)

    for target in targets:
        name = heatmap_name_for_category(target.category)
        grouped_size[name] += target.size_bytes
        grouped_count[name] += 1

    for bucket in downloads_breakdown:
        grouped_size["Downloads"] += bucket.size_bytes
        grouped_count["Downloads"] += bucket.count

    buckets = [
        StorageBucket(
            name=name,
            size_bytes=size,
            count=grouped_count[name],
            recommendation=heatmap_recommendation(name),
        )
        for name, size in grouped_size.items()
        if size > 0
    ]
    buckets.sort(key=lambda item: item.size_bytes, reverse=True)
    return buckets


def heatmap_name_for_category(category: str) -> str:
    mapping = {
        "cache": "Caches",
        "logs": "Logs",
        "environment": "Dev Environments",
        "developer-junk": "Developer Junk",
        "developer-junk-small": "Developer Junk",
        "installer": "Installers",
        "archive": "Archives",
        "video": "Videos",
        "screenshot": "Screenshots",
        "pdf": "PDFs",
        "docker": "Docker",
        "messages": "Messages Attachments",
        "application-support": "Application Support",
        "application": "Applications",
        "xcode": "Xcode Developer Data",
        "ai-models": "AI Models",
        "git-repo": "Git Repos",
    }
    return mapping.get(category, category.replace("-", " ").title())


def heatmap_recommendation(name: str) -> str:
    recommendations = {
        "Caches": "Usually the first place to recover space; prefer SAFE cache targets first.",
        "Downloads": "Classify before deleting. Installers and extracted archives are often low value.",
        "Screenshots": "Archive useful screenshots and delete old debugging or throwaway captures.",
        "Videos": "Review old recordings and move useful ones to external storage.",
        "PDFs": "Review old large PDFs; many are re-downloadable but course notes may not be.",
        "Dev Environments": "Review active projects before deleting environments.",
        "Developer Junk": "Dependencies and bytecode can often be regenerated.",
        "Installers": "Usually re-downloadable after the app is installed.",
        "Archives": "Delete only when extracted or re-downloadable.",
        "Docker": "Use Docker's prune tools manually.",
        "Messages Attachments": "Review personal media carefully; prefer Messages/Finder review over blanket deletion.",
        "Application Support": "Inspect app-specific data before deleting anything.",
        "Applications": "Uninstall unused apps manually.",
        "Xcode Developer Data": "Use Xcode Organizer or simulator tools for cleanup.",
        "AI Models": "Model caches are usually re-downloadable but can be needed offline.",
        "Git Repos": "Look for build output, datasets, binaries, or missing Git LFS usage.",
    }
    return recommendations.get(name, "Review manually.")


def downloads_recommendation(category: str) -> str:
    recommendations = {
        "installer": "Check whether the app is already installed; old installers are usually low value.",
        "archive": "Check whether the archive was extracted or can be downloaded again.",
        "video": "Large recordings should be archived or deleted after review.",
        "screenshot": "Old screenshots are often safe to archive/delete after review.",
        "image": "Review duplicates and image spam.",
        "pdf": "Keep textbooks/notes you use; delete duplicate downloads.",
        "document": "Review manually; documents may be important.",
        "dataset": "Check whether the data exists elsewhere before deleting.",
        "large-file": "Review manually.",
    }
    return recommendations.get(category, "Review manually.")


def file_score_details(path: Path, category: str, file: LargeFile) -> dict[str, str]:
    confidence = {
        "installer": "70%",
        "archive": "52%",
        "video": "44%",
        "screenshot": "58%",
        "pdf": "38%",
        "image": "35%",
        "dataset": "30%",
        "large-file": "25%",
    }.get(category, "25%")
    redownloadable = {
        "installer": "yes",
        "archive": "maybe",
        "video": "maybe",
        "screenshot": "no",
        "pdf": "maybe",
        "image": "maybe",
        "dataset": "maybe",
    }.get(category, "maybe")
    return {
        "confidence": confidence,
        "re_downloadable": redownloadable,
        "age_days": str(age_days(file.modified_at)),
        "unused_days": str(unused_days(file.accessed_at)),
        "last_modified": file.modified_at.strftime("%Y-%m-%d"),
        "last_opened": file.accessed_at.strftime("%Y-%m-%d"),
        "extension": path.suffix.lower() or "(none)",
    }


def confidence_details(category: str, risk: str, reason: str, recommended: bool) -> dict[str, str]:
    if category == "cache" and risk == RISK_SAFE:
        confidence = "94%"
        redownloadable = "yes"
    elif category == "cache":
        confidence = "72%"
        redownloadable = "yes"
    elif category == "logs":
        confidence = "82%"
        redownloadable = "no"
    elif recommended:
        confidence = "70%"
        redownloadable = "maybe"
    else:
        confidence = "45%"
        redownloadable = "maybe"
    return {
        "confidence": confidence,
        "re_downloadable": redownloadable,
        "basis": reason,
    }


def is_screenshot(path: Path) -> bool:
    if path.suffix.lower() not in SCREENSHOT_EXTENSIONS:
        return False
    name = path.name.lower()
    return any(pattern in name for pattern in SCREENSHOT_NAME_PATTERNS)


def matching_installed_app(path: Path) -> str | None:
    app_root = Path("/Applications")
    if not app_root.exists():
        return None

    stem = normalize_name(path.stem)
    if not stem:
        return None
    try:
        apps = [item for item in app_root.iterdir() if item.suffix.lower() == ".app"]
    except (OSError, PermissionError):
        return None

    for app in apps:
        app_name = normalize_name(app.stem)
        if not app_name:
            continue
        if app_name in stem or stem in app_name:
            return app.name
        if "chrome" in stem and "chrome" in app_name:
            return app.name
        if "vscode" in stem and ("visualstudiocode" in app_name or "code" == app_name):
            return app.name
    return None


def matching_extracted_folder(path: Path) -> Path | None:
    candidates = []
    stem = path.name
    for suffix in sorted(ARCHIVE_EXTENSIONS, key=len, reverse=True):
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    candidates.append(path.with_name(stem))
    candidates.append(path.with_name(path.stem))

    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate
    return None


def normalize_name(value: str) -> str:
    value = re.sub(r"\d+(\.\d+)*", "", value.lower())
    return re.sub(r"[^a-z0-9]+", "", value)


def age_days(when: datetime) -> int:
    return max(0, (datetime.now() - when).days)


def unused_days(when: datetime) -> int:
    return max(0, (datetime.now() - when).days)


def dedupe_large_files(files: list[LargeFile]) -> list[LargeFile]:
    seen: set[Path] = set()
    deduped: list[LargeFile] = []
    for file in sorted(files, key=lambda item: item.size_bytes, reverse=True):
        resolved = safe_resolve(file.path)
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(file)
    return deduped


def write_report(result: ScanResult, output_path: Path) -> None:
    output_path = output_path.expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_report(result), encoding="utf-8")


def build_report(result: ScanResult) -> str:
    total = sum(target.size_bytes for target in result.targets if target.risk != RISK_DANGEROUS and target.deletable)
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
        "| Rank | Category | Size | Risk | Confidence | Re-downloadable | Path | Reason |",
        "|---|---|---:|---|---:|---|---|---|",
    ]

    for index, target in enumerate(result.targets, start=1):
        lines.append(
            "| "
            + " | ".join(
                [
                    str(index),
                    markdown_escape(target.name),
                    bytes_to_human(target.size_bytes),
                    target.risk,
                    target.details.get("confidence", "-"),
                    target.details.get("re_downloadable", "-"),
                    markdown_escape(target_path_label(target)),
                    markdown_escape(target.reason),
                ]
            )
            + " |"
        )

    lines.extend(storage_heatmap_section(result))
    lines.extend(downloads_breakdown_section(result))

    lines.extend(["", "---", "", "## Large Files Over 1 GB", "", "| File | Size | Last Modified | Last Opened |", "|---|---:|---|---|"])
    for file in result.large_files:
        if file.size_bytes < 1024**3:
            continue
        lines.append(
            f"| {markdown_escape(display_path(file.path))} | {bytes_to_human(file.size_bytes)} | {file.modified_at.strftime('%Y-%m-%d %H:%M')} | {file.accessed_at.strftime('%Y-%m-%d %H:%M')} |"
        )

    lines.extend(["", "---", "", "## Large Directories", "", "| Folder | Size |", "|---|---:|"])
    for target in result.large_directories:
        lines.append(f"| {markdown_escape(target_path_label(target))} | {bytes_to_human(target.size_bytes)} |")

    lines.extend(["", "---", "", "## Recommended Safe Deletions", ""])
    if safe:
        lines.extend(f"- {target.name}: `{display_path(target.path)}` ({bytes_to_human(target.size_bytes)})" for target in safe)
    else:
        lines.append("- None found above the configured threshold.")

    lines.extend(["", "---", "", "## Recommended Review Targets", ""])
    if review:
        lines.extend(f"- {target.name}: `{target_path_label(target)}` ({bytes_to_human(target.size_bytes)})" for target in review)
    else:
        lines.append("- None found above the configured threshold.")

    lines.extend(organizer_report_section(result))

    if result.warnings:
        lines.extend(["", "---", "", "## Scan Warnings", ""])
        lines.extend(f"- {warning}" for warning in result.warnings)

    lines.append("")
    return "\n".join(lines)


def organizer_report_section(result: ScanResult) -> list[str]:
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


def storage_heatmap_section(result: ScanResult) -> list[str]:
    lines = [
        "",
        "---",
        "",
        "## Storage Heatmap",
        "",
        "| Area | Size | Items | Recommendation |",
        "|---|---:|---:|---|",
    ]
    if not result.storage_heatmap:
        lines.append("| None | 0 B | 0 | No storage buckets found. |")
        return lines

    for bucket in result.storage_heatmap:
        lines.append(
            f"| {markdown_escape(bucket.name)} | {bytes_to_human(bucket.size_bytes)} | {bucket.count} | {markdown_escape(bucket.recommendation)} |"
        )
    return lines


def downloads_breakdown_section(result: ScanResult) -> list[str]:
    lines = [
        "",
        "---",
        "",
        "## Downloads Breakdown",
        "",
        "| Type | Size | Files | Recommendation |",
        "|---|---:|---:|---|",
    ]
    if not result.downloads_breakdown:
        lines.append("| None | 0 B | 0 | Downloads folder not found or empty. |")
        return lines

    for bucket in result.downloads_breakdown:
        lines.append(
            f"| {markdown_escape(bucket.name)} | {bytes_to_human(bucket.size_bytes)} | {bucket.count} | {markdown_escape(bucket.recommendation)} |"
        )
    return lines


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


def print_storage_heatmap(buckets: list[StorageBucket]) -> None:
    print("\nTop storage areas:")
    if not buckets:
        print("No storage heatmap buckets found.")
        return
    for bucket in buckets[:8]:
        print(f"- {bucket.name:<18} {bytes_to_human(bucket.size_bytes):>10}  {bucket.count} items")


def print_organizer_summary(buckets: list[OrganizerBucket], report_path: Path) -> None:
    print("\nOrganizer suggestions:")
    if not buckets:
        print("No large organizer buckets found.")
        return

    for bucket in buckets[:8]:
        print(f"- {bucket.name:<14} {bytes_to_human(bucket.size_bytes):>10}  {len(bucket.files)} files")
    print(f"Full organizer details are in {display_path(report_path)}.")


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
    seen_indexes: set[int] = set()
    for part in raw.replace(",", " ").split():
        if not part.isdigit():
            print(f"Ignoring invalid selection: {part}")
            continue
        index = int(part)
        if index in seen_indexes:
            continue
        seen_indexes.add(index)
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


def expand_path(path: str | Path) -> Path:
    return Path(path).expanduser()


def safe_resolve(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=False)
    except OSError:
        return path.expanduser().absolute()


def is_relative_to(path: Path, parent: Path) -> bool:
    path = safe_resolve(path)
    parent = safe_resolve(parent)
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def display_path(path: str | Path) -> str:
    raw = str(expand_path(path))
    home = str(HOME)
    if raw == home:
        return "~"
    if raw.startswith(home + "/"):
        return "~/" + raw[len(home) + 1 :]
    return raw


def bytes_to_human(size: int) -> str:
    value = float(max(size, 0))
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def parse_human_size(value: str) -> int:
    text = value.strip().upper().replace("IB", "B")
    if not text:
        return 0

    number = ""
    unit = ""
    for char in text:
        if char.isdigit() or char == ".":
            number += char
        elif char.isalpha():
            unit += char

    if not number:
        return 0

    multipliers = {
        "B": 1,
        "K": 1024,
        "KB": 1024,
        "M": 1024**2,
        "MB": 1024**2,
        "G": 1024**3,
        "GB": 1024**3,
        "T": 1024**4,
        "TB": 1024**4,
    }
    return int(float(number) * multipliers.get(unit or "B", 1))


def is_protected_exact_path(path: Path) -> bool:
    resolved = safe_resolve(path)
    return any(resolved == safe_resolve(protected) for protected in PROTECTED_EXACT_PATHS)


def is_system_protected_path(path: Path) -> bool:
    resolved = safe_resolve(path)
    system_roots = (Path("/System"), Path("/Library"), Path("/usr"), Path("/bin"), Path("/sbin"), Path("/Applications"))
    return any(resolved == root or is_relative_to(resolved, root) for root in system_roots)


def should_prune_scan_dir(path: Path) -> bool:
    resolved = safe_resolve(path)
    if resolved.name in {".git", ".svn", ".hg"}:
        return True
    return any(resolved == safe_resolve(root) for root in PROTECTED_SCAN_ROOTS)


def is_source_repo_root(path: Path) -> bool:
    return (path / ".git").exists()


def directory_size(path: Path) -> int:
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            if current.is_symlink():
                continue
            if current.is_file():
                total += current.stat().st_size
                continue
            for child in current.iterdir():
                try:
                    if child.is_symlink():
                        continue
                    if child.is_dir():
                        stack.append(child)
                    elif child.is_file():
                        total += child.stat().st_size
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            continue
    return total


def path_size(path: Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    return directory_size(path)


def file_modified_at(path: Path) -> datetime:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime)
    except OSError:
        return datetime.fromtimestamp(0)


def file_accessed_at(path: Path) -> datetime:
    try:
        return datetime.fromtimestamp(path.stat().st_atime)
    except OSError:
        return datetime.fromtimestamp(0)


def iter_existing(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        expanded = path.expanduser()
        if expanded.exists():
            yield expanded


def target_path_label(target: CleanupTarget) -> str:
    if len(target.paths) == 1:
        return display_path(target.path)
    return f"{len(target.paths)} paths, starting at {display_path(target.path)}"


def markdown_escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


if __name__ == "__main__":
    raise SystemExit(main())
