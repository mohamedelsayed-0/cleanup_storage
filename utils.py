from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable


RISK_SAFE = "SAFE"
RISK_REVIEW = "REVIEW"
RISK_DANGEROUS = "DANGEROUS"

HOME = Path.home()


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
    category: str


@dataclass(frozen=True)
class OrganizerBucket:
    name: str
    action: str
    size_bytes: int
    files: tuple[LargeFile, ...]


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


def file_modified_at(path: Path) -> datetime:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime)
    except OSError:
        return datetime.fromtimestamp(0)


def iter_existing(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        expanded = path.expanduser()
        if expanded.exists():
            yield expanded


def markdown_escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
