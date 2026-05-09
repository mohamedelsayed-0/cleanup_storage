# Mac Storage Cleanup Tool

One-file, terminal-based Mac storage scanner and cleanup assistant.

```bash
python3 cleanup.py
```

It scans for large low-value storage, writes `cleanup_report.md`, asks what to delete in the terminal, and only deletes after you type exactly `DELETE`.

## Quick Use

```bash
# scan only
python3 cleanup.py --dry-run

# interactive cleanup
python3 cleanup.py

# faster scan without duplicate hashing
python3 cleanup.py --dry-run --no-duplicates

# slower scan that includes app bundle sizing
python3 cleanup.py --dry-run --scan-apps
```

Useful flags:

```bash
--scan-root ~/Desktop/Projects
--min-target-mb 250
--duplicate-min-mb 500
--deep
--report cleanup_report.md
--log cleanup_log.txt
```

## What It Looks For

- Caches: pip, Homebrew, Torch, HuggingFace, app caches
- Developer junk: `node_modules`, `.venv`, `venv`, `__pycache__`, conda envs
- AI storage: Ollama models, model/checkpoint files
- Downloads: installers, archives, PDFs, videos, datasets, images
- Media clutter: screenshots, videos, screen recordings
- Hidden macOS storage: Application Support, Messages attachments, Xcode data
- Large apps in `/Applications`
- Git repo bloat
- Exact duplicate files

## Safety Rules

- No automatic deletion.
- Every selected deletion requires `DELETE`.
- Source repos and `.git` folders are protected.
- System paths are protected.
- Manual-only targets are reported but not deleted by the tool.
- Live app caches may only partially clear; close the app and rerun if files remain.

Protected roots include `~/Documents`, `~/Desktop`, `~/Pictures`, `~/Movies`, `~/Music`, `~/Applications`, `/System`, `/Library`, `/usr`, `/bin`, `/sbin`, and `/Applications`.

## Generated Files

- `cleanup_report.md`: ranked suggestions, storage heatmap, duplicates, organizer notes
- `cleanup_log.txt`: deletion history
