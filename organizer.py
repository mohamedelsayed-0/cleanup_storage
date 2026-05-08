from __future__ import annotations

from collections import defaultdict

from utils import LargeFile, OrganizerBucket


ORGANIZER_ACTIONS = {
    "installer": "Review installers. Most old .dmg and .pkg files can be deleted after installation.",
    "archive": "Review archives. Keep only source archives that cannot be downloaded again.",
    "video": "Move wanted videos to a media folder or external storage; delete throwaway captures.",
    "large-file": "Review manually. Large files are not safe to classify automatically.",
}


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
