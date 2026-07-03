from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.request
from typing import Iterable, List


DEFAULT_MANIFEST = Path("data/challenge_manifest.json")
DEFAULT_DATA_DIR = Path("data/challenges")


@dataclass
class ChallengeResource:
    name: str
    urls: List[str]


@dataclass
class DownloadResult:
    name: str
    path: str
    status: str
    url: str | None = None
    sha256: str | None = None
    size: int = 0
    error: str | None = None


def load_manifest(path: str | Path = DEFAULT_MANIFEST) -> List[ChallengeResource]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [ChallengeResource(name=item["name"], urls=list(item.get("urls", []))) for item in raw]


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_one(resource: ChallengeResource, data_dir: str | Path, *, force: bool = False) -> DownloadResult:
    out_dir = Path(data_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / resource.name
    if target.exists() and not force:
        return DownloadResult(
            name=resource.name,
            path=str(target),
            status="exists",
            sha256=sha256_file(target),
            size=target.stat().st_size,
        )

    last_error = None
    for url in resource.urls:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "vea-aeg-reproduction"})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            target.write_bytes(data)
            try:
                target.chmod(target.stat().st_mode | 0o111)
            except OSError:
                pass
            return DownloadResult(
                name=resource.name,
                path=str(target),
                status="downloaded",
                url=url,
                sha256=sha256_file(target),
                size=target.stat().st_size,
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)

    return DownloadResult(
        name=resource.name,
        path=str(target),
        status="failed",
        error=last_error or "no URL available",
    )


def download_manifest(
    resources: Iterable[ChallengeResource],
    data_dir: str | Path = DEFAULT_DATA_DIR,
    *,
    force: bool = False,
) -> List[DownloadResult]:
    return [download_one(resource, data_dir, force=force) for resource in resources]
