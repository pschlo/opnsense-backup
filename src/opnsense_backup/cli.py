from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def env_or_value(value: str | None, env_name: str) -> str | None:
    if value is not None:
        return value
    env_value = os.environ.get(env_name)
    if env_value is None or env_value.strip() == "":
        return None
    return env_value


def require_value(value: str | None, name: str, env_name: str) -> str:
    if value is None:
        raise RuntimeError(f"Missing {name}. Set --{name.replace('_', '-')} or {env_name}.")
    return value


def normalize_host_to_base_url(host: str) -> str:
    host = host.strip()
    if not host:
        raise RuntimeError("Host must not be empty")

    if "://" not in host:
        host = f"https://{host}"

    parsed = urllib.parse.urlparse(host)
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError(f"Unsupported URL scheme for host: {parsed.scheme!r}")

    if not parsed.netloc:
        raise RuntimeError(f"Invalid host: {host!r}")

    if parsed.path not in ("", "/"):
        raise RuntimeError(
            "Host must not include a path; pass only hostname[:port] or full base URL without path"
        )

    if parsed.params or parsed.query or parsed.fragment:
        raise RuntimeError("Host must not include params, query, or fragment")

    return f"{parsed.scheme}://{parsed.netloc}"


def build_auth_header(api_key: str, api_secret: str) -> str:
    token = base64.b64encode(f"{api_key}:{api_secret}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def make_ssl_context(insecure: bool) -> ssl.SSLContext | None:
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_get(
    url: str,
    auth_header: str,
    ssl_context: ssl.SSLContext | None,
    timeout: int,
) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": auth_header,
            "Accept": "*/*",
            "User-Agent": "opnsense-backup/0.1.0",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for {url}\n{body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request failed for {url}: {exc}") from exc


def ensure_within_dir(base_dir: Path, path: Path) -> Path:
    """
    Resolve `path` and ensure it stays within `base_dir`.
    Returns the resolved path.
    """
    base_resolved = base_dir.resolve()
    path_resolved = path.resolve()

    try:
        path_resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise RuntimeError(
            f"Refusing to access path outside output directory: {path}"
        ) from exc

    return path_resolved


def safe_mkdir(path: Path, out_dir: Path) -> Path:
    resolved = ensure_within_dir(out_dir, path)
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def write_bytes_if_changed(path: Path, content: bytes, out_dir: Path) -> bool:
    """
    Write only if the file does not exist or content changed.
    Returns True if the file was written, False otherwise.
    """
    target = ensure_within_dir(out_dir, path)
    safe_mkdir(target.parent, out_dir)

    if target.exists():
        try:
            existing = target.read_bytes()
            if existing == content:
                return False
        except OSError as exc:
            raise RuntimeError(f"Failed reading existing file {target}: {exc}") from exc

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        os.replace(tmp_path, target)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return True


def write_text_if_changed(path: Path, content: str, out_dir: Path) -> bool:
    return write_bytes_if_changed(path, content.encode("utf-8"), out_dir)


def parse_backups_payload(raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Failed to parse JSON response from backups endpoint") from exc

    if not isinstance(data, dict):
        raise RuntimeError("Unexpected backups response: expected JSON object")
    return data


BackupEntry = dict[str, Any]

def extract_backup_entries(payload: dict[str, Any]) -> list[BackupEntry]:
    items = payload["items"]
    if not isinstance(items, list):
        raise RuntimeError("Unexpected backups response: 'items' is not a list")

    entries: list[BackupEntry] = []
    seen_ids: set[str] = set()

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise RuntimeError(f"Unexpected backups response: item {index} is not an object")

        backup_id = item.get("id")
        if not isinstance(backup_id, str) or not backup_id:
            raise RuntimeError(f"Unexpected backups response: item {index} missing string 'id'")

        if backup_id in seen_ids:
            raise RuntimeError("Duplicate backup IDs")

        seen_ids.add(backup_id)
        entries.append(item)

    return entries


def local_history_file_timestamp(path: Path) -> float:
    """
    Extract timestamp from filenames like:
    config-1774471269.8738.xml
    """
    name = path.name
    prefix = "config-"
    suffix = ".xml"

    if not name.startswith(prefix) or not name.endswith(suffix):
        raise RuntimeError(f"Unexpected history filename format: {name}")

    raw = name[len(prefix):-len(suffix)]
    return float(raw)


def select_history_entries(
    entries: list[BackupEntry],
    keep_days: int | None,
) -> list[BackupEntry]:
    """Choose entries from the last N days."""
    def entry_timestamp(item: BackupEntry) -> float:
        return float(item["time"])

    sorted_entries = sorted(entries, key=entry_timestamp, reverse=True)

    if keep_days is None:
        return sorted_entries

    cutoff = time.time() - (keep_days * 86400)
    return [entry for entry in sorted_entries if entry_timestamp(entry) >= cutoff]


def download_current_config(
    base_url: str,
    auth_header: str,
    ssl_context: ssl.SSLContext | None,
    timeout: int,
    out_dir: Path,
) -> None:
    url = f"{base_url}/api/core/backup/download/this"
    content = http_get(url, auth_header, ssl_context, timeout)
    target = out_dir / "current" / "config.xml"
    written = write_bytes_if_changed(target, content, out_dir)
    if written:
        print(f"updated current config: {target}")
    else:
        print(f"current config unchanged: {target}")


def download_backup_listing(
    base_url: str,
    auth_header: str,
    ssl_context: ssl.SSLContext | None,
    timeout: int,
    out_dir: Path,
) -> dict[str, Any]:
    url = f"{base_url}/api/core/backup/backups/this"
    content = http_get(url, auth_header, ssl_context, timeout)
    payload = parse_backups_payload(content)

    metadata_path = out_dir / "metadata" / "backups.json"
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    changed = write_text_if_changed(metadata_path, serialized, out_dir)
    if changed:
        print(f"updated metadata: {metadata_path}")
    else:
        print(f"metadata unchanged: {metadata_path}")

    return payload


def download_history_configs(
    base_url: str,
    auth_header: str,
    ssl_context: ssl.SSLContext | None,
    timeout: int,
    out_dir: Path,
    entries: list[BackupEntry],
) -> None:
    history_dir = safe_mkdir(out_dir / "history", out_dir)

    downloaded = 0
    skipped = 0

    for entry in entries:
        backup_id = entry["id"]
        target = ensure_within_dir(out_dir, history_dir / backup_id)

        if target.exists():
            skipped += 1
            print(f"history exists, skipping: {target}")
            continue

        encoded_id = urllib.parse.quote(backup_id, safe="")
        url = f"{base_url}/api/core/backup/download/this/{encoded_id}"
        content = http_get(url, auth_header, ssl_context, timeout)
        written = write_bytes_if_changed(target, content, out_dir)
        if written:
            downloaded += 1
            print(f"downloaded history: {target}")
        else:
            skipped += 1
            print(f"history unchanged: {target}")

    print(f"history summary: downloaded={downloaded} skipped_existing={skipped}")


def prune_local_history(
    out_dir: Path,
    keep_days: int,
) -> None:
    history_dir = safe_mkdir(out_dir / "history", out_dir)
    cutoff = time.time() - (keep_days * 86400)

    local_files: list[Path] = [
        ensure_within_dir(out_dir, path)
        for path in history_dir.iterdir()
        if path.is_file()
    ]

    deleted = 0
    kept = 0

    for path in local_files:
        timestamp = local_history_file_timestamp(path)
        if timestamp >= cutoff:
            kept += 1
            continue

        path.unlink()
        deleted += 1
        print(f"pruned history: {path}")

    print(f"history prune summary: deleted={deleted} kept={kept}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opnsense-backup",
        description="Download current and historical OPNsense config backups",
    )

    parser.add_argument(
        "--host",
        help="OPNsense host or base URL, e.g. router.example.com or https://router.example.com "
             "(env: OPNSENSE_HOST)",
    )
    parser.add_argument(
        "--api-key",
        help="OPNsense API key (env: OPNSENSE_API_KEY)",
    )
    parser.add_argument(
        "--api-secret",
        help="OPNsense API secret (env: OPNSENSE_API_SECRET)",
    )
    parser.add_argument("--out-dir", required=True, help="Output directory")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--keep-days",
        type=int,
        help="Keep history entries from the last N days locally",
    )

    return parser


def run_sync(args: argparse.Namespace) -> int:
    host = require_value(
        env_or_value(args.host, "OPNSENSE_HOST"),
        "host",
        "OPNSENSE_HOST",
    )
    api_key = require_value(
        env_or_value(args.api_key, "OPNSENSE_API_KEY"),
        "api_key",
        "OPNSENSE_API_KEY",
    )
    api_secret = require_value(
        env_or_value(args.api_secret, "OPNSENSE_API_SECRET"),
        "api_secret",
        "OPNSENSE_API_SECRET",
    )
    if args.keep_days is not None and args.keep_days < 0:
        raise RuntimeError("--keep-days must be >= 0")

    base_url = normalize_host_to_base_url(host)
    auth_header = build_auth_header(api_key, api_secret)
    ssl_context = make_ssl_context(args.insecure)

    out_dir = Path(args.out_dir).expanduser().resolve()
    if not out_dir.exists():
        raise RuntimeError(f"Output directory does not exist: {out_dir}")

    if not out_dir.is_dir():
        raise RuntimeError(f"Output path is not a directory: {out_dir}")

    if not os.access(out_dir, os.W_OK):
        raise RuntimeError(f"Output directory is not writable: {out_dir}")

    download_current_config(
        base_url=base_url,
        auth_header=auth_header,
        ssl_context=ssl_context,
        timeout=args.timeout,
        out_dir=out_dir,
    )

    payload = download_backup_listing(
        base_url=base_url,
        auth_header=auth_header,
        ssl_context=ssl_context,
        timeout=args.timeout,
        out_dir=out_dir,
    )

    entries = extract_backup_entries(payload)
    print(f"found {len(entries)} historical backup entries")

    selected_entries = select_history_entries(entries, args.keep_days)
    print(f"selected {len(selected_entries)} historical backup entries for download")

    download_history_configs(
        base_url=base_url,
        auth_header=auth_header,
        ssl_context=ssl_context,
        timeout=args.timeout,
        out_dir=out_dir,
        entries=selected_entries,
    )

    if args.keep_days is not None:
        prune_local_history(
            out_dir=out_dir,
            keep_days=args.keep_days,
        )

    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        raise SystemExit(run_sync(args))
    except RuntimeError as exc:
        eprint(f"error: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
