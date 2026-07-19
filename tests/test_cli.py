from pathlib import Path

import pytest

from opnsense_backup.cli import (
    build_auth_header,
    ensure_within_dir,
    extract_backup_entries,
    normalize_host_to_base_url,
    parse_backups_payload,
    write_bytes_if_changed,
)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("router.example.com", "https://router.example.com"),
        ("https://router.example.com/", "https://router.example.com"),
        ("http://192.0.2.1:8080", "http://192.0.2.1:8080"),
    ],
)
def test_normalize_host(host: str, expected: str) -> None:
    assert normalize_host_to_base_url(host) == expected


def test_auth_header() -> None:
    assert build_auth_header("key", "secret") == "Basic a2V5OnNlY3JldA=="


def test_path_must_stay_inside_output_directory(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="outside output directory"):
        ensure_within_dir(tmp_path, tmp_path / ".." / "escape.xml")


def test_write_bytes_only_when_content_changes(tmp_path: Path) -> None:
    destination = tmp_path / "current" / "config.xml"

    assert write_bytes_if_changed(destination, b"first", tmp_path)
    assert not write_bytes_if_changed(destination, b"first", tmp_path)
    assert write_bytes_if_changed(destination, b"second", tmp_path)
    assert destination.read_bytes() == b"second"


def test_parse_and_extract_backup_entries() -> None:
    payload = parse_backups_payload(b'{"items": [{"id": "config-1.xml"}]}')

    assert extract_backup_entries(payload) == [{"id": "config-1.xml"}]


def test_duplicate_backup_ids_are_rejected() -> None:
    with pytest.raises(RuntimeError, match="Duplicate"):
        extract_backup_entries({"items": [{"id": "same"}, {"id": "same"}]})
