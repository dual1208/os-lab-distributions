#!/usr/bin/env python3
"""Seal or verify the fixed campus-link certificate-rotation manifest.

There are intentionally no path arguments.  Production always uses
/var/lib/campus-link/rotation; isolated tests use the same fixed descendants
under CAMPUS_LINK_ROTATION_TEST_ROOT.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Any

from campus_link_rotation_state import (
    ARTIFACTS,
    STATES,
    RotationError,
    atomic_write,
    canonical_json,
    decode_json_bytes,
    layout,
    read_json_file,
    read_regular,
    read_row,
    require_directory,
    sha256_bytes,
    validate_assignments,
    validate_manifest,
    validate_rows,
)


def _strict_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("verb", choices=("seal", "verify"))
    parser.add_argument("--mode", choices=("production", "isolated-test"), required=True)
    if len(argv) != 3 or argv[1] != "--mode":
        parser.error("only a fixed verb and --mode are accepted")
    return parser.parse_args(argv)


def _production_boundary(mode: str) -> None:
    if mode != "production":
        return
    if getattr(os, "geteuid", lambda: 1)() != 0:
        raise RotationError("production manifest sealing requires root")
    if "CAMPUS_LINK_ROTATION_TEST_ROOT" in os.environ:
        raise RotationError("production manifest sealing rejects test overrides")
    raise RotationError(
        "production sealing is disabled until authenticated per-host artifact attestations exist"
    )


def _manifest_value(rotation_root: Path, production: bool) -> dict[str, Any]:
    assignments_path = rotation_root / "identity-assignments.json"
    assignments = validate_assignments(
        read_json_file(
            assignments_path,
            0o400,
            production=production,
            label="identity assignments",
        )
    )
    rows_root = rotation_root / "rows"
    require_directory(rows_root, 0o700, production=production)
    if sorted(item.name for item in rows_root.iterdir()) != sorted(STATES):
        raise RotationError("sealed state directory set is invalid")
    states: dict[str, dict[str, str]] = {}
    for state_name in STATES:
        row = read_row(rows_root / state_name, production=production, file_mode=0o400)
        states[state_name] = {
            artifact: sha256_bytes(row[artifact]) for artifact in ARTIFACTS
        }
    identity_and_states = {
        "artifacts": list(ARTIFACTS),
        "identity_assignments": assignments,
        "states": states,
    }
    manifest_id = hashlib.sha256(canonical_json(identity_and_states)).hexdigest()[:32]
    value = {
        "format": 1,
        "manifest_id": manifest_id,
        **identity_and_states,
    }
    checked_states, checked_assignments = validate_manifest(value)
    validate_rows(
        rows_root,
        checked_states,
        checked_assignments,
        production=production,
    )
    return value


def _seal(mode: str) -> str:
    selected = layout(mode)
    production = mode == "production"
    require_directory(selected.rotation_root, 0o700, production=production)
    for marker in (selected.active, selected.closed, selected.stage):
        if marker.exists() or marker.is_symlink():
            raise RotationError("manifest cannot be replaced during a bound transaction")
    value = _manifest_value(selected.rotation_root, production)
    raw = canonical_json(value)
    atomic_write(selected.manifest, raw, 0o444)
    # Re-open through the strict verifier after publication.
    published_raw = read_regular(selected.manifest, 0o444, production=production)
    if published_raw != raw:
        raise RotationError("published manifest changed during sealing")
    published = decode_json_bytes(
        published_raw, "rotation manifest", require_canonical=True
    )
    states, assignments = validate_manifest(published)
    validate_rows(selected.rows, states, assignments, production=production)
    return sha256_bytes(published_raw)


def _verify(mode: str) -> str:
    selected = layout(mode)
    production = mode == "production"
    require_directory(selected.rotation_root, 0o700, production=production)
    verified_raw = read_regular(selected.manifest, 0o444, production=production)
    value = decode_json_bytes(
        verified_raw, "rotation manifest", require_canonical=True
    )
    states, assignments = validate_manifest(value)
    validate_rows(selected.rows, states, assignments, production=production)
    return sha256_bytes(verified_raw)


def main(argv: list[str] | None = None) -> int:
    arguments = _strict_arguments(list(sys.argv[1:] if argv is None else argv))
    try:
        _production_boundary(arguments.mode)
        digest = _seal(arguments.mode) if arguments.verb == "seal" else _verify(arguments.mode)
    except (OSError, RotationError) as error:
        print(f"certificate-rotation manifest rejected state: {error}", file=sys.stderr)
        return 1
    print(f"ROTATION_MANIFEST_SHA256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
