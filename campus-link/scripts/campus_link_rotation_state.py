#!/usr/bin/env python3
"""Strict state and filesystem primitives for bounded certificate rotation.

This module deliberately contains no networking, process launcher, or generic
extension mechanism.  The privileged driver and the offline manifest sealer use
the same exact artifact/state vocabulary and the same fail-closed parsers.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


FORMAT = 1
MAX_FILE_BYTES = 65_536
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
SAFE_VALUE = re.compile(r"[A-Za-z0-9._:+/-]+\Z")
SPKI_PIN = re.compile(r"sha256/[A-Za-z0-9+/]{43}=\Z")

IDENTITIES = (
    "relay-control",
    "site-a-control",
    "site-a-data",
    "site-b-control",
    "site-b-data",
)
OBSERVERS = (
    "relay.local-control",
    "relay.site-a-control",
    "relay.site-b-control",
    "edge-a.local-control",
    "edge-a.peer-control",
    "edge-a.local-data",
    "edge-a.peer-data",
    "edge-b.local-control",
    "edge-b.peer-control",
    "edge-b.local-data",
    "edge-b.peer-data",
)
COMPONENTS = ("relay", "edge-a", "edge-b")
EDGES = ("edge-a", "edge-b")
EXPIRY_AUTHORITIES = (
    "edge-control",
    "relay-listener",
    "relay-data",
    "direct-data",
)
ARTIFACTS = (
    "relay.config",
    "relay.control-cert",
    "relay.control-key",
    "edge-a.config",
    "edge-a.control-cert",
    "edge-a.control-key",
    "edge-a.data-cert",
    "edge-a.data-key",
    "edge-b.config",
    "edge-b.control-cert",
    "edge-b.control-key",
    "edge-b.data-cert",
    "edge-b.data-key",
)
STATES = (
    "pre",
    "overlap",
    "relay-next",
    "edge-a-next",
    "edge-b-next",
    "retiring",
    "post",
)
CHANGE_SETS = {
    ("pre", "overlap"): {"relay.config", "edge-a.config", "edge-b.config"},
    ("overlap", "relay-next"): {"relay.control-cert", "relay.control-key"},
    ("relay-next", "edge-a-next"): {
        "edge-a.control-cert",
        "edge-a.control-key",
        "edge-a.data-cert",
        "edge-a.data-key",
    },
    ("edge-a-next", "edge-b-next"): {
        "edge-b.control-cert",
        "edge-b.control-key",
        "edge-b.data-cert",
        "edge-b.data-key",
    },
    ("edge-b-next", "retiring"): set(),
    ("retiring", "post"): {"relay.config", "edge-a.config", "edge-b.config"},
}
ACTIVATION_NEW_OBSERVERS = {
    "relay": {
        "relay.local-control",
        "edge-a.peer-control",
        "edge-b.peer-control",
    },
    "edge-a": {
        "relay.site-a-control",
        "edge-a.local-control",
        "edge-a.local-data",
        "edge-b.peer-data",
    },
    "edge-b": {
        "relay.site-b-control",
        "edge-b.local-control",
        "edge-b.local-data",
        "edge-a.peer-data",
    },
}

STAGE_KEYS = (
    "FORMAT",
    "RUN_ID",
    "CANDIDATE_SHA256",
    "ROTATION_ID",
    "ROTATION_MANIFEST_SHA256",
    "STATE",
)
ACTIVE_KEYS = (
    "FORMAT",
    "STATUS",
    "GATE",
    "MODE",
    "RUN_ID",
    "CANDIDATE_SHA256",
    "RUN_MANIFEST_SHA256",
    "PREREQUISITE_MARKER_SHA256",
    "ROTATION_ID",
    "ROTATION_MANIFEST_SHA256",
    "START_MONOTONIC_MS",
)


class RotationError(ValueError):
    """A rotation input or state violates the fixed contract."""


@dataclass(frozen=True)
class Layout:
    mode: str
    test_root: Path | None
    rotation_root: Path
    rows: Path
    live: Path
    transactions: Path
    manifest: Path
    stage: Path
    run_root: Path
    active: Path
    closed: Path


def layout(mode: str) -> Layout:
    if mode == "production":
        root = Path("/var/lib/campus-link/rotation")
        run = Path("/run/campus-link")
        test_root = None
    elif mode == "isolated-test":
        raw = os.environ.get("CAMPUS_LINK_ROTATION_TEST_ROOT", "")
        if not raw or "\x00" in raw:
            raise RotationError("isolated rotation root is not configured")
        test_root = Path(raw)
        if not test_root.is_absolute():
            raise RotationError("isolated rotation root must be absolute")
        root = test_root / "var" / "lib" / "campus-link" / "rotation"
        run = test_root / "run" / "campus-link"
    else:
        raise RotationError("rotation mode is invalid")
    return Layout(
        mode=mode,
        test_root=test_root,
        rotation_root=root,
        rows=root / "rows",
        live=root / "live",
        transactions=root / "transactions",
        manifest=root / "manifest.json",
        stage=root / "stage.env",
        run_root=run,
        active=run / "certificate-rotation.active",
        closed=run / "certificate-rotation.closed",
    )


def exact_object(value: Any, keys: Iterable[str], label: str) -> dict[str, Any]:
    expected = set(keys)
    if not isinstance(value, dict) or set(value) != expected:
        raise RotationError(f"{label} schema is invalid")
    return value


def duplicate_rejecting_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RotationError("duplicate JSON object key")
        result[key] = value
    return result


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def decode_json_bytes(raw: bytes, label: str, *, require_canonical: bool) -> Any:
    if not raw or len(raw) > MAX_FILE_BYTES or b"\x00" in raw or not raw.endswith(b"\n"):
        raise RotationError(f"{label} encoding is invalid")
    try:
        value = json.loads(raw, object_pairs_hook=duplicate_rejecting_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RotationError(f"{label} is not valid JSON") from error
    if require_canonical and canonical_json(value) != raw:
        raise RotationError(f"{label} is not canonical JSON")
    return value


def _mode_matches(actual: int, expected: int, production: bool) -> bool:
    if production or os.name != "nt":
        return actual == expected
    # Windows exposes only a coarse read-only bit.  This accommodation is
    # isolated-test-only; production Linux checks remain exact.
    if expected in {0o400, 0o444}:
        return actual & 0o222 == 0
    return actual & 0o222 != 0


def require_directory(path: Path, mode: int, *, production: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RotationError(f"required directory is unavailable: {path.name}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RotationError(f"required directory is unsafe: {path.name}")
    if not _mode_matches(stat.S_IMODE(metadata.st_mode), mode, production):
        raise RotationError(f"directory mode is invalid: {path.name}")
    if production and (metadata.st_uid != 0 or metadata.st_gid != 0):
        raise RotationError(f"directory ownership is invalid: {path.name}")


def read_regular(
    path: Path,
    mode: int,
    *,
    production: bool,
    allow_empty: bool = False,
) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise RotationError(f"required file is unavailable: {path.name}") from error
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise RotationError(f"required file is unsafe: {path.name}")
    if not _mode_matches(stat.S_IMODE(before.st_mode), mode, production):
        raise RotationError(f"file mode is invalid: {path.name}")
    if production and (before.st_uid != 0 or before.st_gid != 0):
        raise RotationError(f"file ownership is invalid: {path.name}")
    if before.st_size > MAX_FILE_BYTES or (before.st_size == 0 and not allow_empty):
        raise RotationError(f"file size is invalid: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RotationError(f"required file cannot be opened: {path.name}") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
        ):
            raise RotationError(f"required file changed while opening: {path.name}")
        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) > MAX_FILE_BYTES or (len(raw) == 0 and not allow_empty):
            raise RotationError(f"file size is invalid: {path.name}")
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise RotationError(f"required file changed while reading: {path.name}")
        return raw
    finally:
        os.close(descriptor)


def read_json_file(
    path: Path,
    mode: int,
    *,
    production: bool,
    label: str,
    require_canonical: bool = True,
) -> Any:
    return decode_json_bytes(
        read_regular(path, mode, production=production),
        label,
        require_canonical=require_canonical,
    )


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path, mode: int, *, production: bool) -> str:
    return sha256_bytes(read_regular(path, mode, production=production))


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: Path, raw: bytes, mode: int) -> None:
    if len(raw) > MAX_FILE_BYTES or not raw:
        raise RotationError("atomic output size is invalid")
    require_directory(path.parent, 0o700, production=False)
    nonce = f"{secrets.randbits(64):016x}"
    temporary = path.parent / f".{path.name}.{os.getpid()}.{nonce}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(temporary, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RotationError("atomic output write failed")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def atomic_json(path: Path, value: Any, mode: int = 0o600) -> None:
    atomic_write(path, canonical_json(value), mode)


def parse_env_marker(
    path: Path,
    keys: tuple[str, ...],
    *,
    production: bool,
    mode: int = 0o600,
) -> dict[str, str]:
    raw = read_regular(path, mode, production=production)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise RotationError("marker encoding is invalid") from error
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise RotationError("marker encoding is invalid")
    result: dict[str, str] = {}
    order: list[str] = []
    for line in text[:-1].split("\n"):
        if line.count("=") != 1:
            raise RotationError("marker line is invalid")
        key, value = line.split("=", 1)
        if key in result or SAFE_VALUE.fullmatch(value) is None:
            raise RotationError("marker value is invalid")
        result[key] = value
        order.append(key)
    if tuple(order) != keys:
        raise RotationError("marker schema or order is invalid")
    return result


def stage_value(bindings: dict[str, str], state: str) -> bytes:
    if state not in STATES:
        raise RotationError("stage state is invalid")
    values = {
        "FORMAT": "1",
        "RUN_ID": bindings["run_id"],
        "CANDIDATE_SHA256": bindings["candidate_sha256"],
        "ROTATION_ID": bindings["rotation_id"],
        "ROTATION_MANIFEST_SHA256": bindings["rotation_manifest_sha256"],
        "STATE": state,
    }
    return "".join(f"{key}={values[key]}\n" for key in STAGE_KEYS).encode("ascii")


def validate_stage(
    path: Path,
    bindings: dict[str, str],
    *,
    production: bool,
) -> str:
    marker = parse_env_marker(path, STAGE_KEYS, production=production)
    if marker["FORMAT"] != "1":
        raise RotationError("stage format is invalid")
    for field, key in (
        ("RUN_ID", "run_id"),
        ("CANDIDATE_SHA256", "candidate_sha256"),
        ("ROTATION_ID", "rotation_id"),
        ("ROTATION_MANIFEST_SHA256", "rotation_manifest_sha256"),
    ):
        if marker[field] != bindings[key]:
            raise RotationError("stage binding is invalid")
    if marker["STATE"] not in STATES:
        raise RotationError("stage state is invalid")
    return marker["STATE"]


def _pin(value: Any, label: str) -> str:
    if type(value) is not str or SPKI_PIN.fullmatch(value) is None:
        raise RotationError(f"{label} pin is invalid")
    try:
        decoded = base64.b64decode(value[7:], validate=True)
    except (ValueError, TypeError) as error:
        raise RotationError(f"{label} pin is invalid") from error
    if len(decoded) != 32:
        raise RotationError(f"{label} pin is invalid")
    return value


def validate_assignments(value: Any) -> dict[str, dict[str, str]]:
    assignments = exact_object(value, IDENTITIES, "identity assignments")
    result: dict[str, dict[str, str]] = {}
    seen: set[str] = set()
    for identity in IDENTITIES:
        slots = exact_object(assignments[identity], ("current", "next"), f"{identity} assignment")
        result[identity] = {}
        for slot in ("current", "next"):
            pin = _pin(slots[slot], f"{identity} {slot}")
            if pin in seen:
                raise RotationError("identity pins are reused")
            seen.add(pin)
            result[identity][slot] = pin
    return result


def validate_manifest(value: Any) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    manifest = exact_object(
        value,
        ("format", "manifest_id", "artifacts", "identity_assignments", "states"),
        "rotation manifest",
    )
    if type(manifest["format"]) is not int or manifest["format"] != FORMAT:
        raise RotationError("rotation manifest format is invalid")
    if (
        type(manifest["manifest_id"]) is not str
        or HEX32.fullmatch(manifest["manifest_id"]) is None
    ):
        raise RotationError("rotation manifest ID is invalid")
    if manifest["artifacts"] != list(ARTIFACTS):
        raise RotationError("rotation artifact order is invalid")
    assignments = validate_assignments(manifest["identity_assignments"])
    raw_states = exact_object(manifest["states"], STATES, "rotation states")
    states: dict[str, dict[str, str]] = {}
    for state_name in STATES:
        row = exact_object(raw_states[state_name], ARTIFACTS, f"{state_name} state")
        states[state_name] = {}
        for artifact in ARTIFACTS:
            digest = row[artifact]
            if type(digest) is not str or HEX64.fullmatch(digest) is None:
                raise RotationError(f"{state_name} artifact hash is invalid")
            states[state_name][artifact] = digest
        keys = [digest for name, digest in states[state_name].items() if name.endswith("-key")]
        certs = [digest for name, digest in states[state_name].items() if name.endswith("-cert")]
        if len(keys) != len(set(keys)) or len(certs) != len(set(certs)) or set(keys) & set(certs):
            raise RotationError(f"{state_name} reuses a credential artifact")
    for (prior_name, current_name), expected in CHANGE_SETS.items():
        prior = states[prior_name]
        current = states[current_name]
        changed = {name for name in ARTIFACTS if prior[name] != current[name]}
        if changed != expected:
            raise RotationError(f"{prior_name} to {current_name} transition is invalid")
    return states, assignments


def _der_length(raw: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(raw):
        raise RotationError("certificate DER is truncated")
    first = raw[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 4 or offset + 1 + count > len(raw):
        raise RotationError("certificate DER length is invalid")
    encoded = raw[offset + 1 : offset + 1 + count]
    if encoded[0] == 0 or (count == 1 and encoded[0] < 0x80):
        raise RotationError("certificate DER length is noncanonical")
    return int.from_bytes(encoded, "big"), offset + 1 + count


def _der_tlv(raw: bytes, offset: int) -> tuple[int, int, int, int]:
    if offset >= len(raw):
        raise RotationError("certificate DER is truncated")
    tag = raw[offset]
    if tag & 0x1F == 0x1F:
        raise RotationError("certificate DER uses an unsupported tag")
    length, content = _der_length(raw, offset + 1)
    end = content + length
    if end > len(raw):
        raise RotationError("certificate DER is truncated")
    return tag, content, end, offset


def _der_children(raw: bytes, content: int, end: int) -> list[tuple[int, int, int, int]]:
    children: list[tuple[int, int, int, int]] = []
    cursor = content
    while cursor < end:
        item = _der_tlv(raw, cursor)
        children.append(item)
        cursor = item[2]
    if cursor != end:
        raise RotationError("certificate DER nesting is invalid")
    return children


def certificate_spki_pin(raw: bytes) -> str:
    match = re.fullmatch(
        br"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\r?\n?",
        raw,
    )
    if match is None:
        raise RotationError("certificate PEM envelope is invalid")
    try:
        der = base64.b64decode(re.sub(br"\s+", b"", match.group(1)), validate=True)
    except (ValueError, TypeError) as error:
        raise RotationError("certificate PEM payload is invalid") from error
    outer = _der_tlv(der, 0)
    if outer[0] != 0x30 or outer[2] != len(der):
        raise RotationError("certificate DER envelope is invalid")
    certificate = _der_children(der, outer[1], outer[2])
    if len(certificate) != 3 or certificate[0][0] != 0x30:
        raise RotationError("certificate DER structure is invalid")
    tbs = _der_children(der, certificate[0][1], certificate[0][2])
    index = 1 if tbs and tbs[0][0] == 0xA0 else 0
    spki_index = index + 5
    if len(tbs) <= spki_index or tbs[spki_index][0] != 0x30:
        raise RotationError("certificate SPKI is unavailable")
    spki = der[tbs[spki_index][3] : tbs[spki_index][2]]
    return "sha256/" + base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def _authorization(
    value: Any,
    identity: str,
    expected_pin: str,
    next_pin: str | None,
    label: str,
) -> str:
    expected_keys = {"uri", "current_spki"} | ({"next_spki"} if next_pin is not None else set())
    auth = exact_object(value, expected_keys, label)
    endpoint, plane = identity.rsplit("-", 1)
    uri_pattern = re.compile(
        rf"spiffe://campus-link/([a-z0-9](?:[a-z0-9-]{{0,62}}))/{re.escape(endpoint)}/{plane}\Z"
    )
    if type(auth["uri"]) is not str or (match := uri_pattern.fullmatch(auth["uri"])) is None:
        raise RotationError(f"{label} URI is invalid")
    if auth["current_spki"] != expected_pin:
        raise RotationError(f"{label} current pin is invalid")
    if next_pin is not None and auth["next_spki"] != next_pin:
        raise RotationError(f"{label} next pin is invalid")
    return match.group(1)


def _config_slots(state_name: str) -> tuple[str, str | None]:
    if state_name == "pre":
        return "current", None
    if state_name == "post":
        return "next", None
    return "current", "next"


def validate_config_pins(
    artifact: str,
    raw: bytes,
    state_name: str,
    assignments: dict[str, dict[str, str]],
) -> set[str]:
    value = decode_json_bytes(raw, artifact, require_canonical=False)
    if not isinstance(value, dict):
        raise RotationError(f"{artifact} root is invalid")
    current_slot, next_slot = _config_slots(state_name)

    circuits: set[str] = set()

    def check(auth: Any, identity: str, label: str) -> None:
        current = assignments[identity][current_slot]
        following = assignments[identity][next_slot] if next_slot is not None else None
        circuits.add(_authorization(auth, identity, current, following, label))

    if artifact == "relay.config":
        controls = value.get("control_identities")
        if not isinstance(controls, dict) or set(controls) != {"site-a", "site-b"}:
            raise RotationError("relay control identity map is invalid")
        check(value.get("local_control_identity"), "relay-control", "relay local control")
        check(controls["site-a"], "site-a-control", "relay site-a control")
        check(controls["site-b"], "site-b-control", "relay site-b control")
    elif artifact == "edge-a.config":
        check(value.get("local_control_identity"), "site-a-control", "edge-a local control")
        check(value.get("control_identity"), "relay-control", "edge-a peer control")
        check(value.get("local_data_identity"), "site-a-data", "edge-a local data")
        check(value.get("data_identity"), "site-b-data", "edge-a peer data")
    elif artifact == "edge-b.config":
        check(value.get("local_control_identity"), "site-b-control", "edge-b local control")
        check(value.get("control_identity"), "relay-control", "edge-b peer control")
        check(value.get("local_data_identity"), "site-b-data", "edge-b local data")
        check(value.get("data_identity"), "site-a-data", "edge-b peer data")
    else:
        raise RotationError("unknown configuration artifact")
    return circuits


def _credential_slot(state_name: str, component: str) -> str:
    index = STATES.index(state_name)
    thresholds = {
        "relay": STATES.index("relay-next"),
        "edge-a": STATES.index("edge-a-next"),
        "edge-b": STATES.index("edge-b-next"),
    }
    return "next" if index >= thresholds[component] else "current"


def validate_row_semantics(
    row: dict[str, bytes],
    state_name: str,
    assignments: dict[str, dict[str, str]],
) -> None:
    circuits: set[str] = set()
    for config_name in ("relay.config", "edge-a.config", "edge-b.config"):
        circuits.update(
            validate_config_pins(config_name, row[config_name], state_name, assignments)
        )
    if len(circuits) != 1:
        raise RotationError(f"{state_name} configuration circuits are inconsistent")
    certificate_identities = {
        "relay.control-cert": ("relay", "relay-control"),
        "edge-a.control-cert": ("edge-a", "site-a-control"),
        "edge-a.data-cert": ("edge-a", "site-a-data"),
        "edge-b.control-cert": ("edge-b", "site-b-control"),
        "edge-b.data-cert": ("edge-b", "site-b-data"),
    }
    for artifact, (component, identity) in certificate_identities.items():
        slot = _credential_slot(state_name, component)
        if certificate_spki_pin(row[artifact]) != assignments[identity][slot]:
            raise RotationError(f"{state_name} certificate assignment is invalid")


def read_row(
    directory: Path,
    *,
    production: bool,
    file_mode: int,
) -> dict[str, bytes]:
    require_directory(directory, 0o700, production=production)
    try:
        names = sorted(item.name for item in directory.iterdir())
    except OSError as error:
        raise RotationError("artifact row cannot be listed") from error
    if names != sorted(ARTIFACTS):
        raise RotationError("artifact row entry set is invalid")
    return {
        artifact: read_regular(directory / artifact, file_mode, production=production)
        for artifact in ARTIFACTS
    }


def validate_rows(
    root: Path,
    states: dict[str, dict[str, str]],
    assignments: dict[str, dict[str, str]],
    *,
    production: bool,
) -> None:
    require_directory(root, 0o700, production=production)
    if sorted(item.name for item in root.iterdir()) != sorted(STATES):
        raise RotationError("sealed state directory set is invalid")
    for state_name in STATES:
        row = read_row(root / state_name, production=production, file_mode=0o400)
        for artifact, raw in row.items():
            if sha256_bytes(raw) != states[state_name][artifact]:
                raise RotationError(f"{state_name} {artifact} does not match the sealed manifest")
        validate_row_semantics(row, state_name, assignments)


def validate_live_row(
    live: Path,
    state_name: str,
    states: dict[str, dict[str, str]],
    assignments: dict[str, dict[str, str]],
    *,
    production: bool,
) -> dict[str, bytes]:
    row = read_row(live, production=production, file_mode=0o600)
    for artifact, raw in row.items():
        if sha256_bytes(raw) != states[state_name][artifact]:
            raise RotationError("live artifact set is not one complete sealed state")
    validate_row_semantics(row, state_name, assignments)
    return row


def monotonic_ms() -> int:
    return time.monotonic_ns() // 1_000_000
