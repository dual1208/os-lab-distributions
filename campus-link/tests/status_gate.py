#!/usr/bin/env python3
"""Sanitized direct-path qualification evidence for campus-link."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import os
import re
import stat
import sys
import time
from pathlib import Path

try:
    import pwd
except ImportError:  # Windows unit tests have no POSIX account database.
    pwd = None

MAX_STATUS_BYTES = 64 * 1024
MAX_COUNTER = (1 << 64) - 1
MAX_STATUS_AGE_SECONDS = 15.0
MAX_FINAL_SNAPSHOT_AGE_SECONDS = 60.0
MAX_EVIDENCE_INTERVAL_SECONDS = 8 * 60 * 60
MAX_SOAK_EVIDENCE_INTERVAL_SECONDS = 8 * 24 * 60 * 60
MAX_SOAK_SAMPLE_INTERVAL_SECONDS = 10.0
MAX_SOAK_PUBLICATION_WAIT_SECONDS = 5.0
FUTURE_CLOCK_TOLERANCE_SECONDS = 2.0
CERTIFICATE_RECONNECT_MARGIN_SECONDS = 5 * 60
MAX_CERTIFICATE_REMAINING_SECONDS = 90 * 24 * 60 * 60
MAX_OUTER_RELAY_DATAGRAM_BYTES = 2048
RAW_RELAY_BYTE_BASE_PER_SITE = 64 * 1024
RAW_RELAY_BYTES_PER_SECOND = 64
SNAPSHOT_FORMAT = 1
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
BOOT_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
EDGE_SNAPSHOT_KEYS = {
    "status_generation", "selected_path_transitions", "identity_transitions",
    "selected", "direct_required", "direct_healthy", "direct_epoch", "direct_instance", "relay_sent",
    "relay_received", "direct_sent", "direct_received", "direct_progress",
    "watchdog_failures", "fallbacks", "queue_drops", "invalid_packets",
    "duplicate_packets", "dropped",
    "control_session", "telemetry_sequence", "relay_forwarded", "relay_forwarded_bytes",
    "relay_dropped", "relay_dropped_bytes",
    "control_identity", "data_identity", "clock",
}
EVIDENCE_KEYS = (
    "DIRECT_EVIDENCE_DURATION_MS",
    "EDGE_A_DIRECT_PROGRESS_DELTA",
    "EDGE_A_DIRECT_RECEIVED_DELTA",
    "EDGE_A_DIRECT_SENT_DELTA",
    "EDGE_A_DROPPED_DELTA",
    "EDGE_A_DUPLICATE_PACKETS_DELTA",
    "EDGE_A_FALLBACKS_DELTA",
    "EDGE_A_INVALID_PACKETS_DELTA",
    "EDGE_A_QUEUE_DROPS_DELTA",
    "EDGE_A_RELAY_RECEIVED_DELTA",
    "EDGE_A_RELAY_SENT_DELTA",
    "EDGE_A_WATCHDOG_FAILURES_DELTA",
    "EDGE_B_DIRECT_PROGRESS_DELTA",
    "EDGE_B_DIRECT_RECEIVED_DELTA",
    "EDGE_B_DIRECT_SENT_DELTA",
    "EDGE_B_DROPPED_DELTA",
    "EDGE_B_DUPLICATE_PACKETS_DELTA",
    "EDGE_B_FALLBACKS_DELTA",
    "EDGE_B_INVALID_PACKETS_DELTA",
    "EDGE_B_QUEUE_DROPS_DELTA",
    "EDGE_B_RELAY_RECEIVED_DELTA",
    "EDGE_B_RELAY_SENT_DELTA",
    "EDGE_B_WATCHDOG_FAILURES_DELTA",
    "RAW_RELAY_BYTE_LIMIT_PER_SITE",
    "RAW_RELAY_PACKET_LIMIT_PER_SITE",
    "RAW_RELAY_SITE_A_BYTES_DELTA",
    "RAW_RELAY_SITE_A_DELTA",
    "RAW_RELAY_SITE_B_BYTES_DELTA",
    "RAW_RELAY_SITE_B_DELTA",
)
FAULT_EVIDENCE_KEYS = (
    "FAULT_DIRECT_EVIDENCE_DURATION_MS",
    "FAULT_EDGE_A_DIRECT_PROGRESS_DELTA",
    "FAULT_EDGE_A_DIRECT_RECEIVED_DELTA",
    "FAULT_EDGE_A_DIRECT_SENT_DELTA",
    "FAULT_EDGE_A_DROPPED_DELTA",
    "FAULT_EDGE_A_DUPLICATE_PACKETS_DELTA",
    "FAULT_EDGE_A_FALLBACKS_DELTA",
    "FAULT_EDGE_A_INVALID_PACKETS_DELTA",
    "FAULT_EDGE_A_QUEUE_DROPS_DELTA",
    "FAULT_EDGE_A_RELAY_RECEIVED_DELTA",
    "FAULT_EDGE_A_RELAY_SENT_DELTA",
    "FAULT_EDGE_A_WATCHDOG_FAILURES_DELTA",
    "FAULT_EDGE_B_DIRECT_PROGRESS_DELTA",
    "FAULT_EDGE_B_DIRECT_RECEIVED_DELTA",
    "FAULT_EDGE_B_DIRECT_SENT_DELTA",
    "FAULT_EDGE_B_DROPPED_DELTA",
    "FAULT_EDGE_B_DUPLICATE_PACKETS_DELTA",
    "FAULT_EDGE_B_FALLBACKS_DELTA",
    "FAULT_EDGE_B_INVALID_PACKETS_DELTA",
    "FAULT_EDGE_B_QUEUE_DROPS_DELTA",
    "FAULT_EDGE_B_RELAY_RECEIVED_DELTA",
    "FAULT_EDGE_B_RELAY_SENT_DELTA",
    "FAULT_EDGE_B_WATCHDOG_FAILURES_DELTA",
    "FAULT_EXACT_PATH_IDENTITY_CHECKS",
    "FAULT_RAW_RELAY_BYTE_LIMIT_PER_SITE",
    "FAULT_RAW_RELAY_PACKET_LIMIT_PER_SITE",
    "FAULT_RAW_RELAY_SITE_A_BYTES_DELTA",
    "FAULT_RAW_RELAY_SITE_A_DELTA",
    "FAULT_RAW_RELAY_SITE_B_BYTES_DELTA",
    "FAULT_RAW_RELAY_SITE_B_DELTA",
    "FAULT_REESTABLISHED_DIRECT_PATHS",
    "FAULT_RELAY_CONTROL_SESSION_TRANSITIONS",
)


class GateError(RuntimeError):
    pass


class TelemetryTransitionError(GateError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise GateError(f"duplicate JSON key {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise GateError(f"invalid JSON constant {value}")


def _effective_identity() -> tuple[int, int] | None:
    """Return the gate identity where POSIX ownership has security meaning."""
    if os.name != "posix":
        return None
    return os.geteuid(), os.getegid()


def _site_identity(site: str) -> tuple[int, int] | None:
    if os.name != "posix":
        return None
    if site not in {"site-a", "site-b"}:
        raise GateError("invalid site owner request")
    if pwd is None:
        raise GateError("POSIX account database is unavailable")
    try:
        account = pwd.getpwnam(f"campus-link-{site[-1]}")
    except KeyError as error:
        raise GateError(f"{site} service identity is absent") from error
    return account.pw_uid, account.pw_gid


def _validate_opened_metadata(
    info: os.stat_result, expected_identity: tuple[int, int] | None,
    expected_mode: int | None = None,
) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise GateError("status is not a regular file")
    if info.st_nlink != 1:
        raise GateError("status link count is invalid")
    if expected_identity is not None:
        if (info.st_uid, info.st_gid) != expected_identity:
            raise GateError("status owner is invalid")
        if expected_mode is not None and stat.S_IMODE(info.st_mode) != expected_mode:
            raise GateError("status mode is invalid")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise GateError("status permissions are unsafe")


def _read_json_source(
    path: Path, expected_identity: tuple[int, int] | None = None,
    expected_mode: int | None = None,
) -> tuple[dict, tuple[int, int]]:
    identity = _effective_identity() if expected_identity is None else expected_identity
    if expected_identity is not None:
        parent = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or (parent.st_uid, parent.st_gid) != expected_identity
            or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise GateError("status parent directory ownership is invalid")
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise GateError("status is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _validate_opened_metadata(opened, identity, expected_mode)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise GateError("status changed while it was opened")
        if opened.st_size <= 0 or opened.st_size > MAX_STATUS_BYTES:
            raise GateError("status size is outside bounds")
        source_identity = (opened.st_dev, opened.st_ino)
        chunks = []
        remaining = MAX_STATUS_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(data) > MAX_STATUS_BYTES:
        raise GateError("status exceeds size bound")
    value = json.loads(
        data, object_pairs_hook=_unique_object, parse_constant=_reject_json_constant,
    )
    if not isinstance(value, dict):
        raise GateError("status root is not an object")
    return value, source_identity


def _read_json(path: Path) -> dict:
    value, _ = _read_json_source(path)
    return value


def _counter(container: dict, name: str) -> int:
    value = container.get(name)
    if type(value) is not int or value < 0 or value > MAX_COUNTER:  # bool is rejected.
        raise GateError(f"invalid counter {name}")
    return value


def _require_fresh_status(status: dict) -> None:
    encoded = status.get("updated")
    if type(encoded) is not str or len(encoded) > 64 or not encoded.endswith("Z"):
        raise GateError("status update timestamp is invalid")
    try:
        updated = datetime.datetime.fromisoformat(encoded[:-1] + "+00:00")
    except ValueError as error:
        raise GateError("status update timestamp is invalid") from error
    if updated.utcoffset() != datetime.timedelta(0):
        raise GateError("status update timestamp is not UTC")
    age = time.time() - updated.timestamp()
    if not math.isfinite(age) or age < -FUTURE_CLOCK_TOLERANCE_SECONDS:
        raise GateError("status update timestamp is in the future")
    if age > MAX_STATUS_AGE_SECONDS:
        raise GateError("status is stale")


def _certificate_status(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"expires", "pin_slot"}:
        raise GateError(f"{label} certificate status is malformed")
    encoded, slot = value["expires"], value["pin_slot"]
    if type(encoded) is not str or len(encoded) > 64 or not encoded.endswith("Z"):
        raise GateError(f"{label} certificate expiry is invalid")
    if slot not in {"current", "next"}:
        raise GateError(f"{label} certificate pin slot is invalid")
    try:
        expires = datetime.datetime.fromisoformat(encoded[:-1] + "+00:00")
    except ValueError as error:
        raise GateError(f"{label} certificate expiry is invalid") from error
    if expires.utcoffset() != datetime.timedelta(0):
        raise GateError(f"{label} certificate expiry is not UTC")
    remaining = expires.timestamp() - time.time()
    if (
        not math.isfinite(remaining)
        or remaining <= CERTIFICATE_RECONNECT_MARGIN_SECONDS
        or remaining > MAX_CERTIFICATE_REMAINING_SECONDS + FUTURE_CLOCK_TOLERANCE_SECONDS
    ):
        raise GateError(f"{label} certificate lifetime is outside bounds")
    return {"expires": encoded, "pin_slot": slot}


def _identity_plane(status: dict, name: str) -> dict[str, dict[str, str]]:
    value = status.get(name)
    if not isinstance(value, dict) or set(value) != {"local", "peer"}:
        raise GateError(f"{name} status is absent or malformed")
    return {
        endpoint: _certificate_status(value[endpoint], f"{name} {endpoint}")
        for endpoint in ("local", "peer")
    }


def _data_identity(
    status: dict, selected: str, selected_direct_epoch: int,
) -> dict[str, object]:
    value = status.get("data_identity")
    if not isinstance(value, dict) or set(value) != {
        "local", "peer", "path", "direct_epoch",
    }:
        raise GateError("data_identity status is absent or malformed")
    binding_path = value["path"]
    binding_epoch = _counter(value, "direct_epoch")
    if binding_path not in {"relay", "direct"} or binding_path != selected:
        raise GateError("data_identity is not bound to the selected path")
    if binding_path == "direct":
        if binding_epoch == 0 or binding_epoch != selected_direct_epoch:
            raise GateError("data_identity direct epoch is invalid")
    elif binding_epoch != 0:
        raise GateError("relay data_identity carries a direct epoch")
    return {
        "local": _certificate_status(value["local"], "data_identity local"),
        "peer": _certificate_status(value["peer"], "data_identity peer"),
        "path": binding_path,
        "direct_epoch": binding_epoch,
    }


def _clock_status(
    status: dict, *, require_synchronized: bool | None = True,
) -> dict[str, object]:
    value = status.get("clock")
    if not isinstance(value, dict) or set(value) != {
        "synchronized", "absolute_offset_millis", "uncertainty_millis",
    }:
        raise GateError("authenticated clock status is absent or malformed")
    synchronized = value["synchronized"]
    if type(synchronized) is not bool:
        raise GateError("authenticated clock synchronization state is invalid")
    absolute_offset = _counter(value, "absolute_offset_millis")
    uncertainty = _counter(value, "uncertainty_millis")
    if require_synchronized is not None and synchronized is not require_synchronized:
        state = "synchronized" if require_synchronized else "unsynchronized"
        raise GateError(f"authenticated clock is not {state}")
    if synchronized:
        if absolute_offset > 1000 or uncertainty > 1000 - absolute_offset:
            raise GateError("authenticated clock bound exceeds one second")
    elif absolute_offset != 0 or uncertainty != 0:
        raise GateError("unsynchronized clock exposed a stale bound")
    return {
        "synchronized": synchronized,
        "absolute_offset_millis": absolute_offset,
        "uncertainty_millis": uncertainty,
    }


def _relay_telemetry(status: dict) -> dict[str, object]:
    telemetry = status.get("relay_telemetry")
    if not isinstance(telemetry, dict) or set(telemetry) != {
        "control_session", "sequence", "forwarded_packets", "forwarded_bytes",
        "dropped_packets", "dropped_bytes",
    }:
        raise GateError("authenticated relay telemetry is absent or malformed")
    control_session = _counter(telemetry, "control_session")
    sequence = _counter(telemetry, "sequence")
    if control_session == 0:
        raise GateError("authenticated relay telemetry control session is invalid")
    if sequence == 0:
        raise GateError("authenticated relay telemetry sequence is invalid")
    result: dict[str, object] = {
        "control_session": control_session,
        "sequence": sequence,
        "dropped_packets": _counter(telemetry, "dropped_packets"),
        "dropped_bytes": _counter(telemetry, "dropped_bytes"),
    }
    for name in ("forwarded_packets", "forwarded_bytes"):
        forwarded = telemetry[name]
        if not isinstance(forwarded, dict) or set(forwarded) != {"site-a", "site-b"}:
            raise GateError(f"authenticated relay {name} counters are invalid")
        result[name] = {
            site: _counter(forwarded, site) for site in ("site-a", "site-b")
        }
    return result


def _edge_status(status: dict, expected_site: str) -> dict:
    if expected_site not in {"site-a", "site-b"} or status.get("site") != expected_site:
        raise GateError(f"status site does not match expected {expected_site}")
    _require_fresh_status(status)
    path_status = status.get("path")
    if not isinstance(path_status, dict):
        raise GateError("edge path status is absent")
    selected = path_status.get("selected")
    direct_required = path_status.get("direct_required")
    direct_healthy = path_status.get("direct_healthy")
    if (
        selected not in {"none", "relay", "direct"}
        or direct_required is not True
        or type(direct_healthy) is not bool
    ):
        raise GateError("edge path state is invalid")
    direct_epoch = _counter(path_status, "direct_epoch")
    direct_instance = _counter(path_status, "direct_instance")
    if selected == "direct" and (direct_epoch == 0 or direct_instance == 0):
        raise GateError("selected direct path has an invalid epoch or instance")
    if selected != "direct" and direct_instance != 0:
        raise GateError("non-direct path retained a direct instance")
    telemetry = _relay_telemetry(status)
    control_identity = _identity_plane(status, "control_identity")
    data_identity = _data_identity(status, selected, direct_epoch)
    clock = _clock_status(status)
    status_generation = _counter(status, "status_generation")
    selected_path_transitions = _counter(status, "selected_path_transitions")
    identity_transitions = _counter(status, "identity_transitions")
    if status_generation == 0 or status_generation == MAX_COUNTER:
        raise GateError("edge status publication generation is invalid")
    if selected_path_transitions == MAX_COUNTER or identity_transitions == MAX_COUNTER:
        raise GateError("edge sticky transition counter is exhausted")
    for plane_name, plane in (
        ("control_identity", control_identity), ("data_identity", data_identity),
    ):
        for endpoint in ("local", "peer"):
            if plane[endpoint]["pin_slot"] != "current":
                raise GateError(f"{plane_name} {endpoint} is not in the current slot")
    return {
        "status_generation": status_generation,
        "selected_path_transitions": selected_path_transitions,
        "identity_transitions": identity_transitions,
        "selected": selected,
        "direct_required": direct_required,
        "direct_healthy": direct_healthy,
        "direct_epoch": direct_epoch,
        "direct_instance": direct_instance,
        "relay_sent": _counter(path_status, "relay_sent_packets"),
        "relay_received": _counter(path_status, "relay_received_packets"),
        "queue_drops": _counter(path_status, "queue_drops"),
        "invalid_packets": _counter(path_status, "invalid_packets"),
        "duplicate_packets": _counter(path_status, "duplicate_packets"),
        "dropped": _counter(status, "dropped_packets"),
        "direct_sent": _counter(path_status, "direct_sent_packets"),
        "direct_received": _counter(path_status, "direct_received_packets"),
        "direct_progress": _counter(path_status, "direct_progress_acknowledgements"),
        "watchdog_failures": _counter(path_status, "direct_watchdog_failures"),
        "fallbacks": _counter(path_status, "fallbacks"),
        "control_session": telemetry["control_session"],
        "telemetry_sequence": telemetry["sequence"],
        "relay_forwarded": telemetry["forwarded_packets"],
        "relay_forwarded_bytes": telemetry["forwarded_bytes"],
        "relay_dropped": telemetry["dropped_packets"],
        "relay_dropped_bytes": telemetry["dropped_bytes"],
        "control_identity": control_identity,
        "data_identity": data_identity,
        "clock": clock,
    }


def _edge(path: Path, expected_site: str) -> dict:
    status, _ = _read_site_status(path, expected_site)
    return _edge_status(status, expected_site)


def _read_site_status(path: Path, expected_site: str) -> tuple[dict, tuple[int, int]]:
    return _read_json_source(path, _site_identity(expected_site), 0o640)


def _edge_pair(edge_a: Path, edge_b: Path) -> dict[str, dict]:
    status_a, source_a = _read_site_status(edge_a, "site-a")
    status_b, source_b = _read_site_status(edge_b, "site-b")
    if source_a == source_b:
        raise GateError("edge status inputs use the same opened file")
    pair = {
        "edge_a": _edge_status(status_a, "site-a"),
        "edge_b": _edge_status(status_b, "site-b"),
    }
    if (
        pair["edge_a"]["selected"] == "direct"
        and pair["edge_b"]["selected"] == "direct"
        and pair["edge_a"]["direct_epoch"] != pair["edge_b"]["direct_epoch"]
    ):
        raise GateError("healthy direct edges report different path epochs")
    return pair


def capture(edge_a: Path, edge_b: Path) -> dict:
    edges = _edge_pair(edge_a, edge_b)
    return {
        "format": SNAPSHOT_FORMAT,
        "boot_id_sha256": _boot_id_sha256(),
        "monotonic_ns": time.monotonic_ns(),
        **edges,
    }


def capture_after_publications(
    edge_a: Path,
    edge_b: Path,
    previous: dict,
    timeout_seconds: float,
) -> dict:
    """Wait for one new publication from each edge and capture them together."""
    _validate_snapshot(previous)
    if (
        type(timeout_seconds) not in {int, float}
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > MAX_SOAK_PUBLICATION_WAIT_SECONDS
    ):
        raise GateError("invalid status publication wait timeout")
    deadline = time.monotonic() + timeout_seconds
    while True:
        current = capture(edge_a, edge_b)
        if current["boot_id_sha256"] != previous["boot_id_sha256"]:
            raise GateError("status publications belong to different boots")
        advanced = True
        for label in ("edge_a", "edge_b"):
            prior_generation = previous[label]["status_generation"]
            generation = current[label]["status_generation"]
            if generation < prior_generation:
                raise GateError(f"{label} status publication generation regressed")
            if generation == prior_generation:
                advanced = False
        if advanced:
            return current
        if time.monotonic() >= deadline:
            raise GateError("both edge status publication generations did not advance")
        time.sleep(0.1)


def write_snapshot(path: Path, snapshot: dict) -> None:
    _validate_snapshot(snapshot)
    encoded = (json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as target:
            target.write(encoded)
            target.flush()
            os.fsync(target.fileno())
    finally:
        os.close(descriptor)


def _boot_id_sha256() -> str:
    info = BOOT_ID_PATH.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise GateError("boot ID is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(BOOT_ID_PATH, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise GateError("boot ID is not a regular file")
        if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
            raise GateError("boot ID changed while it was opened")
        data = os.read(descriptor, 129)
    finally:
        os.close(descriptor)
    if len(data) == 0 or len(data) > 128:
        raise GateError("boot ID size is outside bounds")
    try:
        value = data.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise GateError("boot ID encoding is invalid") from error
    if not BOOT_ID_PATTERN.fullmatch(value):
        raise GateError("boot ID format is invalid")
    return hashlib.sha256(data).hexdigest()


def _validate_snapshot(value: dict) -> None:
    if set(value) != {"format", "boot_id_sha256", "monotonic_ns", "edge_a", "edge_b"}:
        raise GateError("snapshot root schema is invalid")
    if type(value["format"]) is not int or value["format"] != SNAPSHOT_FORMAT:
        raise GateError("invalid snapshot format")
    boot_id = value["boot_id_sha256"]
    if type(boot_id) is not str or not re.fullmatch(r"[a-f0-9]{64}", boot_id):
        raise GateError("invalid snapshot boot ID")
    monotonic_ns = value["monotonic_ns"]
    if type(monotonic_ns) is not int or monotonic_ns <= 0 or monotonic_ns > MAX_COUNTER:
        raise GateError("invalid snapshot monotonic timestamp")
    for label in ("edge_a", "edge_b"):
        edge = value[label]
        if not isinstance(edge, dict) or set(edge) != EDGE_SNAPSHOT_KEYS:
            raise GateError(f"invalid {label} snapshot schema")
        if (
            edge["selected"] not in {"none", "relay", "direct"}
            or edge["direct_required"] is not True
            or type(edge["direct_healthy"]) is not bool
        ):
            raise GateError(f"invalid {label} snapshot path state")
        for name in {
            "status_generation", "selected_path_transitions", "identity_transitions",
            "direct_epoch", "direct_instance", "relay_sent", "relay_received", "direct_sent",
            "direct_received", "direct_progress",
            "watchdog_failures", "fallbacks", "queue_drops", "dropped",
            "invalid_packets", "duplicate_packets",
            "control_session", "telemetry_sequence",
            "relay_dropped", "relay_dropped_bytes",
        }:
            _counter(edge, name)
        if edge["status_generation"] in {0, MAX_COUNTER}:
            raise GateError(f"invalid {label} status publication generation")
        if any(
            edge[name] == MAX_COUNTER
            for name in ("selected_path_transitions", "identity_transitions")
        ):
            raise GateError(f"exhausted {label} sticky transition counter")
        if edge["control_session"] == 0:
            raise GateError(f"invalid {label} control session")
        if edge["telemetry_sequence"] == 0:
            raise GateError(f"invalid {label} telemetry sequence")
        if edge["selected"] == "direct" and (
            edge["direct_epoch"] == 0 or edge["direct_instance"] == 0
        ):
            raise GateError(f"invalid {label} selected direct epoch or instance")
        if edge["selected"] != "direct" and edge["direct_instance"] != 0:
            raise GateError(f"invalid {label} retained direct instance")
        for name in ("relay_forwarded", "relay_forwarded_bytes"):
            forwarded = edge[name]
            if not isinstance(forwarded, dict) or set(forwarded) != {"site-a", "site-b"}:
                raise GateError(f"invalid {label} {name} schema")
            for site in ("site-a", "site-b"):
                _counter(forwarded, site)
        _clock_status({"clock": edge["clock"]})
        control_identity = edge["control_identity"]
        if not isinstance(control_identity, dict) or set(control_identity) != {"local", "peer"}:
            raise GateError(f"invalid {label} control_identity schema")
        for endpoint in ("local", "peer"):
            certificate = _certificate_status(
                control_identity[endpoint], f"{label} control_identity {endpoint}"
            )
            if certificate["pin_slot"] != "current":
                raise GateError(f"invalid {label} control_identity non-current slot")
        data_identity = edge["data_identity"]
        if not isinstance(data_identity, dict) or set(data_identity) != {
            "local", "peer", "path", "direct_epoch",
        }:
            raise GateError(f"invalid {label} data_identity schema")
        for endpoint in ("local", "peer"):
            certificate = _certificate_status(
                data_identity[endpoint], f"{label} data_identity {endpoint}"
            )
            if certificate["pin_slot"] != "current":
                raise GateError(f"invalid {label} data_identity non-current slot")
        if data_identity["path"] != edge["selected"]:
            raise GateError(f"invalid {label} data_identity path binding")
        binding_epoch = _counter(data_identity, "direct_epoch")
        if data_identity["path"] == "direct":
            if binding_epoch == 0 or binding_epoch != edge["direct_epoch"]:
                raise GateError(f"invalid {label} data_identity direct epoch")
        elif data_identity["path"] != "relay" or binding_epoch != 0:
            raise GateError(f"invalid {label} relay data_identity epoch")
    edge_a, edge_b = value["edge_a"], value["edge_b"]
    if (
        edge_a["selected"] == "direct"
        and edge_b["selected"] == "direct"
        and edge_a["direct_epoch"] != edge_b["direct_epoch"]
    ):
        raise GateError("healthy direct edges report different path epochs")
    if edge_a["control_identity"]["peer"] != edge_b["control_identity"]["peer"]:
        raise GateError("control identity peer binding differs between edges")
    if (
        edge_a["data_identity"]["local"] != edge_b["data_identity"]["peer"]
        or edge_b["data_identity"]["local"] != edge_a["data_identity"]["peer"]
    ):
        raise GateError("data identity peer/local binding differs between edges")


def read_snapshot(path: Path) -> dict:
    value = _read_json(path)
    _validate_snapshot(value)
    if value["boot_id_sha256"] != _boot_id_sha256():
        raise GateError("snapshot belongs to a different boot")
    return value


def _raw_relay_limits(duration_ms: int, raw_relay_rate: float) -> tuple[int, int]:
    scaled_packets = (duration_ms * raw_relay_rate) / 1000
    if not math.isfinite(scaled_packets) or scaled_packets > MAX_COUNTER - 32:
        raise GateError("raw relay allowance exceeds counter bounds")
    packet_limit = 32 + math.ceil(scaled_packets)
    scaled_bytes = (duration_ms * RAW_RELAY_BYTES_PER_SECOND) / 1000
    if (
        not math.isfinite(scaled_bytes)
        or scaled_bytes > MAX_COUNTER - RAW_RELAY_BYTE_BASE_PER_SITE
    ):
        raise GateError("raw relay byte allowance exceeds counter bounds")
    byte_limit = RAW_RELAY_BYTE_BASE_PER_SITE + math.ceil(scaled_bytes)
    return packet_limit, byte_limit


def verify(
    before: dict,
    after: dict,
    minimum_direct_packets: int,
    raw_relay_rate: float,
    *,
    now_monotonic_ns: int | None = None,
    max_evidence_interval_seconds: int = MAX_EVIDENCE_INTERVAL_SECONDS,
    allow_zero_direct_packets: bool = False,
    require_telemetry_advance: bool = True,
) -> dict[str, int]:
    _validate_snapshot(before)
    _validate_snapshot(after)
    if before["boot_id_sha256"] != after["boot_id_sha256"]:
        raise GateError("snapshots belong to different boots")
    if (
        type(minimum_direct_packets) is not int
        or minimum_direct_packets < 0
        or (minimum_direct_packets == 0 and not allow_zero_direct_packets)
        or type(raw_relay_rate) not in {int, float}
        or not math.isfinite(raw_relay_rate)
        or raw_relay_rate < 0
        or type(max_evidence_interval_seconds) is not int
        or max_evidence_interval_seconds <= 0
        or type(allow_zero_direct_packets) is not bool
        or type(require_telemetry_advance) is not bool
    ):
        raise GateError("invalid verification bound")
    elapsed_ns = after["monotonic_ns"] - before["monotonic_ns"]
    if elapsed_ns <= 0:
        raise GateError("non-monotonic evidence interval")
    if elapsed_ns > max_evidence_interval_seconds * 1_000_000_000:
        raise GateError("evidence interval exceeds qualification bound")
    if now_monotonic_ns is not None:
        if type(now_monotonic_ns) is not int or now_monotonic_ns <= 0:
            raise GateError("invalid verification timestamp")
        final_age_ns = now_monotonic_ns - after["monotonic_ns"]
        if final_age_ns < -int(FUTURE_CLOCK_TOLERANCE_SECONDS * 1_000_000_000):
            raise GateError("snapshot timestamp is in the future")
        if final_age_ns > int(MAX_FINAL_SNAPSHOT_AGE_SECONDS * 1_000_000_000):
            raise GateError("final snapshot is stale")
    duration_ms = elapsed_ns // 1_000_000
    if duration_ms <= 0:
        raise GateError("evidence interval is too short")
    evidence: dict[str, int] = {"DIRECT_EVIDENCE_DURATION_MS": duration_ms}
    for label in ("edge_a", "edge_b"):
        prior, current = before[label], after[label]
        if current["status_generation"] <= prior["status_generation"]:
            raise GateError(f"{label} status publication generation did not advance")
        for name in ("selected_path_transitions", "identity_transitions"):
            if current[name] != prior[name]:
                raise GateError(f"{label} sticky {name} changed during direct transfer")
        if any(item["selected"] != "direct" or not item["direct_healthy"] for item in (prior, current)):
            raise GateError(f"{label} direct path is not healthy")
        if current["direct_instance"] != prior["direct_instance"]:
            raise GateError(f"{label} direct instance changed during direct transfer")
        prefix = label.upper()
        for key in ("direct_sent", "direct_received", "direct_progress"):
            delta = current[key] - prior[key]
            required = (
                minimum_direct_packets
                if key != "direct_progress"
                else (0 if allow_zero_direct_packets else 1)
            )
            if delta < required:
                raise GateError(f"{label} {key} did not advance")
            evidence[f"{prefix}_{key.upper()}_DELTA"] = delta
        for key in (
            "relay_sent", "relay_received", "queue_drops", "invalid_packets",
            "duplicate_packets", "dropped",
            "watchdog_failures", "fallbacks",
        ):
            delta = current[key] - prior[key]
            if delta != 0:
                raise GateError(f"{label} {key} changed during direct transfer")
            evidence[f"{prefix}_{key.upper()}_DELTA"] = delta
        if current["control_session"] != prior["control_session"]:
            raise GateError(f"{label} authenticated relay telemetry session changed")
        for plane in ("control_identity", "data_identity"):
            if current[plane] != prior[plane]:
                raise GateError(f"{label} {plane} changed during direct transfer")
        if (
            current["telemetry_sequence"] < prior["telemetry_sequence"]
            or (
                require_telemetry_advance
                and current["telemetry_sequence"] == prior["telemetry_sequence"]
            )
        ):
            reason = (
                "regressed"
                if current["telemetry_sequence"] < prior["telemetry_sequence"]
                else "did not advance"
            )
            raise GateError(f"{label} authenticated relay telemetry {reason}")
        for name in ("relay_dropped", "relay_dropped_bytes"):
            if current[name] < prior[name]:
                raise GateError(f"{label} authenticated relay {name} counter regressed")
        for name in ("relay_forwarded", "relay_forwarded_bytes"):
            for site in ("site-a", "site-b"):
                if current[name][site] < prior[name][site]:
                    raise GateError(f"{label} authenticated relay {name} counter regressed")
    # Bind the limit to the exact integer duration emitted in evidence so the
    # shell chain can recompute it independently without float ambiguity.
    raw_limit, byte_limit = _raw_relay_limits(duration_ms, raw_relay_rate)
    evidence["RAW_RELAY_PACKET_LIMIT_PER_SITE"] = raw_limit
    evidence["RAW_RELAY_BYTE_LIMIT_PER_SITE"] = byte_limit
    for counter, limit, suffix in (
        ("relay_forwarded", raw_limit, "DELTA"),
        ("relay_forwarded_bytes", byte_limit, "BYTES_DELTA"),
    ):
        for site in ("site-a", "site-b"):
            prior = min(before[label][counter][site] for label in ("edge_a", "edge_b"))
            current = max(after[label][counter][site] for label in ("edge_a", "edge_b"))
            delta = current - prior
            if delta < 0 or delta > limit:
                raise GateError("raw relay forwarding exceeded keepalive bound")
            key = f"RAW_RELAY_{site.upper().replace('-', '_')}_{suffix}"
            evidence[key] = delta
    if tuple(sorted(evidence)) != EVIDENCE_KEYS:
        raise GateError("internal evidence schema mismatch")
    return evidence


def verify_soak(
    before: dict,
    previous: dict,
    after: dict,
    minimum_direct_packets: int,
    raw_relay_rate: float,
    *,
    final: bool,
    now_monotonic_ns: int | None = None,
) -> dict[str, int]:
    """Verify one cumulative and one adjacent continuous-soak interval."""
    for snapshot in (before, previous, after):
        _validate_snapshot(snapshot)
    if len({snapshot["boot_id_sha256"] for snapshot in (before, previous, after)}) != 1:
        raise GateError("soak snapshots belong to different boots")
    if type(final) is not bool:
        raise GateError("invalid soak final flag")
    if previous["monotonic_ns"] < before["monotonic_ns"]:
        raise GateError("soak previous snapshot predates the baseline")
    step_ns = after["monotonic_ns"] - previous["monotonic_ns"]
    if step_ns <= 0:
        raise GateError("non-monotonic soak observation")
    if step_ns > int(MAX_SOAK_SAMPLE_INTERVAL_SECONDS * 1_000_000_000):
        raise GateError("soak observation interval exceeds its bound")

    # Revalidate the immediately preceding observation against the one fixed
    # baseline. This prevents a caller from presenting a valid-looking but
    # previously unverified intermediate snapshot.
    if previous["monotonic_ns"] != before["monotonic_ns"]:
        verify(
            before,
            previous,
            0,
            raw_relay_rate,
            now_monotonic_ns=now_monotonic_ns,
            max_evidence_interval_seconds=MAX_SOAK_EVIDENCE_INTERVAL_SECONDS,
            allow_zero_direct_packets=True,
            require_telemetry_advance=False,
        )
    elif previous != before:
        raise GateError("soak baseline timestamp was reused with different evidence")

    monotonic_counters = (
        "direct_sent", "direct_received", "direct_progress",
        "telemetry_sequence", "relay_dropped", "relay_dropped_bytes",
    )
    for label in ("edge_a", "edge_b"):
        prior, current = previous[label], after[label]
        if current["status_generation"] <= prior["status_generation"]:
            raise GateError(f"{label} status publication generation did not advance")
        for key in ("selected_path_transitions", "identity_transitions"):
            if prior[key] != before[label][key] or current[key] != before[label][key]:
                raise GateError(f"{label} sticky {key} changed during soak")
        for key in monotonic_counters:
            if current[key] < prior[key]:
                raise GateError(f"{label} {key} regressed between soak observations")
        for key in ("relay_forwarded", "relay_forwarded_bytes"):
            for site in ("site-a", "site-b"):
                if current[key][site] < prior[key][site]:
                    raise GateError(
                        f"{label} authenticated relay {key} regressed between soak observations"
                    )

    return verify(
        before,
        after,
        minimum_direct_packets if final else 0,
        raw_relay_rate,
        now_monotonic_ns=now_monotonic_ns,
        max_evidence_interval_seconds=MAX_SOAK_EVIDENCE_INTERVAL_SECONDS,
        allow_zero_direct_packets=not final,
        require_telemetry_advance=final,
    )


def _fault_path(status: dict, label: str) -> dict[str, object]:
    path = status.get("path")
    if not isinstance(path, dict):
        raise GateError(f"{label} path status is absent")
    selected = path.get("selected")
    healthy = path.get("direct_healthy")
    if (
        selected not in {"none", "relay", "direct"}
        or type(healthy) is not bool
        or path.get("direct_required") is not True
    ):
        raise GateError(f"{label} path state is invalid")
    return {
        "selected": selected,
        "direct_healthy": healthy,
        "direct_epoch": _counter(path, "direct_epoch"),
        "direct_instance": _counter(path, "direct_instance"),
        "relay_sent": _counter(path, "relay_sent_packets"),
        "relay_received": _counter(path, "relay_received_packets"),
        "queue_drops": _counter(path, "queue_drops"),
        "invalid_packets": _counter(path, "invalid_packets"),
        "duplicate_packets": _counter(path, "duplicate_packets"),
        "fallbacks": _counter(path, "fallbacks"),
    }


def _local_only_identity(status: dict, name: str, label: str) -> dict[str, str]:
    value = status.get(name)
    if not isinstance(value, dict) or set(value) != {"local"}:
        raise GateError(f"{label} {name} is not local-only")
    return _certificate_status(value["local"], f"{label} {name} local")


def _wait_transition(check, timeout_seconds: float, reason: str) -> None:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise GateError("invalid transition timeout")
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while True:
        try:
            if check():
                return
        except TelemetryTransitionError:
            raise
        except (GateError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            last_error = error
        if time.monotonic() >= deadline:
            if last_error is not None:
                raise GateError(reason) from last_error
            raise GateError(reason)
        time.sleep(0.25)


def wait_control_outage(
    edge_a: Path, edge_b: Path, before: dict, timeout_seconds: float,
) -> None:
    _validate_snapshot(before)

    def observed() -> bool:
        ready = True
        for label, site, path in (
            ("edge_a", "site-a", edge_a), ("edge_b", "site-b", edge_b),
        ):
            status, _ = _read_site_status(path, site)
            if status.get("site") != site:
                raise TelemetryTransitionError(f"{label} site changed")
            _require_fresh_status(status)
            current_path = _fault_path(status, label)
            prior = before[label]
            if current_path["selected"] == "relay":
                raise TelemetryTransitionError(f"{label} selected relay during control outage")
            if (
                current_path["selected"] != "direct"
                or not current_path["direct_healthy"]
                or current_path["direct_epoch"] != prior["direct_epoch"]
                or current_path["direct_instance"] != prior["direct_instance"]
            ):
                raise TelemetryTransitionError(f"{label} direct path changed during control outage")
            if _counter(status, "dropped_packets") != prior["dropped"]:
                raise TelemetryTransitionError(f"{label} dropped changed during control outage")
            for counter in (
                "relay_sent", "relay_received", "queue_drops", "invalid_packets",
                "duplicate_packets", "fallbacks",
            ):
                if current_path[counter] != prior[counter]:
                    raise TelemetryTransitionError(f"{label} {counter} changed during control outage")
            data_identity = _data_identity(
                status, "direct", int(current_path["direct_epoch"]),
            )
            if data_identity != prior["data_identity"]:
                raise TelemetryTransitionError(f"{label} data identity changed during control outage")
            reconnecting = status.get("control") == "reconnecting"
            telemetry_absent = status.get("relay_telemetry") is None
            if not reconnecting or not telemetry_absent:
                ready = False
                continue
            _clock_status(status, require_synchronized=False)
            local = _local_only_identity(status, "control_identity", label)
            if local != prior["control_identity"]["local"]:
                raise TelemetryTransitionError(f"{label} local control identity changed")
        return ready

    _wait_transition(observed, timeout_seconds, "control outage was not observed")


def wait_control_reconnected(
    edge_a: Path, edge_b: Path, before: dict, timeout_seconds: float,
) -> None:
    _validate_snapshot(before)

    def observed() -> bool:
        current = _edge_pair(edge_a, edge_b)
        ready = True
        for label in ("edge_a", "edge_b"):
            prior, item = before[label], current[label]
            if item["selected"] != "direct" or not item["direct_healthy"]:
                raise TelemetryTransitionError(f"{label} direct path changed during control recovery")
            if item["direct_epoch"] != prior["direct_epoch"]:
                raise TelemetryTransitionError(f"{label} direct epoch changed during control recovery")
            if item["direct_instance"] != prior["direct_instance"]:
                raise TelemetryTransitionError(f"{label} direct instance changed during control recovery")
            if item["control_identity"] != prior["control_identity"]:
                raise TelemetryTransitionError(f"{label} control identity changed during reconnect")
            if item["data_identity"] != prior["data_identity"]:
                raise TelemetryTransitionError(f"{label} data identity changed during reconnect")
            for counter in (
                "relay_sent", "relay_received", "queue_drops", "invalid_packets",
                "duplicate_packets", "dropped", "fallbacks",
            ):
                if item[counter] != prior[counter]:
                    raise TelemetryTransitionError(f"{label} {counter} changed during reconnect")
            if item["control_session"] == prior["control_session"]:
                ready = False
            for name in ("relay_dropped", "relay_dropped_bytes"):
                if item[name] < prior[name]:
                    raise TelemetryTransitionError(
                        f"{label} authenticated relay {name} counter regressed"
                    )
            for name in ("relay_forwarded", "relay_forwarded_bytes"):
                for site in ("site-a", "site-b"):
                    if item[name][site] < prior[name][site]:
                        raise TelemetryTransitionError(
                            f"{label} authenticated relay {name} counter regressed"
                        )
        return ready

    _wait_transition(observed, timeout_seconds, "fresh control sessions were not observed")


def wait_direct_outage(
    edge_a: Path, edge_b: Path, before: dict, timeout_seconds: float,
) -> None:
    _validate_snapshot(before)

    def observed() -> bool:
        ready = True
        for label, site, path in (
            ("edge_a", "site-a", edge_a), ("edge_b", "site-b", edge_b),
        ):
            status, _ = _read_site_status(path, site)
            if status.get("site") != site:
                raise TelemetryTransitionError(f"{label} site changed")
            _require_fresh_status(status)
            _clock_status(status)
            current_path = _fault_path(status, label)
            prior = before[label]
            if current_path["selected"] == "relay":
                raise TelemetryTransitionError(f"{label} selected relay during direct outage")
            if _counter(status, "dropped_packets") != prior["dropped"]:
                raise TelemetryTransitionError(f"{label} dropped changed during direct outage")
            for counter in (
                "relay_sent", "relay_received", "queue_drops", "invalid_packets",
                "duplicate_packets", "fallbacks",
            ):
                if current_path[counter] != prior[counter]:
                    raise TelemetryTransitionError(f"{label} {counter} changed during direct outage")
            control_identity = _identity_plane(status, "control_identity")
            if control_identity != prior["control_identity"]:
                raise TelemetryTransitionError(f"{label} control identity changed during direct outage")
            try:
                telemetry = _relay_telemetry(status)
            except GateError as error:
                raise TelemetryTransitionError(
                    f"{label} control telemetry disappeared or became malformed"
                ) from error
            if telemetry["control_session"] != prior["control_session"]:
                raise TelemetryTransitionError(f"{label} control session changed during direct outage")
            if telemetry["sequence"] < prior["telemetry_sequence"]:
                raise TelemetryTransitionError(f"{label} relay telemetry sequence regressed")
            for current_name, prior_name in (
                ("dropped_packets", "relay_dropped"),
                ("dropped_bytes", "relay_dropped_bytes"),
            ):
                if telemetry[current_name] < prior[prior_name]:
                    raise TelemetryTransitionError(
                        f"{label} authenticated relay {current_name} counter regressed"
                    )
            for current_name, prior_name in (
                ("forwarded_packets", "relay_forwarded"),
                ("forwarded_bytes", "relay_forwarded_bytes"),
            ):
                for site_name in ("site-a", "site-b"):
                    if telemetry[current_name][site_name] < prior[prior_name][site_name]:
                        raise TelemetryTransitionError(
                            f"{label} authenticated relay {current_name} counter regressed"
                        )
            if current_path["selected"] == "direct" and current_path["direct_healthy"]:
                ready = False
                continue
            if current_path["selected"] != "none" or current_path["direct_healthy"]:
                raise TelemetryTransitionError(f"{label} direct withdrawal state is invalid")
            if current_path["direct_instance"] != 0:
                raise TelemetryTransitionError(f"{label} retained a direct instance after withdrawal")
            identity_value = status.get("data_identity")
            if not isinstance(identity_value, dict) or set(identity_value) != {
                "local", "path", "direct_epoch",
            }:
                raise TelemetryTransitionError(f"{label} retained a peer binding after withdrawal")
            local = _certificate_status(identity_value["local"], f"{label} data local")
            if (
                local != prior["data_identity"]["local"]
                or identity_value["path"] != "none"
                or _counter(identity_value, "direct_epoch") != 0
            ):
                raise TelemetryTransitionError(f"{label} withdrawn data identity is invalid")
        return ready

    _wait_transition(observed, timeout_seconds, "direct withdrawal was not observed")


def verify_fault_stream(
    before: dict,
    relay_recovered: dict,
    direct_recovered: dict,
    minimum_direct_packets: int,
    raw_relay_rate: float,
    *,
    now_monotonic_ns: int | None = None,
) -> dict[str, int]:
    for snapshot in (before, relay_recovered, direct_recovered):
        _validate_snapshot(snapshot)
    if len({item["boot_id_sha256"] for item in (before, relay_recovered, direct_recovered)}) != 1:
        raise GateError("fault snapshots belong to different boots")
    if type(minimum_direct_packets) is not int or minimum_direct_packets <= 0:
        raise GateError("invalid fault packet bound")
    if type(raw_relay_rate) not in {int, float} or not math.isfinite(raw_relay_rate) or raw_relay_rate < 0:
        raise GateError("invalid fault raw-relay bound")
    timestamps = [item["monotonic_ns"] for item in (before, relay_recovered, direct_recovered)]
    if not timestamps[0] < timestamps[1] < timestamps[2]:
        raise GateError("fault snapshot order is not monotonic")
    elapsed_ns = timestamps[2] - timestamps[0]
    if elapsed_ns > MAX_EVIDENCE_INTERVAL_SECONDS * 1_000_000_000:
        raise GateError("fault evidence interval exceeds qualification bound")
    if now_monotonic_ns is not None:
        final_age = now_monotonic_ns - timestamps[2]
        if final_age < -int(FUTURE_CLOCK_TOLERANCE_SECONDS * 1_000_000_000):
            raise GateError("fault snapshot timestamp is in the future")
        if final_age > int(MAX_FINAL_SNAPSHOT_AGE_SECONDS * 1_000_000_000):
            raise GateError("fault final snapshot is stale")
    duration_ms = elapsed_ns // 1_000_000
    if duration_ms <= 0:
        raise GateError("fault evidence interval is too short")
    evidence: dict[str, int] = {
        "FAULT_DIRECT_EVIDENCE_DURATION_MS": duration_ms,
        "FAULT_EXACT_PATH_IDENTITY_CHECKS": 6,
        "FAULT_REESTABLISHED_DIRECT_PATHS": 0,
        "FAULT_RELAY_CONTROL_SESSION_TRANSITIONS": 2,
    }
    for label in ("edge_a", "edge_b"):
        prior, control, current = before[label], relay_recovered[label], direct_recovered[label]
        for item in (prior, control, current):
            if item["selected"] != "direct" or not item["direct_healthy"] or item["direct_required"] is not True:
                raise GateError(f"{label} was not direct-only at an evidence boundary")
        if control["direct_epoch"] != prior["direct_epoch"]:
            raise GateError(f"{label} direct epoch changed during broker outage")
        if control["direct_instance"] != prior["direct_instance"]:
            raise GateError(f"{label} direct instance changed during broker outage")
        if current["direct_epoch"] < control["direct_epoch"]:
            raise GateError(f"{label} direct epoch regressed after recovery")
        if current["direct_instance"] <= control["direct_instance"]:
            raise GateError(f"{label} direct instance did not advance after withdrawal")
        evidence["FAULT_REESTABLISHED_DIRECT_PATHS"] += 1
        if not (
            prior["control_identity"] == control["control_identity"] == current["control_identity"]
        ):
            raise GateError(f"{label} control identity changed during fault stream")
        for endpoint in ("local", "peer"):
            if not (
                prior["data_identity"][endpoint]
                == control["data_identity"][endpoint]
                == current["data_identity"][endpoint]
            ):
                raise GateError(f"{label} data identity changed during fault stream")
        if control["data_identity"] != prior["data_identity"]:
            raise GateError(f"{label} selected-path binding changed during broker outage")
        if (
            current["data_identity"]["path"] != "direct"
            or current["data_identity"]["direct_epoch"] != current["direct_epoch"]
        ):
            raise GateError(f"{label} recovered selected-path binding is invalid")
        if control["control_session"] == prior["control_session"]:
            raise GateError(f"{label} broker control session was not replaced")
        if current["control_session"] != control["control_session"]:
            raise GateError(f"{label} broker control session changed during direct recovery")
        if current["telemetry_sequence"] <= control["telemetry_sequence"]:
            raise GateError(f"{label} authenticated relay telemetry did not resume")
        for older, newer in ((prior, control), (control, current)):
            for name in ("relay_dropped", "relay_dropped_bytes"):
                if newer[name] < older[name]:
                    raise GateError(f"{label} authenticated relay {name} counter regressed")
            for name in ("relay_forwarded", "relay_forwarded_bytes"):
                for site in ("site-a", "site-b"):
                    if newer[name][site] < older[name][site]:
                        raise GateError(f"{label} authenticated relay {name} counter regressed")
        prefix = f"FAULT_{label.upper()}"
        for key in ("direct_sent", "direct_received", "direct_progress"):
            if control[key] <= prior[key]:
                raise GateError(f"{label} direct stream did not advance through broker outage")
            delta = current[key] - prior[key]
            required = minimum_direct_packets if key != "direct_progress" else 1
            if delta < required:
                raise GateError(f"{label} {key} did not advance across fault stream")
            evidence[f"{prefix}_{key.upper()}_DELTA"] = delta
        for key in (
            "relay_sent", "relay_received", "queue_drops", "invalid_packets",
            "duplicate_packets", "dropped", "fallbacks",
        ):
            delta = current[key] - prior[key]
            if delta != 0:
                raise GateError(f"{label} {key} changed across direct-only fault stream")
            evidence[f"{prefix}_{key.upper()}_DELTA"] = delta
        watchdog_delta = current["watchdog_failures"] - prior["watchdog_failures"]
        if watchdog_delta <= 0:
            raise GateError(f"{label} direct withdrawal lacked a watchdog failure")
        evidence[f"{prefix}_WATCHDOG_FAILURES_DELTA"] = watchdog_delta
    raw_limit, byte_limit = _raw_relay_limits(duration_ms, raw_relay_rate)
    evidence["FAULT_RAW_RELAY_PACKET_LIMIT_PER_SITE"] = raw_limit
    evidence["FAULT_RAW_RELAY_BYTE_LIMIT_PER_SITE"] = byte_limit
    for counter, limit, suffix in (
        ("relay_forwarded", raw_limit, "DELTA"),
        ("relay_forwarded_bytes", byte_limit, "BYTES_DELTA"),
    ):
        for site in ("site-a", "site-b"):
            prior_raw = min(before[label][counter][site] for label in ("edge_a", "edge_b"))
            current_raw = max(
                direct_recovered[label][counter][site] for label in ("edge_a", "edge_b")
            )
            delta = current_raw - prior_raw
            if delta < 0 or delta > limit:
                raise GateError("fault raw relay forwarding exceeded keepalive bound")
            key = f"FAULT_RAW_RELAY_{site.upper().replace('-', '_')}_{suffix}"
            evidence[key] = delta
    if tuple(sorted(evidence)) != FAULT_EVIDENCE_KEYS:
        raise GateError("internal fault evidence schema mismatch")
    return evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--edge-a", required=True, type=Path)
    common.add_argument("--edge-b", required=True, type=Path)
    wait = commands.add_parser("wait-direct", parents=[common])
    wait.add_argument("--timeout-seconds", type=float, default=60.0)
    telemetry = commands.add_parser("wait-telemetry", parents=[common])
    telemetry.add_argument("--before", required=True, type=Path)
    telemetry.add_argument("--timeout-seconds", type=float, default=30.0)
    for name in (
        "wait-control-outage", "wait-control-reconnected", "wait-direct-outage",
    ):
        transition = commands.add_parser(name, parents=[common])
        transition.add_argument("--before", required=True, type=Path)
        transition.add_argument("--timeout-seconds", type=float, default=30.0)
    snapshot = commands.add_parser("capture", parents=[common])
    snapshot.add_argument("--output", required=True, type=Path)
    snapshot.add_argument("--after", type=Path)
    snapshot.add_argument("--timeout-seconds", type=float)
    check = commands.add_parser("verify")
    check.add_argument("--before", required=True, type=Path)
    check.add_argument("--after", required=True, type=Path)
    check.add_argument("--minimum-direct-packets", type=int, default=1)
    check.add_argument("--raw-relay-rate", type=float, default=1.0)
    soak = commands.add_parser("verify-soak")
    soak.add_argument("--before", required=True, type=Path)
    soak.add_argument("--previous", required=True, type=Path)
    soak.add_argument("--after", required=True, type=Path)
    soak.add_argument("--minimum-direct-packets", type=int, default=1000)
    soak.add_argument("--raw-relay-rate", type=float, default=1.0)
    soak.add_argument("--final", action="store_true")
    fault = commands.add_parser("verify-fault-stream")
    fault.add_argument("--before", required=True, type=Path)
    fault.add_argument("--relay-recovered", required=True, type=Path)
    fault.add_argument("--direct-recovered", required=True, type=Path)
    fault.add_argument("--minimum-direct-packets", type=int, default=1)
    fault.add_argument("--raw-relay-rate", type=float, default=1.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command in {
            "wait-control-outage", "wait-control-reconnected", "wait-direct-outage",
        }:
            before = read_snapshot(args.before)
            function = {
                "wait-control-outage": wait_control_outage,
                "wait-control-reconnected": wait_control_reconnected,
                "wait-direct-outage": wait_direct_outage,
            }[args.command]
            function(args.edge_a, args.edge_b, before, args.timeout_seconds)
            return 0
        if args.command in {"wait-direct", "wait-telemetry"}:
            if not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0:
                raise GateError("invalid wait timeout")
            before = read_snapshot(args.before) if args.command == "wait-telemetry" else None
            deadline = time.monotonic() + args.timeout_seconds
            last_error: Exception | None = None
            while True:
                try:
                    current = _edge_pair(args.edge_a, args.edge_b)
                    if args.command == "wait-direct":
                        if all(
                            item["selected"] == "direct" and item["direct_healthy"]
                            for item in current.values()
                        ):
                            return 0
                    else:
                        if before is None:
                            raise GateError("telemetry baseline is unavailable")
                        for label, item in current.items():
                            prior = before[label]
                            if item["control_session"] != prior["control_session"]:
                                raise TelemetryTransitionError(
                                    f"{label} authenticated relay telemetry session changed"
                                )
                            for name in ("relay_forwarded", "relay_forwarded_bytes"):
                                for site in ("site-a", "site-b"):
                                    if item[name][site] < prior[name][site]:
                                        raise TelemetryTransitionError(
                                            f"{label} authenticated relay {name} counter regressed"
                                        )
                            for name in ("relay_dropped", "relay_dropped_bytes"):
                                if item[name] < prior[name]:
                                    raise TelemetryTransitionError(
                                        f"{label} authenticated relay {name} counter regressed"
                                    )
                            if item["telemetry_sequence"] < prior["telemetry_sequence"]:
                                raise TelemetryTransitionError(
                                    f"{label} authenticated relay telemetry sequence regressed"
                                )
                        if all(
                            current[label]["telemetry_sequence"]
                            > before[label]["telemetry_sequence"]
                            for label in ("edge_a", "edge_b")
                        ):
                            return 0
                except TelemetryTransitionError:
                    raise
                except (GateError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                    last_error = error
                if time.monotonic() >= deadline:
                    reason = (
                        "direct path did not become healthy"
                        if args.command == "wait-direct"
                        else "authenticated relay telemetry did not advance"
                    )
                    if last_error is not None:
                        raise GateError(reason) from last_error
                    raise GateError(reason)
                time.sleep(0.25)
        if args.command == "capture":
            if args.after is None:
                if args.timeout_seconds is not None:
                    raise GateError("publication timeout requires a previous snapshot")
                captured = capture(args.edge_a, args.edge_b)
            else:
                if args.timeout_seconds is None:
                    raise GateError("publication wait timeout is required")
                captured = capture_after_publications(
                    args.edge_a,
                    args.edge_b,
                    read_snapshot(args.after),
                    args.timeout_seconds,
                )
            write_snapshot(args.output, captured)
            return 0
        if args.command == "verify-fault-stream":
            evidence = verify_fault_stream(
                read_snapshot(args.before),
                read_snapshot(args.relay_recovered),
                read_snapshot(args.direct_recovered),
                args.minimum_direct_packets,
                args.raw_relay_rate,
                now_monotonic_ns=time.monotonic_ns(),
            )
            for key in FAULT_EVIDENCE_KEYS:
                print(f"{key}={evidence[key]}")
            return 0
        if args.command == "verify-soak":
            evidence = verify_soak(
                read_snapshot(args.before),
                read_snapshot(args.previous),
                read_snapshot(args.after),
                args.minimum_direct_packets,
                args.raw_relay_rate,
                final=args.final,
                now_monotonic_ns=time.monotonic_ns(),
            )
            if args.final:
                for key in EVIDENCE_KEYS:
                    print(f"{key}={evidence[key]}")
            return 0
        evidence = verify(
            read_snapshot(args.before), read_snapshot(args.after),
            args.minimum_direct_packets, args.raw_relay_rate,
            now_monotonic_ns=time.monotonic_ns(),
        )
        for key in EVIDENCE_KEYS:
            print(f"{key}={evidence[key]}")
        return 0
    except (GateError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"status gate failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
