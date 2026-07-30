#!/usr/bin/env python3
"""Fail-closed validator for the campus-link certificate-rotation gate.

The live driver writes a bounded, sanitized transcript.  This validator checks
the complete state transition and emits the only schema that may become a pass
marker.  It deliberately never reads a certificate or private key.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


FORMAT = 1
MAX_FILE_BYTES = 65_536
MAX_COUNTER = 9_999_999_999_999_999
MAX_TRANSACTION_MS = 30 * 60 * 1000
MAX_OUTAGE_MS = 30_000
MAX_CUTOFF_OVERRUN_MS = 250
MAX_ROLLBACK_MS = 120_000
MIN_STREAM_RECORDS_EACH_DIRECTION = 1024

HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
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

ROTATION_ARTIFACTS = (
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
ROTATION_STATES = (
    "pre",
    "overlap",
    "relay-next",
    "edge-a-next",
    "edge-b-next",
    "retiring",
    "post",
)
ROTATION_CHANGE_SETS = {
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

PASS_MARKER_KEYS = (
    "FORMAT",
    "STATUS",
    "GATE",
    "MODE",
    "RUN_ID",
    "CANDIDATE_SHA256",
    "RUN_MANIFEST_SHA256",
    "PREREQUISITE_MARKER_SHA256",
    "START_MONOTONIC_MS",
    "COMPLETE_MONOTONIC_MS",
    "ROTATION_ID",
    "ROTATION_MANIFEST_SHA256",
    "TRANSACTION_MARKER_SHA256",
    "CURRENT_NEXT_OVERLAP_CHECKS",
    "NEXT_SLOT_OBSERVATIONS",
    "NEXT_OBSERVATIONS_INSIDE_TRANSACTION",
    "NEXT_OBSERVATIONS_OUTSIDE_TRANSACTION",
    "SERVICE_RELOADS",
    "CONTROL_RECONNECTS",
    "DIRECT_RECONNECTS",
    "MAX_APPLICATION_OUTAGE_MS",
    "STREAM_RECORDS_A_TO_B",
    "STREAM_RECORDS_B_TO_A",
    "STREAM_DIGEST_DIRECTIONS",
    "OLD_PIN_REJECTIONS",
    "NEXT_PIN_ACCEPTANCES",
    "EXPIRY_AUTHORITIES",
    "EXPIRY_VISIBILITY_CHECKS",
    "EXPIRED_RECONNECT_REJECTIONS",
    "INSIDE_MARGIN_REJECTIONS",
    "NEXT_RESTORATIONS",
    "MAX_CUTOFF_OVERRUN_MS",
    "ROLLBACK_SCENARIOS",
    "ROLLBACK_RESTORES",
)


class GateError(ValueError):
    """The supplied transcript cannot satisfy the rotation contract."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise GateError("duplicate JSON object key")
        value[key] = item
    return value


def _read_json(
    path: Path, *, production: bool, expected_mode: int = 0o600,
) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise GateError("transcript is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise GateError("transcript is not a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise GateError(f"evidence mode is not {expected_mode:04o}")
    if production and (metadata.st_uid != 0 or metadata.st_gid != 0):
        raise GateError("production transcript is not root-owned")
    if metadata.st_size <= 0 or metadata.st_size > MAX_FILE_BYTES:
        raise GateError("transcript size is outside bounds")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise GateError("transcript cannot be read") from error
    if b"\x00" in raw or not raw.endswith(b"\n"):
        raise GateError("transcript encoding is invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateError("transcript is not canonical JSON data") from error
    if not isinstance(value, dict):
        raise GateError("transcript root is not an object")
    return value


def _exact(value: Any, keys: tuple[str, ...] | set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise GateError(f"{label} schema is invalid")
    return value


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0) or value > MAX_COUNTER:
        raise GateError(f"{label} is not a bounded integer")
    return value


def _true(value: Any, label: str) -> None:
    if value is not True:
        raise GateError(f"{label} was not proved")


def _hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise GateError(f"{label} is invalid")
    return value


def _ordered_exact_strings(value: Any, expected: tuple[str, ...], label: str) -> None:
    if not isinstance(value, list) or value != list(expected):
        raise GateError(f"{label} is incomplete or out of order")


def validate_rotation_manifest(value: dict[str, Any]) -> dict[str, dict[str, str]]:
    manifest = _exact(
        value,
        {"format", "manifest_id", "artifacts", "identity_assignments", "states"},
        "rotation manifest",
    )
    if manifest["format"] != FORMAT or type(manifest["format"]) is not int:
        raise GateError("rotation manifest format is invalid")
    _hex(manifest["manifest_id"], HEX32, "rotation manifest ID")
    _ordered_exact_strings(manifest["artifacts"], ROTATION_ARTIFACTS, "rotation artifacts")

    assignments = _exact(
        manifest["identity_assignments"], set(IDENTITIES), "rotation identity assignments"
    )
    seen_pins: set[str] = set()
    for identity_name in IDENTITIES:
        assignment = _exact(
            assignments[identity_name], {"current", "next"}, f"{identity_name} assignment"
        )
        for slot in ("current", "next"):
            pin = assignment[slot]
            if type(pin) is not str or SPKI_PIN.fullmatch(pin) is None:
                raise GateError(f"{identity_name} {slot} pin is invalid")
            try:
                decoded = base64.b64decode(pin.removeprefix("sha256/"), validate=True)
            except (ValueError, TypeError) as error:
                raise GateError(f"{identity_name} {slot} pin is invalid") from error
            if len(decoded) != 32 or pin in seen_pins:
                raise GateError("rotation identity pins are reused")
            seen_pins.add(pin)

    raw_states = _exact(manifest["states"], set(ROTATION_STATES), "rotation states")
    states: dict[str, dict[str, str]] = {}
    for state_name in ROTATION_STATES:
        row = _exact(raw_states[state_name], set(ROTATION_ARTIFACTS), f"{state_name} state")
        states[state_name] = {}
        for artifact in ROTATION_ARTIFACTS:
            states[state_name][artifact] = _hex(
                row[artifact], HEX64, f"{state_name} {artifact} hash"
            )
        private_hashes = [
            digest for artifact, digest in states[state_name].items() if artifact.endswith("-key")
        ]
        certificate_hashes = [
            digest for artifact, digest in states[state_name].items() if artifact.endswith("-cert")
        ]
        if (
            len(private_hashes) != len(set(private_hashes))
            or len(certificate_hashes) != len(set(certificate_hashes))
            or set(private_hashes) & set(certificate_hashes)
        ):
            raise GateError(f"{state_name} reuses a credential artifact")

    for (prior_name, current_name), changed in ROTATION_CHANGE_SETS.items():
        prior, current = states[prior_name], states[current_name]
        actual_changed = {
            artifact for artifact in ROTATION_ARTIFACTS if current[artifact] != prior[artifact]
        }
        if actual_changed != changed:
            raise GateError(
                f"{prior_name} to {current_name} artifact transition is invalid"
            )
    return states


def validate_artifact_snapshot(
    states: dict[str, dict[str, str]], state_name: str, snapshot: Any,
) -> None:
    if state_name not in ROTATION_STATES:
        raise GateError("selected rotation state is invalid")
    actual = _exact(snapshot, set(ROTATION_ARTIFACTS), "rotation artifact snapshot")
    for artifact in ROTATION_ARTIFACTS:
        digest = _hex(actual[artifact], HEX64, f"snapshot {artifact} hash")
        if digest != states[state_name][artifact]:
            raise GateError("rotation artifact snapshot mixes or alters states")


def _slots(value: Any, label: str) -> dict[str, str]:
    slots = _exact(value, set(OBSERVERS), f"{label} slots")
    if any(slot not in {"current", "next"} for slot in slots.values()):
        raise GateError(f"{label} contains an invalid pin slot")
    return slots


def _ordinals(value: Any, labels: tuple[str, ...], name: str) -> dict[str, int]:
    result = _exact(value, set(labels), name)
    for label in labels:
        _integer(result[label], f"{name} {label}", positive=True)
    return result


def _records(value: Any, name: str) -> dict[str, int]:
    result = _exact(value, {"a-to-b", "b-to-a"}, name)
    for direction in ("a-to-b", "b-to-a"):
        _integer(result[direction], f"{name} {direction}")
    return result


def _require_progress(prior: dict[str, int], current: dict[str, int], label: str) -> None:
    for direction in ("a-to-b", "b-to-a"):
        if current[direction] <= prior[direction]:
            raise GateError(f"{label} did not advance {direction} stream progress")


def _validate_common_stage(value: Any, label: str) -> dict[str, Any]:
    stage = _exact(
        value,
        {
            "observed_monotonic_ms",
            "slots",
            "service_invocations",
            "control_sessions",
            "direct_instances",
            "direct_healthy",
            "stream_records",
        },
        label,
    )
    _integer(stage["observed_monotonic_ms"], f"{label} observation", positive=True)
    _slots(stage["slots"], label)
    _ordinals(stage["service_invocations"], COMPONENTS, f"{label} service invocations")
    _ordinals(stage["control_sessions"], EDGES, f"{label} control sessions")
    _ordinals(stage["direct_instances"], EDGES, f"{label} direct instances")
    _true(stage["direct_healthy"], f"{label} direct path")
    _records(stage["stream_records"], f"{label} stream records")
    return stage


def _one_increment(
    prior: dict[str, int], current: dict[str, int], changed: set[str], label: str,
) -> None:
    for key in prior:
        expected = prior[key] + (1 if key in changed else 0)
        if current[key] != expected:
            raise GateError(f"{label} did not make the exact required transition")


def _validate_activation(
    value: Any,
    component: str,
    expected_slots: dict[str, str],
    prior: dict[str, Any],
    active_hash: str,
) -> dict[str, Any]:
    stage = _exact(
        value,
        {
            "component",
            "observed_monotonic_ms",
            "active_marker_sha256",
            "slots",
            "service_invocations",
            "control_sessions",
            "direct_instances",
            "direct_healthy",
            "selected_instance_binding_verified",
            "stream_records",
            "max_outage_ms",
            "sequence_errors",
            "duplicate_records",
            "start_limit_lockouts",
            "digest_ok",
        },
        f"{component} activation",
    )
    if stage["component"] != component or stage["active_marker_sha256"] != active_hash:
        raise GateError(f"{component} activation binding is invalid")
    _integer(stage["observed_monotonic_ms"], f"{component} activation time", positive=True)
    if _slots(stage["slots"], component) != expected_slots:
        raise GateError(f"{component} activation slot matrix is invalid")
    invocations = _ordinals(
        stage["service_invocations"], COMPONENTS, f"{component} service invocations"
    )
    sessions = _ordinals(stage["control_sessions"], EDGES, f"{component} control sessions")
    direct = _ordinals(stage["direct_instances"], EDGES, f"{component} direct instances")
    records = _records(stage["stream_records"], f"{component} stream records")
    _true(stage["direct_healthy"], f"{component} recovered direct path")
    _true(
        stage["selected_instance_binding_verified"],
        f"{component} selected-instance identity binding",
    )
    _true(stage["digest_ok"], f"{component} stream digest")
    if _integer(stage["sequence_errors"], f"{component} sequence errors") != 0:
        raise GateError(f"{component} produced a sequence error")
    if _integer(stage["duplicate_records"], f"{component} duplicate records") != 0:
        raise GateError(f"{component} duplicated an application record")
    if _integer(stage["start_limit_lockouts"], f"{component} start-limit lockouts") != 0:
        raise GateError(f"{component} encountered a start-limit lockout")
    if _integer(stage["max_outage_ms"], f"{component} outage") > MAX_OUTAGE_MS:
        raise GateError(f"{component} outage exceeded the contract")
    _one_increment(
        prior["service_invocations"], invocations, {component}, f"{component} reload"
    )
    changed_sessions = set(EDGES) if component == "relay" else {component}
    _one_increment(prior["control_sessions"], sessions, changed_sessions, f"{component} control")
    changed_direct = set() if component == "relay" else set(EDGES)
    _one_increment(prior["direct_instances"], direct, changed_direct, f"{component} direct")
    _require_progress(prior["stream_records"], records, f"{component} activation")
    return stage


def validate_transcript(value: dict[str, Any], expected: argparse.Namespace) -> dict[str, str]:
    root = _exact(
        value,
        {
            "format",
            "mode",
            "run_id",
            "candidate_sha256",
            "run_manifest_sha256",
            "prerequisite_marker_sha256",
            "rotation_id",
            "rotation_manifest_sha256",
            "transaction_marker_sha256",
            "start_monotonic_ms",
            "complete_monotonic_ms",
            "baseline",
            "overlap",
            "activations",
            "retired",
            "expiry",
            "rollback_drills",
        },
        "transcript root",
    )
    if root["format"] != FORMAT or type(root["format"]) is not int:
        raise GateError("transcript format is invalid")
    if root["mode"] not in {"production", "isolated-test"} or root["mode"] != expected.mode:
        raise GateError("transcript mode is invalid")
    bindings = {
        "run_id": (expected.run_id, HEX32),
        "candidate_sha256": (expected.candidate_sha256, HEX64),
        "run_manifest_sha256": (expected.run_manifest_sha256, HEX64),
        "prerequisite_marker_sha256": (expected.prerequisite_marker_sha256, HEX64),
        "rotation_id": (expected.rotation_id, HEX32),
        "rotation_manifest_sha256": (expected.rotation_manifest_sha256, HEX64),
        "transaction_marker_sha256": (expected.transaction_marker_sha256, HEX64),
    }
    for name, (wanted, pattern) in bindings.items():
        actual = _hex(root[name], pattern, name)
        if actual != wanted:
            raise GateError(f"{name} does not match the active transaction")

    started = _integer(root["start_monotonic_ms"], "transaction start", positive=True)
    completed = _integer(root["complete_monotonic_ms"], "transaction completion", positive=True)
    if started != expected.start_monotonic_ms:
        raise GateError("transaction start does not match the active marker")
    if completed < started or completed - started > MAX_TRANSACTION_MS:
        raise GateError("transaction duration is outside bounds")
    if completed > expected.now_monotonic_ms:
        raise GateError("transaction completion is in the future")

    baseline = _validate_common_stage(root["baseline"], "baseline")
    overlap_raw = _exact(
        root["overlap"],
        {
            "observed_monotonic_ms",
            "slots",
            "service_invocations",
            "control_sessions",
            "direct_instances",
            "direct_healthy",
            "stream_records",
            "authorized_current_and_next",
        },
        "overlap",
    )
    overlap = _validate_common_stage(
        {key: overlap_raw[key] for key in overlap_raw if key != "authorized_current_and_next"},
        "overlap",
    )
    _ordered_exact_strings(
        overlap_raw["authorized_current_and_next"], IDENTITIES, "overlap identities"
    )
    all_current = {observer: "current" for observer in OBSERVERS}
    if baseline["slots"] != all_current or overlap["slots"] != all_current:
        raise GateError("a next slot was observed before activation")
    for field in ("service_invocations", "control_sessions", "direct_instances"):
        if overlap[field] != baseline[field]:
            raise GateError("authorization overlap disturbed a live session")
    _require_progress(baseline["stream_records"], overlap["stream_records"], "authorization overlap")

    activations = root["activations"]
    if not isinstance(activations, list) or len(activations) != len(COMPONENTS):
        raise GateError("activation list is incomplete")
    prior = overlap
    expected_slots = dict(all_current)
    activation_times: list[int] = []
    max_outage = 0
    for index, component in enumerate(COMPONENTS):
        for observer in ACTIVATION_NEW_OBSERVERS[component]:
            expected_slots[observer] = "next"
        stage = _validate_activation(
            activations[index], component, dict(expected_slots), prior,
            expected.transaction_marker_sha256,
        )
        activation_times.append(stage["observed_monotonic_ms"])
        max_outage = max(max_outage, stage["max_outage_ms"])
        prior = stage
    if expected_slots != {observer: "next" for observer in OBSERVERS}:
        raise GateError("the fixed next-slot observation set is incomplete")

    retired = _exact(
        root["retired"],
        {
            "observed_monotonic_ms",
            "slots",
            "service_invocations",
            "control_sessions",
            "direct_instances",
            "direct_healthy",
            "selected_instance_binding_verified",
            "stream_records",
            "max_outage_ms",
            "sequence_errors",
            "duplicate_records",
            "start_limit_lockouts",
            "digest_ok",
            "old_authorized",
            "next_promoted",
            "old_pin_rejections",
            "next_pin_acceptances",
        },
        "retirement",
    )
    retired_time = _integer(retired["observed_monotonic_ms"], "retirement time", positive=True)
    if _slots(retired["slots"], "retirement") != all_current:
        raise GateError("post-retirement slots were not promoted to current")
    retired_invocations = _ordinals(
        retired["service_invocations"], COMPONENTS, "retirement service invocations"
    )
    retired_sessions = _ordinals(retired["control_sessions"], EDGES, "retirement control sessions")
    retired_direct = _ordinals(retired["direct_instances"], EDGES, "retirement direct instances")
    retired_records = _records(retired["stream_records"], "retirement stream records")
    _one_increment(prior["service_invocations"], retired_invocations, set(COMPONENTS), "pin retirement reload")
    for edge in EDGES:
        if retired_sessions[edge] != prior["control_sessions"][edge] + 2:
            raise GateError("pin retirement did not produce the exact control reconnects")
        if retired_direct[edge] != prior["direct_instances"][edge] + 2:
            raise GateError("pin retirement did not produce the exact direct reconnects")
    _true(retired["direct_healthy"], "post-retirement direct path")
    _true(
        retired["selected_instance_binding_verified"],
        "post-retirement selected-instance identity binding",
    )
    _true(retired["digest_ok"], "post-retirement stream digest")
    _true(retired["next_promoted"], "next-pin promotion")
    if retired["old_authorized"] is not False:
        raise GateError("old authorization remained after retirement")
    if _integer(retired["sequence_errors"], "retirement sequence errors") != 0:
        raise GateError("retirement produced a sequence error")
    if _integer(retired["duplicate_records"], "retirement duplicate records") != 0:
        raise GateError("retirement duplicated an application record")
    if _integer(retired["start_limit_lockouts"], "retirement start-limit lockouts") != 0:
        raise GateError("retirement encountered a start-limit lockout")
    retired_outage = _integer(retired["max_outage_ms"], "retirement outage")
    if retired_outage > MAX_OUTAGE_MS:
        raise GateError("retirement outage exceeded the contract")
    max_outage = max(max_outage, retired_outage)
    _require_progress(prior["stream_records"], retired_records, "pin retirement")
    for direction in ("a-to-b", "b-to-a"):
        if retired_records[direction] < MIN_STREAM_RECORDS_EACH_DIRECTION:
            raise GateError("rotation stream is too short")
    _ordered_exact_strings(retired["old_pin_rejections"], IDENTITIES, "old-pin rejections")
    _ordered_exact_strings(retired["next_pin_acceptances"], IDENTITIES, "next-pin acceptances")

    expiry = _exact(root["expiry"], {"observed_monotonic_ms", "authorities"}, "expiry")
    expiry_time = _integer(expiry["observed_monotonic_ms"], "expiry observation", positive=True)
    authorities = _exact(expiry["authorities"], set(EXPIRY_AUTHORITIES), "expiry authorities")
    max_cutoff_overrun = 0
    for authority in EXPIRY_AUTHORITIES:
        proof = _exact(
            authorities[authority],
            {
                "status_expiry_visible",
                "closed_by_cutoff",
                "expired_reconnect_rejected",
                "inside_margin_rejected",
                "next_restored",
                "cutoff_overrun_ms",
                "outage_ms",
            },
            f"{authority} expiry proof",
        )
        for check in (
            "status_expiry_visible",
            "closed_by_cutoff",
            "expired_reconnect_rejected",
            "inside_margin_rejected",
            "next_restored",
        ):
            _true(proof[check], f"{authority} {check}")
        overrun = _integer(proof["cutoff_overrun_ms"], f"{authority} cutoff overrun")
        outage = _integer(proof["outage_ms"], f"{authority} recovery outage")
        if overrun > MAX_CUTOFF_OVERRUN_MS:
            raise GateError(f"{authority} cutoff overrun exceeded the contract")
        if outage > MAX_OUTAGE_MS:
            raise GateError(f"{authority} expiry recovery exceeded the contract")
        max_cutoff_overrun = max(max_cutoff_overrun, overrun)
        max_outage = max(max_outage, outage)

    drills = _exact(
        root["rollback_drills"], {"pre-retirement", "post-retirement"}, "rollback drills"
    )
    for floor in ("pre-retirement", "post-retirement"):
        drill = _exact(
            drills[floor],
            {
                "triggered",
                "bounded_ms",
                "credential_state_verified",
                "authorization_state_verified",
                "service_state_verified",
                "direct_health_verified",
                "stream_resumed",
                "old_authorized",
                "next_authorized",
            },
            f"{floor} rollback drill",
        )
        for check in (
            "triggered",
            "credential_state_verified",
            "authorization_state_verified",
            "service_state_verified",
            "direct_health_verified",
            "stream_resumed",
            "next_authorized",
        ):
            _true(drill[check], f"{floor} rollback {check}")
        duration = _integer(drill["bounded_ms"], f"{floor} rollback duration")
        if duration > MAX_ROLLBACK_MS:
            raise GateError(f"{floor} rollback exceeded the contract")
        expected_old = floor == "pre-retirement"
        if drill["old_authorized"] is not expected_old:
            raise GateError(f"{floor} rollback restored an unsafe authorization floor")

    timeline = [
        baseline["observed_monotonic_ms"],
        overlap["observed_monotonic_ms"],
        *activation_times,
        retired_time,
        expiry_time,
        completed,
    ]
    if timeline[0] < started or any(right <= left for left, right in zip(timeline, timeline[1:])):
        raise GateError("rotation observations are not strictly monotonic")

    control_reconnects = sum(
        retired_sessions[edge] - baseline["control_sessions"][edge] for edge in EDGES
    )
    direct_reconnects = min(
        retired_direct[edge] - baseline["direct_instances"][edge] for edge in EDGES
    )
    marker = {
        "FORMAT": "1",
        "STATUS": "pass",
        "GATE": "certificate-rotation",
        "MODE": expected.mode,
        "RUN_ID": expected.run_id,
        "CANDIDATE_SHA256": expected.candidate_sha256,
        "RUN_MANIFEST_SHA256": expected.run_manifest_sha256,
        "PREREQUISITE_MARKER_SHA256": expected.prerequisite_marker_sha256,
        "START_MONOTONIC_MS": str(started),
        "COMPLETE_MONOTONIC_MS": str(completed),
        "ROTATION_ID": expected.rotation_id,
        "ROTATION_MANIFEST_SHA256": expected.rotation_manifest_sha256,
        "TRANSACTION_MARKER_SHA256": expected.transaction_marker_sha256,
        "CURRENT_NEXT_OVERLAP_CHECKS": str(len(IDENTITIES)),
        "NEXT_SLOT_OBSERVATIONS": str(len(OBSERVERS)),
        "NEXT_OBSERVATIONS_INSIDE_TRANSACTION": str(len(OBSERVERS)),
        "NEXT_OBSERVATIONS_OUTSIDE_TRANSACTION": "0",
        "SERVICE_RELOADS": "6",
        "CONTROL_RECONNECTS": str(control_reconnects),
        "DIRECT_RECONNECTS": str(direct_reconnects),
        "MAX_APPLICATION_OUTAGE_MS": str(max_outage),
        "STREAM_RECORDS_A_TO_B": str(retired_records["a-to-b"]),
        "STREAM_RECORDS_B_TO_A": str(retired_records["b-to-a"]),
        "STREAM_DIGEST_DIRECTIONS": "2",
        "OLD_PIN_REJECTIONS": str(len(IDENTITIES)),
        "NEXT_PIN_ACCEPTANCES": str(len(IDENTITIES)),
        "EXPIRY_AUTHORITIES": str(len(EXPIRY_AUTHORITIES)),
        "EXPIRY_VISIBILITY_CHECKS": str(len(EXPIRY_AUTHORITIES)),
        "EXPIRED_RECONNECT_REJECTIONS": str(len(EXPIRY_AUTHORITIES)),
        "INSIDE_MARGIN_REJECTIONS": str(len(EXPIRY_AUTHORITIES)),
        "NEXT_RESTORATIONS": str(len(EXPIRY_AUTHORITIES)),
        "MAX_CUTOFF_OVERRUN_MS": str(max_cutoff_overrun),
        "ROLLBACK_SCENARIOS": "2",
        "ROLLBACK_RESTORES": "2",
    }
    if tuple(marker) != PASS_MARKER_KEYS:
        raise AssertionError("internal pass marker schema drift")
    return marker


def _write_marker(path: Path, marker: dict[str, str]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as output:
            for key, value in marker.items():
                if re.fullmatch(r"[A-Za-z0-9._:+-]+", value) is None:
                    raise GateError("marker value is not canonical")
                output.write(f"{key}={value}\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def validate_rollback(value: dict[str, Any], expected: argparse.Namespace) -> None:
    marker = _exact(
        value,
        {
            "format",
            "status",
            "gate",
            "mode",
            "run_id",
            "candidate_sha256",
            "rotation_id",
            "rotation_manifest_sha256",
            "transaction_marker_sha256",
            "rollback_floor",
            "selected_state",
            "complete_monotonic_ms",
            "credential_state_verified",
            "authorization_state_verified",
            "service_state_verified",
            "direct_health_verified",
            "old_authorized",
            "next_authorized",
        },
        "rollback marker",
    )
    if marker["format"] != 1 or marker["status"] != "pass" or marker["gate"] != "certificate-rotation-rollback":
        raise GateError("rollback marker header is invalid")
    if marker["mode"] != expected.mode:
        raise GateError("rollback mode is invalid")
    for name, wanted, pattern in (
        ("run_id", expected.run_id, HEX32),
        ("candidate_sha256", expected.candidate_sha256, HEX64),
        ("rotation_id", expected.rotation_id, HEX32),
        ("rotation_manifest_sha256", expected.rotation_manifest_sha256, HEX64),
        ("transaction_marker_sha256", expected.transaction_marker_sha256, HEX64),
    ):
        if _hex(marker[name], pattern, name) != wanted:
            raise GateError(f"rollback {name} binding is invalid")
    if marker["rollback_floor"] != expected.rollback_floor:
        raise GateError("rollback floor is invalid")
    expected_state = "overlap" if expected.rollback_floor == "pre-retirement" else "post"
    if marker["selected_state"] != expected_state:
        raise GateError("rollback selected state is invalid")
    completed = _integer(marker["complete_monotonic_ms"], "rollback completion", positive=True)
    if completed > expected.now_monotonic_ms:
        raise GateError("rollback completion is in the future")
    for name in (
        "credential_state_verified",
        "authorization_state_verified",
        "service_state_verified",
        "direct_health_verified",
    ):
        _true(marker[name], f"rollback {name}")
    expected_old = expected.rollback_floor == "pre-retirement"
    if marker["old_authorized"] is not expected_old or marker["next_authorized"] is not True:
        raise GateError("rollback authorization floor is unsafe")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    manifest = subparsers.add_parser("validate-manifest")
    manifest.add_argument("--mode", choices=("production", "isolated-test"), required=True)
    manifest.add_argument("--manifest", type=Path, required=True)
    manifest.add_argument("--state", choices=ROTATION_STATES)
    manifest.add_argument("--snapshot", type=Path)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--mode", choices=("production", "isolated-test"), required=True)
    common.add_argument("--run-id", required=True)
    common.add_argument("--candidate-sha256", required=True)
    common.add_argument("--rotation-id", required=True)
    common.add_argument("--rotation-manifest-sha256", required=True)
    common.add_argument("--transaction-marker-sha256", required=True)
    common.add_argument("--now-monotonic-ms", type=int, required=True)

    validate = subparsers.add_parser("validate", parents=[common])
    validate.add_argument("--transcript", type=Path, required=True)
    validate.add_argument("--run-manifest-sha256", required=True)
    validate.add_argument("--prerequisite-marker-sha256", required=True)
    validate.add_argument("--start-monotonic-ms", type=int, required=True)
    validate.add_argument("--output", type=Path, required=True)

    rollback = subparsers.add_parser("validate-rollback", parents=[common])
    rollback.add_argument("--marker", type=Path, required=True)
    rollback.add_argument(
        "--rollback-floor", choices=("pre-retirement", "next-only"), required=True
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate-manifest":
            manifest = _read_json(
                arguments.manifest,
                production=arguments.mode == "production",
                expected_mode=0o444,
            )
            states = validate_rotation_manifest(manifest)
            if (arguments.state is None) != (arguments.snapshot is None):
                raise GateError("state and snapshot must be supplied together")
            if arguments.snapshot is not None:
                snapshot = _read_json(
                    arguments.snapshot, production=arguments.mode == "production"
                )
                validate_artifact_snapshot(states, arguments.state, snapshot)
        elif arguments.command == "validate":
            value = _read_json(
                arguments.transcript, production=arguments.mode == "production"
            )
            marker = validate_transcript(value, arguments)
            _write_marker(arguments.output, marker)
        else:
            value = _read_json(arguments.marker, production=arguments.mode == "production")
            validate_rollback(value, arguments)
    except (GateError, OSError) as error:
        print(f"certificate-rotation gate rejected evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
