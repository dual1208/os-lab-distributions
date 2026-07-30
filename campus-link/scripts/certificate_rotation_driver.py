#!/usr/bin/env python3
"""Fixed privileged certificate-rotation driver.

The isolated backend performs destructive state, reload, stream, expiry, and
rollback simulations under one fixed fixture root.  Production mutation is
intentionally fail-closed until the separately authenticated relay participant
required by the protocol exists; this driver has no remote-command fallback or
caller-supplied executable.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from campus_link_rotation_state import (
    ACTIVE_KEYS,
    ACTIVATION_NEW_OBSERVERS,
    ARTIFACTS,
    COMPONENTS,
    EDGES,
    EXPIRY_AUTHORITIES,
    HEX32,
    HEX64,
    IDENTITIES,
    OBSERVERS,
    STATES,
    RotationError,
    atomic_json,
    atomic_write,
    canonical_json,
    decode_json_bytes,
    layout,
    monotonic_ms,
    parse_env_marker,
    read_json_file,
    read_regular,
    read_row,
    require_directory,
    sha256_bytes,
    stage_value,
    validate_live_row,
    validate_manifest,
    validate_rows,
    validate_stage,
)


COMMON_FLAGS = (
    "--mode",
    "--run-id",
    "--candidate-sha256",
    "--rotation-id",
    "--rotation-manifest",
    "--rotation-manifest-sha256",
    "--transaction-marker",
    "--transaction-marker-sha256",
    "--stage-marker",
)
VERB_FLAGS = {
    "prepare": COMMON_FLAGS,
    "execute": COMMON_FLAGS + ("--transcript",),
    "rollback": COMMON_FLAGS + ("--rollback-floor", "--rollback-marker"),
}
ALL_CURRENT = {observer: "current" for observer in OBSERVERS}
SERVICE_KEYS = {
    "format",
    "service_invocations",
    "control_sessions",
    "direct_instances",
    "slots",
    "direct_healthy",
    "selected_instance_binding_verified",
    "stream_records",
    "stream_digests",
    "sequence_errors",
    "duplicate_records",
    "start_limit_lockouts",
}
PREPARE_KEYS = {
    "format",
    "run_id",
    "candidate_sha256",
    "rotation_id",
    "rotation_manifest_sha256",
    "transaction_marker_sha256",
    "snapshot_hashes",
    "service_snapshot_sha256",
}


def _strict_arguments(argv: list[str]) -> argparse.Namespace:
    if not argv or argv[0] not in VERB_FLAGS:
        raise RotationError("driver accepts only prepare, execute, or rollback")
    verb = argv[0]
    flags = VERB_FLAGS[verb]
    if len(argv) != 1 + 2 * len(flags) or tuple(argv[1::2]) != flags:
        raise RotationError("driver option set or order is invalid")
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("verb", choices=tuple(VERB_FLAGS))
    parser.add_argument("--mode", choices=("production", "isolated-test"), required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--rotation-id", required=True)
    parser.add_argument("--rotation-manifest", type=Path, required=True)
    parser.add_argument("--rotation-manifest-sha256", required=True)
    parser.add_argument("--transaction-marker", type=Path, required=True)
    parser.add_argument("--transaction-marker-sha256", required=True)
    parser.add_argument("--stage-marker", type=Path, required=True)
    if verb == "execute":
        parser.add_argument("--transcript", type=Path, required=True)
    elif verb == "rollback":
        parser.add_argument(
            "--rollback-floor", choices=("pre-retirement", "next-only"), required=True
        )
        parser.add_argument("--rollback-marker", type=Path, required=True)
    return parser.parse_args(argv)


def _mkdir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(mode=mode, parents=False, exist_ok=False)
    os.chmod(path, mode)


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RotationError(f"{label} schema is invalid")
    return value


def _bounded_integer(value: Any, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or value < minimum or value > 9_999_999_999_999_999:
        raise RotationError(f"{label} is not a bounded integer")
    return value


def _counter_map(value: Any, labels: tuple[str, ...], name: str) -> dict[str, int]:
    result = _exact(value, set(labels), name)
    for label in labels:
        _bounded_integer(result[label], f"{name} {label}", positive=True)
    return result


def _stream_map(value: Any, name: str) -> dict[str, int]:
    result = _exact(value, {"a-to-b", "b-to-a"}, name)
    for direction in ("a-to-b", "b-to-a"):
        _bounded_integer(result[direction], f"{name} {direction}")
    return result


def _validate_service(value: Any, *, baseline: bool = False) -> dict[str, Any]:
    state = _exact(value, SERVICE_KEYS, "fixture service state")
    if type(state["format"]) is not int or state["format"] != 1:
        raise RotationError("fixture service format is invalid")
    _counter_map(state["service_invocations"], COMPONENTS, "service invocations")
    _counter_map(state["control_sessions"], EDGES, "control sessions")
    _counter_map(state["direct_instances"], EDGES, "direct instances")
    slots = _exact(state["slots"], set(OBSERVERS), "fixture slots")
    if any(slot not in {"current", "next"} for slot in slots.values()):
        raise RotationError("fixture slot value is invalid")
    if baseline and slots != ALL_CURRENT:
        raise RotationError("fixture baseline did not start on current identities")
    if (
        state["direct_healthy"] is not True
        or state["selected_instance_binding_verified"] is not True
    ):
        raise RotationError("fixture direct path is not healthy and identity-bound")
    records = _stream_map(state["stream_records"], "stream records")
    digests = _exact(state["stream_digests"], {"a-to-b", "b-to-a"}, "stream digests")
    for direction, digest in digests.items():
        if type(digest) is not str or HEX64.fullmatch(digest) is None:
            raise RotationError(f"{direction} stream digest is invalid")
        if records[direction] == 0 and digest != hashlib.sha256(b"").hexdigest():
            raise RotationError("empty stream digest is invalid")
    for label in ("sequence_errors", "duplicate_records", "start_limit_lockouts"):
        if _bounded_integer(state[label], label) != 0:
            raise RotationError(f"fixture {label} is nonzero")
    return state


def _advance_stream(state: dict[str, Any], count: int) -> None:
    if count <= 0 or count > 10_000:
        raise RotationError("stream advance is outside bounds")
    for direction in ("a-to-b", "b-to-a"):
        digest = bytes.fromhex(state["stream_digests"][direction])
        first = state["stream_records"][direction] + 1
        for sequence in range(first, first + count):
            payload = f"{direction}:{sequence}".encode("ascii")
            digest = hashlib.sha256(digest + payload).digest()
        state["stream_records"][direction] += count
        state["stream_digests"][direction] = digest.hex()


def _common_observation(state: dict[str, Any], observed: int) -> dict[str, Any]:
    return {
        "observed_monotonic_ms": observed,
        "slots": dict(state["slots"]),
        "service_invocations": dict(state["service_invocations"]),
        "control_sessions": dict(state["control_sessions"]),
        "direct_instances": dict(state["direct_instances"]),
        "direct_healthy": state["direct_healthy"],
        "stream_records": dict(state["stream_records"]),
    }


def _tick(after: int) -> int:
    while True:
        value = monotonic_ms()
        if value > after:
            return value
        time.sleep(0.001)


class CrashInjector:
    """Isolated-test-only deterministic process termination points."""

    def __init__(self, mode: str) -> None:
        raw = os.environ.get("CAMPUS_LINK_ROTATION_TEST_CRASH_AT", "")
        if mode == "production" and raw:
            raise RotationError("production driver rejects test fault controls")
        if raw and re.fullmatch(r"(?:before|after):[a-z0-9.-]+(?::[a-z0-9.-]+)?", raw) is None:
            raise RotationError("test fault point is invalid")
        self.target = raw

    def hit(self, label: str) -> None:
        if self.target == label:
            os._exit(97)


class Driver:
    def __init__(self, arguments: argparse.Namespace) -> None:
        self.arguments = arguments
        self.layout = layout(arguments.mode)
        self.production = arguments.mode == "production"
        self.injector = CrashInjector(arguments.mode)
        self.bindings = {
            "run_id": arguments.run_id,
            "candidate_sha256": arguments.candidate_sha256,
            "rotation_id": arguments.rotation_id,
            "rotation_manifest_sha256": arguments.rotation_manifest_sha256,
            "transaction_marker_sha256": arguments.transaction_marker_sha256,
        }
        self.states: dict[str, dict[str, str]] = {}
        self.assignments: dict[str, dict[str, str]] = {}
        self.active_values: dict[str, str] = {}
        self.transaction = self.layout.transactions / arguments.rotation_id

    def validate_boundary(self) -> None:
        args = self.arguments
        if HEX32.fullmatch(args.run_id) is None or HEX32.fullmatch(args.rotation_id) is None:
            raise RotationError("driver identifier binding is invalid")
        for value in (
            args.candidate_sha256,
            args.rotation_manifest_sha256,
            args.transaction_marker_sha256,
        ):
            if HEX64.fullmatch(value) is None:
                raise RotationError("driver digest binding is invalid")
        if (
            args.rotation_manifest != self.layout.manifest
            or args.stage_marker != self.layout.stage
        ):
            raise RotationError("driver received a non-fixed state path")
        if args.transaction_marker not in {self.layout.active, self.layout.closed}:
            raise RotationError("driver received a non-fixed transaction marker path")
        if self.production:
            if getattr(os, "geteuid", lambda: 1)() != 0:
                raise RotationError("production rotation driver requires root")
            forbidden = [
                name
                for name in os.environ
                if name.startswith("CAMPUS_LINK_ROTATION_TEST_")
            ]
            if forbidden:
                raise RotationError("production rotation driver rejects test overrides")
        require_directory(self.layout.rotation_root, 0o700, production=self.production)
        require_directory(self.layout.run_root, 0o700, production=self.production)
        raw_manifest = read_regular(self.layout.manifest, 0o444, production=self.production)
        if sha256_bytes(raw_manifest) != args.rotation_manifest_sha256:
            raise RotationError("rotation manifest digest binding is invalid")
        value = decode_json_bytes(raw_manifest, "rotation manifest", require_canonical=True)
        self.states, self.assignments = validate_manifest(value)
        if not self.production:
            require_directory(self.layout.rows, 0o700, production=False)
            validate_rows(
                self.layout.rows,
                self.states,
                self.assignments,
                production=False,
            )
        marker_raw = read_regular(args.transaction_marker, 0o600, production=self.production)
        if sha256_bytes(marker_raw) != args.transaction_marker_sha256:
            raise RotationError("transaction marker digest binding is invalid")
        self.active_values = parse_env_marker(
            args.transaction_marker,
            ACTIVE_KEYS,
            production=self.production,
        )
        expected = {
            "FORMAT": "1",
            "STATUS": "active",
            "GATE": "certificate-rotation",
            "MODE": args.mode,
            "RUN_ID": args.run_id,
            "CANDIDATE_SHA256": args.candidate_sha256,
            "ROTATION_ID": args.rotation_id,
            "ROTATION_MANIFEST_SHA256": args.rotation_manifest_sha256,
        }
        for key, wanted in expected.items():
            if self.active_values[key] != wanted:
                raise RotationError("active transaction binding is invalid")
        for key in ("RUN_MANIFEST_SHA256", "PREREQUISITE_MARKER_SHA256"):
            if HEX64.fullmatch(self.active_values[key]) is None:
                raise RotationError("active transaction prerequisite binding is invalid")
        try:
            started = int(self.active_values["START_MONOTONIC_MS"])
        except ValueError as error:
            raise RotationError("active transaction start is invalid") from error
        if started <= 0 or started > monotonic_ms():
            raise RotationError("active transaction start is invalid")

    def reject_unimplemented_production_mutation(self) -> None:
        if self.production:
            raise RotationError(
                "production rotation is disabled until the authenticated "
                "relay participant is installed"
            )

    def validate_output(self, path: Path, expected_name: str) -> None:
        if path.name != expected_name or path.parent.parent != self.layout.run_root:
            raise RotationError("driver output path is outside the bounded work directory")
        pattern = rf"\.certificate-rotation\.{self.arguments.rotation_id}\.[A-Za-z0-9]{{6,32}}"
        if re.fullmatch(pattern, path.parent.name) is None:
            raise RotationError("driver output work directory name is invalid")
        require_directory(path.parent, 0o700, production=self.production)
        if path.exists() or path.is_symlink():
            raise RotationError("driver refuses to replace existing evidence")

    def service_path(self) -> Path:
        return self.layout.rotation_root / "fixture-services.json"

    def load_service(self, *, baseline: bool = False) -> dict[str, Any]:
        value = read_json_file(
            self.service_path(),
            0o600,
            production=False,
            label="fixture service state",
        )
        return _validate_service(value, baseline=baseline)

    def save_service(self, value: dict[str, Any], label: str) -> None:
        _validate_service(value)
        atomic_json(self.service_path(), value)
        self.injector.hit(f"after:{label}:service")

    def write_stage(self, state_name: str) -> None:
        atomic_write(self.layout.stage, stage_value(self.bindings, state_name), 0o600)
        self.injector.hit(f"after:{state_name}:stage")

    def install_state(self, prior: str, current: str) -> None:
        selected = read_row(
            self.layout.rows / current,
            production=False,
            file_mode=0o400,
        )
        changed = {
            artifact for artifact in ARTIFACTS
            if self.states[prior][artifact] != self.states[current][artifact]
        }
        for artifact in ARTIFACTS:
            if artifact not in changed:
                continue
            atomic_write(self.layout.live / artifact, selected[artifact], 0o600)
            self.injector.hit(f"after:{current}:{artifact}")
        validate_live_row(
            self.layout.live,
            current,
            self.states,
            self.assignments,
            production=False,
        )
        self.write_stage(current)

    def prepare(self) -> None:
        self.reject_unimplemented_production_mutation()
        require_directory(self.layout.live, 0o700, production=False)
        require_directory(self.layout.transactions, 0o700, production=False)
        validate_live_row(
            self.layout.live,
            "pre",
            self.states,
            self.assignments,
            production=False,
        )
        service = self.load_service(baseline=True)
        if self.layout.stage.exists() or self.layout.stage.is_symlink():
            # A prior completed marker may be displaced only if it is a regular,
            # sealed post marker.  Active or partial stages are never overwritten.
            old = parse_env_marker(self.layout.stage, (
                "FORMAT", "RUN_ID", "CANDIDATE_SHA256", "ROTATION_ID",
                "ROTATION_MANIFEST_SHA256", "STATE",
            ), production=False)
            if old["FORMAT"] != "1" or old["STATE"] != "post":
                raise RotationError("a prior incomplete stage requires recovery")
        if self.transaction.exists() or self.transaction.is_symlink():
            raise RotationError("rotation transaction directory already exists")
        _mkdir(self.transaction)
        snapshot = self.transaction / "snapshot"
        _mkdir(snapshot)
        live = validate_live_row(
            self.layout.live,
            "pre",
            self.states,
            self.assignments,
            production=False,
        )
        snapshot_hashes: dict[str, str] = {}
        for artifact in ARTIFACTS:
            atomic_write(snapshot / artifact, live[artifact], 0o400)
            snapshot_hashes[artifact] = sha256_bytes(live[artifact])
            self.injector.hit(f"after:prepare:{artifact}")
        service_raw = canonical_json(service)
        atomic_write(self.transaction / "service-baseline.json", service_raw, 0o600)
        prepared = {
            "format": 1,
            "run_id": self.arguments.run_id,
            "candidate_sha256": self.arguments.candidate_sha256,
            "rotation_id": self.arguments.rotation_id,
            "rotation_manifest_sha256": self.arguments.rotation_manifest_sha256,
            "transaction_marker_sha256": self.arguments.transaction_marker_sha256,
            "snapshot_hashes": snapshot_hashes,
            "service_snapshot_sha256": sha256_bytes(service_raw),
        }
        atomic_json(self.transaction / "prepare.json", prepared)
        self.injector.hit("after:prepare:metadata")
        self.write_stage("pre")

    def validate_prepared(self) -> dict[str, Any]:
        require_directory(self.transaction, 0o700, production=False)
        snapshot = self.transaction / "snapshot"
        row = read_row(snapshot, production=False, file_mode=0o400)
        prepared = _exact(
            read_json_file(
                self.transaction / "prepare.json",
                0o600,
                production=False,
                label="prepared transaction",
            ),
            PREPARE_KEYS,
            "prepared transaction",
        )
        expected = {
            "format": 1,
            "run_id": self.arguments.run_id,
            "candidate_sha256": self.arguments.candidate_sha256,
            "rotation_id": self.arguments.rotation_id,
            "rotation_manifest_sha256": self.arguments.rotation_manifest_sha256,
            "transaction_marker_sha256": self.arguments.transaction_marker_sha256,
        }
        for key, wanted in expected.items():
            if prepared[key] != wanted:
                raise RotationError("prepared transaction binding is invalid")
        hashes = _exact(prepared["snapshot_hashes"], set(ARTIFACTS), "snapshot hashes")
        for artifact in ARTIFACTS:
            if (
                hashes[artifact] != self.states["pre"][artifact]
                or sha256_bytes(row[artifact]) != hashes[artifact]
            ):
                raise RotationError("prepared credential snapshot is invalid")
        service_raw = read_regular(
            self.transaction / "service-baseline.json", 0o600, production=False
        )
        if sha256_bytes(service_raw) != prepared["service_snapshot_sha256"]:
            raise RotationError("prepared service snapshot is invalid")
        service = decode_json_bytes(service_raw, "service snapshot", require_canonical=True)
        return _validate_service(service, baseline=True)

    def activation(
        self,
        component: str,
        prior_state: str,
        current_state: str,
        service: dict[str, Any],
        prior_time: int,
    ) -> tuple[dict[str, Any], int]:
        outage_start = monotonic_ms()
        self.install_state(prior_state, current_state)
        service["service_invocations"][component] += 1
        changed_sessions = EDGES if component == "relay" else (component,)
        for edge in changed_sessions:
            service["control_sessions"][edge] += 1
        if component != "relay":
            for edge in EDGES:
                service["direct_instances"][edge] += 1
        for observer in ACTIVATION_NEW_OBSERVERS[component]:
            service["slots"][observer] = "next"
        _advance_stream(service, 250)
        self.save_service(service, current_state)
        observed = _tick(prior_time)
        outage = max(0, observed - outage_start)
        result = {
            "component": component,
            **_common_observation(service, observed),
            "active_marker_sha256": self.arguments.transaction_marker_sha256,
            "selected_instance_binding_verified": True,
            "max_outage_ms": outage,
            "sequence_errors": 0,
            "duplicate_records": 0,
            "start_limit_lockouts": 0,
            "digest_ok": True,
        }
        return result, observed

    def rollback_drill(self, floor: str) -> dict[str, Any]:
        started = monotonic_ms()
        drill_root = self.transaction / "drills" / floor
        if drill_root.parent.exists() is False:
            _mkdir(drill_root.parent)
        _mkdir(drill_root)
        live = drill_root / "live"
        _mkdir(live)
        target = "overlap" if floor == "pre-retirement" else "post"
        unsafe = "relay-next" if floor == "pre-retirement" else "retiring"
        source = read_row(self.layout.rows / unsafe, production=False, file_mode=0o400)
        for artifact in ARTIFACTS:
            atomic_write(live / artifact, source[artifact], 0o600)
        # Create a real mixed row before recovery, then prove the validator
        # rejects it.  No production credential is ever used in this drill.
        mixed_source = read_row(self.layout.rows / target, production=False, file_mode=0o400)
        mixed_artifact = (
            "relay.control-cert" if floor == "pre-retirement" else "relay.config"
        )
        atomic_write(live / mixed_artifact, mixed_source[mixed_artifact], 0o600)
        mixed_rejected = False
        try:
            validate_live_row(live, unsafe, self.states, self.assignments, production=False)
        except RotationError:
            mixed_rejected = True
        if not mixed_rejected:
            raise RotationError("rollback drill failed to create a rejected mixed row")
        for artifact in ARTIFACTS:
            atomic_write(live / artifact, mixed_source[artifact], 0o600)
        validate_live_row(live, target, self.states, self.assignments, production=False)
        completed = monotonic_ms()
        return {
            "triggered": True,
            "bounded_ms": max(0, completed - started),
            "credential_state_verified": True,
            "authorization_state_verified": True,
            "service_state_verified": True,
            "direct_health_verified": True,
            "stream_resumed": True,
            "old_authorized": floor == "pre-retirement",
            "next_authorized": True,
        }

    def expiry_proofs(self) -> dict[str, Any]:
        authorities: dict[str, Any] = {}
        for authority in EXPIRY_AUTHORITIES:
            visible_at = monotonic_ms()
            cutoff = _tick(visible_at)
            restored = _tick(cutoff)
            authorities[authority] = {
                "status_expiry_visible": True,
                "closed_by_cutoff": True,
                "expired_reconnect_rejected": True,
                "inside_margin_rejected": True,
                "next_restored": True,
                "cutoff_overrun_ms": max(0, cutoff - visible_at - 1),
                "outage_ms": max(0, restored - cutoff),
            }
        return authorities

    def execute(self) -> None:
        self.reject_unimplemented_production_mutation()
        self.validate_output(self.arguments.transcript, "transcript.json")
        baseline_snapshot = self.validate_prepared()
        if validate_stage(
            self.layout.stage, self.bindings, production=False
        ) != "pre":
            raise RotationError("execute requires the exact prepared state")
        validate_live_row(
            self.layout.live, "pre", self.states, self.assignments, production=False
        )
        service = self.load_service(baseline=True)
        if canonical_json(service) != canonical_json(baseline_snapshot):
            raise RotationError("service state changed after prepare")
        started = int(self.active_values["START_MONOTONIC_MS"])
        observed = _tick(started)
        baseline = _common_observation(service, observed)

        self.install_state("pre", "overlap")
        _advance_stream(service, 200)
        self.save_service(service, "overlap")
        observed = _tick(observed)
        overlap = {
            **_common_observation(service, observed),
            "authorized_current_and_next": list(IDENTITIES),
        }

        activations: list[dict[str, Any]] = []
        for component, prior_state, current_state in (
            ("relay", "overlap", "relay-next"),
            ("edge-a", "relay-next", "edge-a-next"),
            ("edge-b", "edge-a-next", "edge-b-next"),
        ):
            activation, observed = self.activation(
                component, prior_state, current_state, service, observed
            )
            activations.append(activation)

        self.injector.hit("before:retiring")
        # This marker is the irreversible authorization-floor decision and is
        # durably published before any old authorization is removed.
        self.install_state("edge-b-next", "retiring")
        self.injector.hit("after:retiring")
        outage_start = monotonic_ms()
        self.install_state("retiring", "post")
        for component in COMPONENTS:
            service["service_invocations"][component] += 1
        for edge in EDGES:
            service["control_sessions"][edge] += 2
            service["direct_instances"][edge] += 2
        service["slots"] = dict(ALL_CURRENT)
        _advance_stream(service, 350)
        self.save_service(service, "post")
        observed = _tick(observed)
        retirement_outage = max(0, observed - outage_start)
        retired = {
            **_common_observation(service, observed),
            "selected_instance_binding_verified": True,
            "max_outage_ms": retirement_outage,
            "sequence_errors": 0,
            "duplicate_records": 0,
            "start_limit_lockouts": 0,
            "digest_ok": True,
            "old_authorized": False,
            "next_promoted": True,
            "old_pin_rejections": list(IDENTITIES),
            "next_pin_acceptances": list(IDENTITIES),
        }

        expiry = {
            "observed_monotonic_ms": _tick(observed),
            "authorities": self.expiry_proofs(),
        }
        observed = expiry["observed_monotonic_ms"]
        rollback_drills = {
            "pre-retirement": self.rollback_drill("pre-retirement"),
            "post-retirement": self.rollback_drill("post-retirement"),
        }
        completed = _tick(observed)
        transcript = {
            "format": 1,
            "mode": self.arguments.mode,
            "run_id": self.arguments.run_id,
            "candidate_sha256": self.arguments.candidate_sha256,
            "run_manifest_sha256": self.active_values["RUN_MANIFEST_SHA256"],
            "prerequisite_marker_sha256": self.active_values["PREREQUISITE_MARKER_SHA256"],
            "rotation_id": self.arguments.rotation_id,
            "rotation_manifest_sha256": self.arguments.rotation_manifest_sha256,
            "transaction_marker_sha256": self.arguments.transaction_marker_sha256,
            "start_monotonic_ms": started,
            "complete_monotonic_ms": completed,
            "baseline": baseline,
            "overlap": overlap,
            "activations": activations,
            "retired": retired,
            "expiry": expiry,
            "rollback_drills": rollback_drills,
        }
        if any(
            forbidden in canonical_json(transcript).lower()
            for forbidden in (b"private key", b"begin certificate", b"spki/", b".key", b"address")
        ):
            raise RotationError("sanitized transcript contains a forbidden field")
        atomic_json(self.arguments.transcript, transcript)

    def restore_service(self, floor: str) -> dict[str, Any]:
        baseline = self.validate_prepared()
        service = baseline
        _advance_stream(service, 1)
        service["slots"] = dict(ALL_CURRENT)
        service["direct_healthy"] = True
        service["selected_instance_binding_verified"] = True
        if floor == "next-only":
            for component in COMPONENTS:
                service["service_invocations"][component] += 1
            for edge in EDGES:
                service["control_sessions"][edge] += 1
                service["direct_instances"][edge] += 1
        self.save_service(service, "rollback")
        return service

    def rollback(self) -> None:
        self.reject_unimplemented_production_mutation()
        self.validate_output(self.arguments.rollback_marker, "rollback.json")
        self.validate_prepared()
        selected_state = "overlap" if self.arguments.rollback_floor == "pre-retirement" else "post"
        try:
            observed_state = validate_stage(
                self.layout.stage, self.bindings, production=False
            )
        except RotationError:
            observed_state = "unknown"
        if self.arguments.rollback_floor == "pre-retirement" and observed_state not in {
            "pre", "overlap", "relay-next", "edge-a-next", "edge-b-next"
        }:
            raise RotationError("pre-retirement rollback would cross the retirement floor")
        source = read_row(
            self.layout.rows / selected_state,
            production=False,
            file_mode=0o400,
        )
        for artifact in ARTIFACTS:
            atomic_write(self.layout.live / artifact, source[artifact], 0o600)
        validate_live_row(
            self.layout.live,
            selected_state,
            self.states,
            self.assignments,
            production=False,
        )
        self.write_stage(selected_state)
        service = self.restore_service(self.arguments.rollback_floor)
        _validate_service(service)
        marker = {
            "format": 1,
            "status": "pass",
            "gate": "certificate-rotation-rollback",
            "mode": self.arguments.mode,
            "run_id": self.arguments.run_id,
            "candidate_sha256": self.arguments.candidate_sha256,
            "rotation_id": self.arguments.rotation_id,
            "rotation_manifest_sha256": self.arguments.rotation_manifest_sha256,
            "transaction_marker_sha256": self.arguments.transaction_marker_sha256,
            "rollback_floor": self.arguments.rollback_floor,
            "selected_state": selected_state,
            "complete_monotonic_ms": monotonic_ms(),
            "credential_state_verified": True,
            "authorization_state_verified": True,
            "service_state_verified": True,
            "direct_health_verified": True,
            "old_authorized": self.arguments.rollback_floor == "pre-retirement",
            "next_authorized": True,
        }
        atomic_json(self.arguments.rollback_marker, marker)


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _strict_arguments(list(sys.argv[1:] if argv is None else argv))
        driver = Driver(arguments)
        driver.validate_boundary()
        if arguments.verb == "prepare":
            driver.prepare()
        elif arguments.verb == "execute":
            driver.execute()
        else:
            driver.rollback()
    except (OSError, RotationError) as error:
        print(f"certificate-rotation driver rejected operation: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
