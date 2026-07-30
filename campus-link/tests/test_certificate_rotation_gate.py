#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import pathlib
import types
import unittest


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
SPEC = importlib.util.spec_from_file_location(
    "certificate_rotation_gate", HERE / "certificate_rotation_gate.py"
)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


RUN_ID = "1" * 32
CANDIDATE = "2" * 64
RUN_MANIFEST = "3" * 64
PREREQUISITE = "4" * 64
ROTATION_ID = "5" * 32
ROTATION_MANIFEST = "6" * 64
ACTIVE = "7" * 64


def expected() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        mode="isolated-test",
        run_id=RUN_ID,
        candidate_sha256=CANDIDATE,
        run_manifest_sha256=RUN_MANIFEST,
        prerequisite_marker_sha256=PREREQUISITE,
        rotation_id=ROTATION_ID,
        rotation_manifest_sha256=ROTATION_MANIFEST,
        transaction_marker_sha256=ACTIVE,
        start_monotonic_ms=1000,
        now_monotonic_ms=1900,
    )


def slots(*next_observers: str) -> dict[str, str]:
    selected = set(next_observers)
    return {
        observer: "next" if observer in selected else "current"
        for observer in gate.OBSERVERS
    }


def common(
    observed: int,
    slot_matrix: dict[str, str],
    service: tuple[int, int, int],
    sessions: tuple[int, int],
    direct: tuple[int, int],
    records: int,
) -> dict[str, object]:
    return {
        "observed_monotonic_ms": observed,
        "slots": slot_matrix,
        "service_invocations": dict(zip(gate.COMPONENTS, service)),
        "control_sessions": dict(zip(gate.EDGES, sessions)),
        "direct_instances": dict(zip(gate.EDGES, direct)),
        "direct_healthy": True,
        "stream_records": {"a-to-b": records, "b-to-a": records + 1},
    }


def activation(
    component: str,
    observed: int,
    slot_matrix: dict[str, str],
    service: tuple[int, int, int],
    sessions: tuple[int, int],
    direct: tuple[int, int],
    records: int,
) -> dict[str, object]:
    value = common(observed, slot_matrix, service, sessions, direct, records)
    value.update(
        {
            "component": component,
            "active_marker_sha256": ACTIVE,
            "selected_instance_binding_verified": True,
            "max_outage_ms": 900,
            "sequence_errors": 0,
            "duplicate_records": 0,
            "start_limit_lockouts": 0,
            "digest_ok": True,
        }
    )
    return value


def transcript() -> dict[str, object]:
    relay_next = set(gate.ACTIVATION_NEW_OBSERVERS["relay"])
    edge_a_next = relay_next | set(gate.ACTIVATION_NEW_OBSERVERS["edge-a"])
    all_next = edge_a_next | set(gate.ACTIVATION_NEW_OBSERVERS["edge-b"])
    baseline = common(1100, slots(), (1, 1, 1), (10, 10), (20, 20), 100)
    overlap = common(1200, slots(), (1, 1, 1), (10, 10), (20, 20), 200)
    overlap["authorized_current_and_next"] = list(gate.IDENTITIES)
    retired = common(1600, slots(), (3, 3, 3), (14, 14), (24, 24), 1500)
    retired.update(
        {
            "max_outage_ms": 1200,
            "sequence_errors": 0,
            "duplicate_records": 0,
            "start_limit_lockouts": 0,
            "digest_ok": True,
            "selected_instance_binding_verified": True,
            "old_authorized": False,
            "next_promoted": True,
            "old_pin_rejections": list(gate.IDENTITIES),
            "next_pin_acceptances": list(gate.IDENTITIES),
        }
    )
    authorities = {}
    for index, authority in enumerate(gate.EXPIRY_AUTHORITIES):
        authorities[authority] = {
            "status_expiry_visible": True,
            "closed_by_cutoff": True,
            "expired_reconnect_rejected": True,
            "inside_margin_rejected": True,
            "next_restored": True,
            "cutoff_overrun_ms": 20 + index,
            "outage_ms": 400 + index,
        }
    rollback = {
        "triggered": True,
        "bounded_ms": 500,
        "credential_state_verified": True,
        "authorization_state_verified": True,
        "service_state_verified": True,
        "direct_health_verified": True,
        "stream_resumed": True,
        "old_authorized": True,
        "next_authorized": True,
    }
    post_rollback = dict(rollback)
    post_rollback["old_authorized"] = False
    return {
        "format": 1,
        "mode": "isolated-test",
        "run_id": RUN_ID,
        "candidate_sha256": CANDIDATE,
        "run_manifest_sha256": RUN_MANIFEST,
        "prerequisite_marker_sha256": PREREQUISITE,
        "rotation_id": ROTATION_ID,
        "rotation_manifest_sha256": ROTATION_MANIFEST,
        "transaction_marker_sha256": ACTIVE,
        "start_monotonic_ms": 1000,
        "complete_monotonic_ms": 1800,
        "baseline": baseline,
        "overlap": overlap,
        "activations": [
            activation("relay", 1300, slots(*relay_next), (2, 1, 1), (11, 11), (20, 20), 400),
            activation("edge-a", 1400, slots(*edge_a_next), (2, 2, 1), (12, 11), (21, 21), 600),
            activation("edge-b", 1500, slots(*all_next), (2, 2, 2), (12, 12), (22, 22), 800),
        ],
        "retired": retired,
        "expiry": {"observed_monotonic_ms": 1700, "authorities": authorities},
        "rollback_drills": {
            "pre-retirement": rollback,
            "post-retirement": post_rollback,
        },
    }


def rotation_manifest() -> dict[str, object]:
    counter = 1

    def next_hash() -> str:
        nonlocal counter
        value = f"{counter:064x}"
        counter += 1
        return value

    states: dict[str, dict[str, str]] = {
        "pre": {artifact: next_hash() for artifact in gate.ROTATION_ARTIFACTS}
    }
    for prior, current in zip(gate.ROTATION_STATES, gate.ROTATION_STATES[1:]):
        row = dict(states[prior])
        for artifact in gate.ROTATION_CHANGE_SETS[(prior, current)]:
            row[artifact] = next_hash()
        states[current] = row

    assignments = {}
    for index, identity_name in enumerate(gate.IDENTITIES, start=1):
        assignments[identity_name] = {
            "current": "sha256/" + base64.b64encode(bytes([index]) * 32).decode("ascii"),
            "next": "sha256/" + base64.b64encode(bytes([index + 16]) * 32).decode("ascii"),
        }
    return {
        "format": 1,
        "manifest_id": "a" * 32,
        "artifacts": list(gate.ROTATION_ARTIFACTS),
        "identity_assignments": assignments,
        "states": states,
    }


class StableCandidateManifestTests(unittest.TestCase):
    def test_every_complete_state_row_and_snapshot_passes(self):
        states = gate.validate_rotation_manifest(rotation_manifest())
        for state_name in gate.ROTATION_STATES:
            gate.validate_artifact_snapshot(states, state_name, dict(states[state_name]))

    def test_cross_state_artifact_splicing_is_rejected(self):
        states = gate.validate_rotation_manifest(rotation_manifest())
        snapshot = dict(states["edge-a-next"])
        snapshot["edge-b.control-key"] = states["edge-b-next"]["edge-b.control-key"]
        with self.assertRaisesRegex(gate.GateError, "mixes or alters"):
            gate.validate_artifact_snapshot(states, "edge-a-next", snapshot)

    def test_transition_change_sets_are_exact(self):
        value = rotation_manifest()
        value["states"]["relay-next"]["edge-a.control-key"] = "f" * 64
        with self.assertRaisesRegex(gate.GateError, "artifact transition"):
            gate.validate_rotation_manifest(value)
        value = rotation_manifest()
        value["states"]["post"]["relay.config"] = value["states"]["retiring"]["relay.config"]
        with self.assertRaisesRegex(gate.GateError, "artifact transition"):
            gate.validate_rotation_manifest(value)

    def test_manifest_schema_and_all_ten_public_pins_are_unique(self):
        value = rotation_manifest()
        value["states"]["pre"]["extra.key"] = "f" * 64
        with self.assertRaisesRegex(gate.GateError, "pre state schema"):
            gate.validate_rotation_manifest(value)
        value = rotation_manifest()
        value["identity_assignments"]["site-b-data"]["next"] = (
            value["identity_assignments"]["site-a-data"]["next"]
        )
        with self.assertRaisesRegex(gate.GateError, "reused"):
            gate.validate_rotation_manifest(value)
        value = rotation_manifest()
        value["states"]["pre"]["edge-b.data-key"] = value["states"]["pre"]["edge-a.data-key"]
        with self.assertRaisesRegex(gate.GateError, "reuses a credential"):
            gate.validate_rotation_manifest(value)


class RotationTranscriptTests(unittest.TestCase):
    def validate(self, value: dict[str, object]) -> dict[str, str]:
        return gate.validate_transcript(value, expected())

    def rejected(self, value: dict[str, object], message: str) -> None:
        with self.assertRaisesRegex(gate.GateError, message):
            self.validate(value)

    def test_exact_happy_path_marker_is_sanitized(self):
        marker = self.validate(transcript())
        self.assertEqual(tuple(marker), gate.PASS_MARKER_KEYS)
        self.assertEqual(marker["CURRENT_NEXT_OVERLAP_CHECKS"], "5")
        self.assertEqual(marker["NEXT_SLOT_OBSERVATIONS"], "11")
        self.assertEqual(marker["CONTROL_RECONNECTS"], "8")
        self.assertEqual(marker["DIRECT_RECONNECTS"], "4")
        self.assertEqual(marker["ROLLBACK_RESTORES"], "2")
        serialized = "\n".join(f"{key}={value}" for key, value in marker.items()).lower()
        for forbidden in ("private key", "begin certificate", "spki/", ".key", "address", "token"):
            self.assertNotIn(forbidden, serialized)

    def test_baseline_next_slot_is_rejected(self):
        value = transcript()
        value["baseline"]["slots"][gate.OBSERVERS[0]] = "next"
        self.rejected(value, "before activation")

    def test_overlap_must_cover_every_identity_without_restart(self):
        value = transcript()
        value["overlap"]["authorized_current_and_next"].pop()
        self.rejected(value, "overlap identities")
        value = transcript()
        value["overlap"]["service_invocations"]["relay"] += 1
        self.rejected(value, "disturbed a live session")

    def test_active_transaction_binding_and_window_are_exact(self):
        value = transcript()
        value["activations"][0]["active_marker_sha256"] = "8" * 64
        self.rejected(value, "binding")
        value = transcript()
        value["complete_monotonic_ms"] = 1000 + gate.MAX_TRANSACTION_MS + 1
        expected_value = expected()
        expected_value.now_monotonic_ms = value["complete_monotonic_ms"]
        with self.assertRaisesRegex(gate.GateError, "duration"):
            gate.validate_transcript(value, expected_value)

    def test_every_next_observer_and_order_is_required(self):
        value = transcript()
        del value["activations"][1]["slots"]["edge-b.peer-data"]
        self.rejected(value, "slots.*schema")
        value = transcript()
        value["activations"][1]["slots"]["edge-b.local-data"] = "next"
        self.rejected(value, "slot matrix")
        value = transcript()
        value["activations"][1], value["activations"][2] = (
            value["activations"][2], value["activations"][1]
        )
        self.rejected(value, "binding")

    def test_mixed_service_and_connection_state_is_rejected(self):
        value = transcript()
        value["activations"][1]["service_invocations"]["edge-a"] -= 1
        self.rejected(value, "reload")
        value = transcript()
        value["activations"][2]["direct_instances"]["edge-b"] -= 1
        self.rejected(value, "direct")
        value = transcript()
        value["retired"]["control_sessions"]["edge-a"] -= 1
        self.rejected(value, "control reconnects")

    def test_stream_loss_duplication_and_outage_are_rejected(self):
        value = transcript()
        value["activations"][0]["stream_records"]["a-to-b"] = 200
        self.rejected(value, "did not advance")
        value = transcript()
        value["activations"][1]["duplicate_records"] = 1
        self.rejected(value, "duplicated")
        value = transcript()
        value["retired"]["max_outage_ms"] = gate.MAX_OUTAGE_MS + 1
        self.rejected(value, "outage")

    def test_retirement_promotes_next_and_rejects_every_old_pin(self):
        value = transcript()
        value["retired"]["slots"][gate.OBSERVERS[0]] = "next"
        self.rejected(value, "promoted")
        value = transcript()
        value["retired"]["old_authorized"] = True
        self.rejected(value, "remained")
        value = transcript()
        value["retired"]["old_pin_rejections"][0] = gate.IDENTITIES[1]
        self.rejected(value, "old-pin rejections")

    def test_expiry_visibility_reconnect_margin_and_cutoff_are_required(self):
        value = transcript()
        value["expiry"]["authorities"]["direct-data"]["status_expiry_visible"] = False
        self.rejected(value, "status_expiry_visible")
        value = transcript()
        value["expiry"]["authorities"]["edge-control"]["inside_margin_rejected"] = False
        self.rejected(value, "inside_margin_rejected")
        value = transcript()
        value["expiry"]["authorities"]["relay-listener"]["cutoff_overrun_ms"] = 251
        self.rejected(value, "cutoff overrun")

    def test_both_safe_rollback_floors_are_required(self):
        value = transcript()
        value["rollback_drills"]["post-retirement"]["old_authorized"] = True
        self.rejected(value, "unsafe authorization floor")
        value = transcript()
        value["rollback_drills"]["pre-retirement"]["stream_resumed"] = False
        self.rejected(value, "stream_resumed")
        value = transcript()
        del value["rollback_drills"]["post-retirement"]
        self.rejected(value, "rollback drills.*schema")

    def test_schema_rejects_secret_bearing_or_unrecognized_evidence(self):
        value = transcript()
        value["private_key"] = "not evidence"
        self.rejected(value, "root schema")
        value = transcript()
        value["retired"]["spki_pin"] = "sha256/not-evidence"
        self.rejected(value, "retirement schema")


class RollbackMarkerTests(unittest.TestCase):
    def marker(self) -> dict[str, object]:
        return {
            "format": 1,
            "status": "pass",
            "gate": "certificate-rotation-rollback",
            "mode": "isolated-test",
            "run_id": RUN_ID,
            "candidate_sha256": CANDIDATE,
            "rotation_id": ROTATION_ID,
            "rotation_manifest_sha256": ROTATION_MANIFEST,
            "transaction_marker_sha256": ACTIVE,
            "rollback_floor": "next-only",
            "selected_state": "post",
            "complete_monotonic_ms": 1800,
            "credential_state_verified": True,
            "authorization_state_verified": True,
            "service_state_verified": True,
            "direct_health_verified": True,
            "old_authorized": False,
            "next_authorized": True,
        }

    def rollback_expected(self) -> types.SimpleNamespace:
        value = expected()
        value.rollback_floor = "next-only"
        return value

    def test_exact_rollback_marker_passes(self):
        gate.validate_rollback(self.marker(), self.rollback_expected())

    def test_unbound_or_partial_rollback_is_rejected(self):
        value = self.marker()
        value["rotation_manifest_sha256"] = "9" * 64
        with self.assertRaisesRegex(gate.GateError, "binding"):
            gate.validate_rollback(value, self.rollback_expected())
        value = self.marker()
        value["authorization_state_verified"] = False
        with self.assertRaisesRegex(gate.GateError, "not proved"):
            gate.validate_rollback(value, self.rollback_expected())
        value = self.marker()
        value["old_authorized"] = True
        with self.assertRaisesRegex(gate.GateError, "unsafe"):
            gate.validate_rollback(value, self.rollback_expected())


class RotationShellContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "scripts" / "certificate-rotation-gate.sh").read_text(
            encoding="utf-8"
        )
        cls.unit = (ROOT / "systemd" / "campus-link-certificate-rotation.service").read_text(
            encoding="utf-8"
        )

    def test_production_paths_cannot_be_overridden(self):
        self.assertIn("Production rotation forbids executable or evidence-helper overrides", self.source)
        self.assertIn("DRIVER=/usr/local/libexec/campus-link-certificate-rotation-driver", self.source)
        self.assertIn("VALIDATOR=/usr/local/libexec/campus-link-certificate-rotation-validate.py", self.source)
        self.assertIn('validate-manifest --mode "${MODE}"', self.source)

    def test_live_and_rollback_work_are_bounded_and_fail_closed(self):
        self.assertIn("--kill-after=10s 1800s", self.source)
        self.assertIn("--kill-after=10s 120s \"${DRIVER}\" rollback", self.source)
        self.assertIn("rollback_verified", self.source)
        self.assertIn("exit 70", self.source)
        self.assertIn("validate_stage_marker pre", self.source)
        self.assertIn("validate_stage_marker post", self.source)
        self.assertIn("validate_stage_marker()", self.source)
        self.assertGreaterEqual(self.source.count("rotation_manifest_sha256"), 10)
        self.assertIn("retiring|post|expiry|complete|*) rollback_floor=next-only", self.source)
        self.assertIn('rm -f -- "${RESULT}"', self.source)
        self.assertLess(
            self.source.index('mv -fT -- "${ACTIVE}" "${CLOSED}"'),
            self.source.index("transaction_succeeded=1"),
        )
        self.assertIn('transaction_marker_path=${CLOSED}', self.source)
        failure_schema = self.source[
            self.source.index("write_failure_marker()") : self.source.index("validate_stage_marker()")
        ].lower()
        for forbidden in ("private key", "begin certificate", "spki/", ".key", "address", "token"):
            self.assertNotIn(forbidden, failure_schema)

    def test_unit_is_bounded_and_cannot_change_clock_or_home(self):
        self.assertIn("TimeoutStartSec=35m", self.unit)
        self.assertIn("TimeoutStopSec=150s", self.unit)
        self.assertIn("ProtectClock=true", self.unit)
        self.assertIn("ProtectHome=true", self.unit)
        self.assertIn("ProtectSystem=strict", self.unit)
        self.assertIn("AssertPathExists=/var/lib/campus-link/rotation/manifest.json", self.unit)


if __name__ == "__main__":
    unittest.main()
