import contextlib
import copy
import datetime
import io
import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import status_gate


def certificate(
    slot="current", *, remaining=datetime.timedelta(hours=1), expires=None,
):
    return {
        "expires": expires or (
            datetime.datetime.now(datetime.timezone.utc) + remaining
        ).isoformat().replace("+00:00", "Z"),
        "pin_slot": slot,
    }


def edge(
    *, direct_sent=0, direct_received=0, progress=0, relay_sent=0,
    relay_received=0, queue_drops=0, invalid_packets=0, duplicate_packets=0, dropped=0,
    watchdog=0, fallbacks=0, control_session=1,
    telemetry_sequence=1, raw_a=0, raw_b=0, raw_a_bytes=None, raw_b_bytes=None,
    relay_dropped=0, relay_dropped_bytes=0, site="site-a",
    status_generation=1, selected_path_transitions=0, identity_transitions=0,
):
    if raw_a_bytes is None:
        raw_a_bytes = raw_a * 64
    if raw_b_bytes is None:
        raw_b_bytes = raw_b * 64
    return {
        "site": site,
        "updated": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "status_generation": status_generation,
        "selected_path_transitions": selected_path_transitions,
        "identity_transitions": identity_transitions,
        "clock": {
            "synchronized": True,
            "absolute_offset_millis": 10,
            "uncertainty_millis": 20,
        },
        "control_identity": {
            "local": certificate(), "peer": certificate(),
        },
        "data_identity": {
            "local": certificate(), "peer": certificate(),
            "path": "direct", "direct_epoch": 1,
        },
        "relay_telemetry": {
            "control_session": control_session,
            "sequence": telemetry_sequence,
            "forwarded_packets": {"site-a": raw_a, "site-b": raw_b},
            "forwarded_bytes": {"site-a": raw_a_bytes, "site-b": raw_b_bytes},
            "dropped_packets": relay_dropped,
            "dropped_bytes": relay_dropped_bytes,
        },
        "path": {
            "selected": "direct",
            "direct_required": True,
            "direct_healthy": True,
            "direct_epoch": 1,
            "direct_instance": 1,
            "relay_sent_packets": relay_sent,
            "relay_received_packets": relay_received,
            "queue_drops": queue_drops,
            "invalid_packets": invalid_packets,
            "duplicate_packets": duplicate_packets,
            "direct_sent_packets": direct_sent,
            "direct_received_packets": direct_received,
            "direct_progress_acknowledgements": progress,
            "direct_watchdog_failures": watchdog,
            "fallbacks": fallbacks,
        },
        "dropped_packets": dropped,
    }


class StatusGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity_expiry = (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        ).isoformat().replace("+00:00", "Z")
        self.site_identity = mock.patch.object(
            status_gate, "_site_identity", return_value=(os.geteuid(), os.getegid())
            if os.name == "posix" else None,
        )
        self.site_identity.start()

    def tearDown(self):
        self.site_identity.stop()
        self.temporary.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        if os.name == "posix":
            path.chmod(0o640)
        return path

    def snapshot(self, monotonic_ns, amount, raw, raw_bytes=None):
        if raw_bytes is None:
            raw_bytes = raw * 64
        expiry = datetime.datetime.fromisoformat(
            self.identity_expiry[:-1] + "+00:00"
        )

        def identity(offset):
            return certificate(expires=(
                expiry + datetime.timedelta(seconds=offset)
            ).isoformat().replace("+00:00", "Z"))

        edge_state = {
            "status_generation": max(1, monotonic_ns // 1_000_000_000),
            "selected_path_transitions": 7,
            "identity_transitions": 11,
            "selected": "direct", "direct_required": True, "direct_healthy": True,
            "direct_epoch": 1,
            "direct_instance": 1,
            "relay_sent": 0, "relay_received": 0, "direct_sent": amount,
            "direct_received": amount,
            "direct_progress": amount, "watchdog_failures": 0, "fallbacks": 0,
            "queue_drops": 0, "dropped": 0,
            "invalid_packets": 0, "duplicate_packets": 0,
            "telemetry_sequence": amount + 1,
            "control_session": 1,
            "relay_forwarded": {"site-a": raw, "site-b": raw},
            "relay_forwarded_bytes": {"site-a": raw_bytes, "site-b": raw_bytes},
            "relay_dropped": 0,
            "relay_dropped_bytes": 0,
            "clock": {
                "synchronized": True,
                "absolute_offset_millis": 10,
                "uncertainty_millis": 20,
            },
            "control_identity": {
                "local": certificate(expires=self.identity_expiry),
                "peer": certificate(expires=self.identity_expiry),
            },
            "data_identity": {
                "local": certificate(expires=self.identity_expiry),
                "peer": certificate(expires=self.identity_expiry),
                "path": "direct", "direct_epoch": 1,
            },
        }
        edge_a = copy.deepcopy(edge_state)
        edge_b = copy.deepcopy(edge_state)
        edge_a["control_session"] = 1
        edge_b["control_session"] = 2
        edge_a["direct_instance"] = 101
        edge_b["direct_instance"] = 102
        relay_control = identity(1)
        edge_a["control_identity"] = {
            "local": identity(2), "peer": copy.deepcopy(relay_control),
        }
        edge_b["control_identity"] = {
            "local": identity(3), "peer": copy.deepcopy(relay_control),
        }
        site_a_data, site_b_data = identity(4), identity(5)
        edge_a["data_identity"] = {
            "local": copy.deepcopy(site_a_data), "peer": copy.deepcopy(site_b_data),
            "path": "direct", "direct_epoch": 1,
        }
        edge_b["data_identity"] = {
            "local": copy.deepcopy(site_b_data), "peer": copy.deepcopy(site_a_data),
            "path": "direct", "direct_epoch": 1,
        }
        return {
            "format": 1, "boot_id_sha256": "a" * 64, "monotonic_ns": monotonic_ns,
            "edge_a": edge_a, "edge_b": edge_b,
        }

    def raw_from_snapshot(self, item, site):
        return {
            "site": site,
            "updated": datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
                "+00:00", "Z"
            ),
            "status_generation": item["status_generation"],
            "selected_path_transitions": item["selected_path_transitions"],
            "identity_transitions": item["identity_transitions"],
            "clock": copy.deepcopy(item["clock"]),
            "control": "authenticated",
            "udp": "bound",
            "control_identity": copy.deepcopy(item["control_identity"]),
            "data_identity": copy.deepcopy(item["data_identity"]),
            "relay_telemetry": {
                "control_session": item["control_session"],
                "sequence": item["telemetry_sequence"],
                "forwarded_packets": copy.deepcopy(item["relay_forwarded"]),
                "forwarded_bytes": copy.deepcopy(item["relay_forwarded_bytes"]),
                "dropped_packets": item["relay_dropped"],
                "dropped_bytes": item["relay_dropped_bytes"],
            },
            "path": {
                "selected": item["selected"],
                "direct_required": item["direct_required"],
                "direct_healthy": item["direct_healthy"],
                "direct_epoch": item["direct_epoch"],
                "direct_instance": item["direct_instance"],
                "relay_sent_packets": item["relay_sent"],
                "relay_received_packets": item["relay_received"],
                "queue_drops": item["queue_drops"],
                "invalid_packets": item["invalid_packets"],
                "duplicate_packets": item["duplicate_packets"],
                "direct_sent_packets": item["direct_sent"],
                "direct_received_packets": item["direct_received"],
                "direct_progress_acknowledgements": item["direct_progress"],
                "direct_watchdog_failures": item["watchdog_failures"],
                "fallbacks": item["fallbacks"],
            },
            "dropped_packets": item["dropped"],
        }

    @mock.patch.object(status_gate, "_boot_id_sha256", return_value="a" * 64)
    def test_capture_and_verify_sanitized_direct_evidence(self, _boot_id):
        a = self.write("a.json", edge(direct_sent=3, direct_received=4, progress=2))
        b = self.write("b.json", edge(site="site-b", direct_sent=4, direct_received=3, progress=2))
        captured = status_gate.capture(a, b)
        self.assertEqual(captured["edge_a"]["direct_sent"], 3)
        before = self.snapshot(1_000_000_000, 10, 20)
        after = self.snapshot(3_000_000_000, 30, 25)
        evidence = status_gate.verify(before, after, 20, 1.0)
        self.assertEqual(evidence["EDGE_A_DIRECT_SENT_DELTA"], 20)
        self.assertEqual(evidence["RAW_RELAY_PACKET_LIMIT_PER_SITE"], 34)
        self.assertEqual(evidence["RAW_RELAY_BYTE_LIMIT_PER_SITE"], 65_536 + 2 * 64)
        self.assertEqual(tuple(sorted(evidence)), status_gate.EVIDENCE_KEYS)
        self.assertEqual(len(evidence), 29)
        self.assertNotIn("address", " ".join(evidence).lower())

    @mock.patch.object(status_gate, "_boot_id_sha256", return_value="a" * 64)
    def test_capture_binds_exact_sites_to_distinct_opened_files(self, _boot_id):
        a = self.write("site-a.json", edge(site="site-a"))
        b = self.write("site-b.json", edge(site="site-b"))
        with self.assertRaisesRegex(status_gate.GateError, "same opened file"):
            status_gate.capture(a, a)
        with self.assertRaisesRegex(status_gate.GateError, "expected site-a"):
            status_gate.capture(b, a)

    def test_data_identity_is_bound_to_selected_path_and_direct_epoch(self):
        wrong_path = edge()
        wrong_path["data_identity"]["path"] = "relay"
        wrong_path["data_identity"]["direct_epoch"] = 0
        with self.assertRaisesRegex(status_gate.GateError, "selected path"):
            status_gate._edge(self.write("wrong-data-path.json", wrong_path), "site-a")

        wrong_epoch = edge()
        wrong_epoch["data_identity"]["direct_epoch"] = 2
        with self.assertRaisesRegex(status_gate.GateError, "direct epoch"):
            status_gate._edge(self.write("wrong-data-epoch.json", wrong_epoch), "site-a")

        extra_field = edge()
        extra_field["data_identity"]["unbound"] = "candidate"
        with self.assertRaisesRegex(status_gate.GateError, "absent or malformed"):
            status_gate._edge(self.write("extra-data-field.json", extra_field), "site-a")

    def test_cross_edge_direct_epoch_split_brain_is_rejected(self):
        snapshot = self.snapshot(1_000_000_000, 10, 20)
        snapshot["edge_b"]["direct_epoch"] = 2
        snapshot["edge_b"]["data_identity"]["direct_epoch"] = 2
        with self.assertRaisesRegex(status_gate.GateError, "different path epochs"):
            status_gate._validate_snapshot(snapshot)

        edge_a = self.raw_from_snapshot(snapshot["edge_a"], "site-a")
        edge_b = self.raw_from_snapshot(snapshot["edge_b"], "site-b")
        with self.assertRaisesRegex(status_gate.GateError, "different path epochs"):
            status_gate._edge_pair(
                self.write("split-a.json", edge_a), self.write("split-b.json", edge_b)
            )

    def test_authenticated_clock_status_is_exact_and_bounded(self):
        missing = edge()
        del missing["clock"]
        with self.assertRaisesRegex(status_gate.GateError, "clock status"):
            status_gate._edge(self.write("missing-clock.json", missing), "site-a")

        extra = edge()
        extra["clock"]["raw_sample"] = 1
        with self.assertRaisesRegex(status_gate.GateError, "clock status"):
            status_gate._edge(self.write("extra-clock.json", extra), "site-a")

        wrong_type = edge()
        wrong_type["clock"]["synchronized"] = 1
        with self.assertRaisesRegex(status_gate.GateError, "synchronization state"):
            status_gate._edge(self.write("clock-bool.json", wrong_type), "site-a")

        outside = edge()
        outside["clock"]["absolute_offset_millis"] = 800
        outside["clock"]["uncertainty_millis"] = 201
        with self.assertRaisesRegex(status_gate.GateError, "exceeds one second"):
            status_gate._edge(self.write("clock-outside.json", outside), "site-a")

        unsynchronized = edge()
        unsynchronized["clock"] = {
            "synchronized": False,
            "absolute_offset_millis": 0,
            "uncertainty_millis": 0,
        }
        with self.assertRaisesRegex(status_gate.GateError, "not synchronized"):
            status_gate._edge(self.write("clock-unsynchronized.json", unsynchronized), "site-a")

        stale_bound = copy.deepcopy(unsynchronized)
        stale_bound["clock"]["uncertainty_millis"] = 1
        with self.assertRaisesRegex(status_gate.GateError, "stale bound"):
            status_gate._clock_status(stale_bound, require_synchronized=None)

    def test_python_and_shell_use_the_same_exact_evidence_schema(self):
        helper = (Path(__file__).parents[1] / "scripts" / "gate-evidence.sh").read_text(
            encoding="utf-8"
        )
        match = re.search(
            r"readonly -a CAMPUS_LINK_DIRECT_EVIDENCE_KEYS=\(\n(.*?)^\)",
            helper,
            re.M | re.S,
        )
        self.assertIsNotNone(match)
        shell_keys = tuple(line.strip() for line in match.group(1).splitlines())
        self.assertEqual(shell_keys, status_gate.EVIDENCE_KEYS)
        match = re.search(
            r"readonly -a CAMPUS_LINK_FAULT_EVIDENCE_KEYS=\(\n(.*?)^\)",
            helper,
            re.M | re.S,
        )
        self.assertIsNotNone(match)
        shell_keys = tuple(line.strip() for line in match.group(1).splitlines())
        self.assertEqual(shell_keys, status_gate.FAULT_EVIDENCE_KEYS)

    def test_fault_stream_transition_evidence_is_direct_only_and_exact(self):
        before = self.snapshot(1_000_000_000, 10, 20)
        relay = self.snapshot(2_000_000_000, 30, 22)
        direct = self.snapshot(3_000_000_000, 60, 24)
        for label, session in (("edge_a", 11), ("edge_b", 12)):
            relay[label]["control_session"] = session
            direct[label]["control_session"] = session
            direct[label]["direct_instance"] += 100
            direct[label]["watchdog_failures"] = 1
        evidence = status_gate.verify_fault_stream(
            before, relay, direct, 50, 10.0,
        )
        self.assertEqual(evidence["FAULT_RELAY_CONTROL_SESSION_TRANSITIONS"], 2)
        self.assertEqual(evidence["FAULT_REESTABLISHED_DIRECT_PATHS"], 2)
        self.assertEqual(evidence["FAULT_EDGE_A_RELAY_SENT_DELTA"], 0)
        self.assertEqual(evidence["FAULT_EDGE_A_RELAY_RECEIVED_DELTA"], 0)
        self.assertEqual(evidence["FAULT_EDGE_A_QUEUE_DROPS_DELTA"], 0)
        self.assertEqual(evidence["FAULT_EDGE_A_INVALID_PACKETS_DELTA"], 0)
        self.assertEqual(evidence["FAULT_EDGE_A_DUPLICATE_PACKETS_DELTA"], 0)
        self.assertEqual(evidence["FAULT_EDGE_A_DROPPED_DELTA"], 0)
        self.assertEqual(tuple(sorted(evidence)), status_gate.FAULT_EVIDENCE_KEYS)

    def test_fault_stream_rejects_relay_bytes_identity_swap_and_missing_withdrawal(self):
        before = self.snapshot(1_000_000_000, 10, 20)
        relay = self.snapshot(2_000_000_000, 30, 22)
        direct = self.snapshot(3_000_000_000, 60, 24)
        for label, session in (("edge_a", 11), ("edge_b", 12)):
            relay[label]["control_session"] = session
            direct[label]["control_session"] = session
            direct[label]["direct_instance"] += 100
            direct[label]["watchdog_failures"] = 1

        relayed = copy.deepcopy(direct)
        relayed["edge_a"]["relay_received"] = 1
        with self.assertRaisesRegex(status_gate.GateError, "relay_received"):
            status_gate.verify_fault_stream(before, relay, relayed, 1, 10.0)

        hidden_bulk = self.snapshot(3_000_000_000, 60, 54)
        for label, session in (("edge_a", 11), ("edge_b", 12)):
            hidden_bulk[label]["control_session"] = session
            hidden_bulk[label]["direct_instance"] += 100
            hidden_bulk[label]["watchdog_failures"] = 1
        hidden_bulk["edge_a"]["relay_forwarded_bytes"]["site-a"] = (
            before["edge_a"]["relay_forwarded_bytes"]["site-a"]
            + (34 * status_gate.MAX_OUTER_RELAY_DATAGRAM_BYTES)
        )
        with self.assertRaisesRegex(status_gate.GateError, "keepalive bound"):
            status_gate.verify_fault_stream(before, relay, hidden_bulk, 1, 1.0)

        for counter in ("queue_drops", "invalid_packets", "duplicate_packets", "dropped"):
            lossy = copy.deepcopy(direct)
            lossy["edge_a"][counter] = 1
            with self.subTest(counter=counter), self.assertRaisesRegex(
                status_gate.GateError, counter,
            ):
                status_gate.verify_fault_stream(before, relay, lossy, 1, 10.0)

        swapped = copy.deepcopy(direct)
        swapped["edge_b"]["data_identity"]["peer"] = copy.deepcopy(
            swapped["edge_b"]["data_identity"]["local"]
        )
        with self.assertRaisesRegex(status_gate.GateError, "data identity"):
            status_gate.verify_fault_stream(before, relay, swapped, 1, 10.0)

        no_watchdog = copy.deepcopy(direct)
        no_watchdog["edge_a"]["watchdog_failures"] = 0
        with self.assertRaisesRegex(status_gate.GateError, "watchdog"):
            status_gate.verify_fault_stream(before, relay, no_watchdog, 1, 10.0)

        reused_instance = copy.deepcopy(direct)
        reused_instance["edge_a"]["direct_instance"] = relay["edge_a"]["direct_instance"]
        with self.assertRaisesRegex(status_gate.GateError, "direct instance"):
            status_gate.verify_fault_stream(before, relay, reused_instance, 1, 10.0)

        regressed_instance = copy.deepcopy(direct)
        regressed_instance["edge_b"]["direct_instance"] = 1
        with self.assertRaisesRegex(status_gate.GateError, "direct instance"):
            status_gate.verify_fault_stream(before, relay, regressed_instance, 1, 10.0)

        fallback_enabled = copy.deepcopy(direct)
        fallback_enabled["edge_a"]["direct_required"] = False
        with self.assertRaises(status_gate.GateError):
            status_gate.verify_fault_stream(before, relay, fallback_enabled, 1, 10.0)

    def test_fault_waiters_observe_control_and_direct_withdrawal_states(self):
        before = self.snapshot(1_000_000_000, 10, 20)
        relay = self.snapshot(2_000_000_000, 30, 22)
        for label, session in (("edge_a", 11), ("edge_b", 12)):
            relay[label]["control_session"] = session

        paths = {}
        for label, site in (("edge_a", "site-a"), ("edge_b", "site-b")):
            status = self.raw_from_snapshot(before[label], site)
            status["control"] = "reconnecting"
            status["relay_telemetry"] = None
            status["clock"] = {
                "synchronized": False,
                "absolute_offset_millis": 0,
                "uncertainty_millis": 0,
            }
            status["control_identity"] = {
                "local": copy.deepcopy(before[label]["control_identity"]["local"]),
            }
            paths[label] = self.write(f"{label}-outage.json", status)
        status_gate.wait_control_outage(
            paths["edge_a"], paths["edge_b"], before, 0.1,
        )

        for label, site in (("edge_a", "site-a"), ("edge_b", "site-b")):
            paths[label].write_text(
                json.dumps(self.raw_from_snapshot(relay[label], site)), encoding="utf-8",
            )
        status_gate.wait_control_reconnected(
            paths["edge_a"], paths["edge_b"], before, 0.1,
        )

        for label, site in (("edge_a", "site-a"), ("edge_b", "site-b")):
            status = self.raw_from_snapshot(relay[label], site)
            status["path"]["selected"] = "none"
            status["path"]["direct_healthy"] = False
            status["path"]["direct_epoch"] = 0
            status["path"]["direct_instance"] = 0
            status["data_identity"] = {
                "local": copy.deepcopy(relay[label]["data_identity"]["local"]),
                "path": "none", "direct_epoch": 0,
            }
            paths[label].write_text(json.dumps(status), encoding="utf-8")
        status_gate.wait_direct_outage(
            paths["edge_a"], paths["edge_b"], relay, 0.1,
        )

    def test_qualification_never_trusts_a_local_relay_status_file(self):
        qualification = (
            Path(__file__).parents[1] / "scripts" / "qualify-a11-b22.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn("/run/campus-link/status.json", qualification)
        self.assertNotIn("--relay", qualification)
        self.assertIn("wait-telemetry", qualification)

    def test_full_qualification_pins_edge_processes_around_evidence(self):
        qualification = (
            Path(__file__).parents[1] / "scripts" / "qualify-a11-b22.sh"
        ).read_text(encoding="utf-8")
        for service in ("campus-link-edge-a.service", "campus-link-edge-b.service"):
            self.assertGreaterEqual(qualification.count(service), 3)
        capture_identity = qualification[
            qualification.index("capture_service_identity() {") :
            qualification.index("\n}\n", qualification.index("capture_service_identity() {") )
        ]
        unchanged_identity = qualification[
            qualification.index("assert_service_identity_unchanged() {") :
            qualification.index("\n}\n", qualification.index("assert_service_identity_unchanged() {") )
        ]
        self.assertGreaterEqual(capture_identity.count("NRestarts"), 2)
        self.assertGreaterEqual(capture_identity.count("InvocationID"), 2)
        self.assertGreaterEqual(unchanged_identity.count("NRestarts"), 2)
        self.assertGreaterEqual(unchanged_identity.count("InvocationID"), 2)
        before_capture = qualification.index('"${evidence_dir}/before.json"')
        after_capture = qualification.index('"${evidence_dir}/after.json"')
        self.assertLess(qualification.index("  capture_service_identity\n"), before_capture)
        self.assertIn("assert_service_identity_unchanged", qualification[before_capture:after_capture])
        self.assertIn("assert_service_identity_unchanged", qualification[after_capture:])

    def test_relay_data_watchdog_and_raw_growth_fail_closed(self):
        before = self.snapshot(1_000_000_000, 10, 20)
        for mutation in (
            "relay_sent", "relay_received", "queue_drops", "invalid_packets",
            "duplicate_packets", "dropped",
            "watchdog_failures", "fallbacks",
        ):
            after = self.snapshot(2_000_000_000, 20, 21)
            after["edge_a"][mutation] = 1
            with self.subTest(mutation=mutation), self.assertRaises(status_gate.GateError):
                status_gate.verify(before, after, 1, 10.0)
        after = self.snapshot(2_000_000_000, 20, 1000)
        with self.assertRaises(status_gate.GateError):
            status_gate.verify(before, after, 1, 10.0)
        hidden_bulk = self.snapshot(2_000_000_000, 20, 53)
        hidden_bulk["edge_a"]["relay_forwarded_bytes"]["site-a"] = (
            before["edge_a"]["relay_forwarded_bytes"]["site-a"]
            + (33 * status_gate.MAX_OUTER_RELAY_DATAGRAM_BYTES)
        )
        with self.assertRaisesRegex(status_gate.GateError, "keepalive bound"):
            status_gate.verify(before, hidden_bulk, 1, 1.0)

    def test_telemetry_session_sequence_regression_and_skew_fail_closed(self):
        before = self.snapshot(1_000_000_000, 10, 20)
        after = self.snapshot(2_000_000_000, 20, 21)
        after["edge_a"]["control_session"] += 1
        with self.assertRaisesRegex(status_gate.GateError, "session changed"):
            status_gate.verify(before, after, 1, 10.0)

        after = self.snapshot(2_000_000_000, 20, 21)
        after["edge_b"]["telemetry_sequence"] = before["edge_b"]["telemetry_sequence"]
        with self.assertRaisesRegex(status_gate.GateError, "did not advance"):
            status_gate.verify(before, after, 1, 10.0)

        after = self.snapshot(2_000_000_000, 20, 21)
        after["edge_a"]["relay_forwarded"]["site-a"] = 19
        with self.assertRaisesRegex(status_gate.GateError, "counter regressed"):
            status_gate.verify(before, after, 1, 10.0)

        after = self.snapshot(2_000_000_000, 20, 21)
        after["edge_a"]["relay_forwarded_bytes"]["site-a"] = (
            before["edge_a"]["relay_forwarded_bytes"]["site-a"] - 1
        )
        with self.assertRaisesRegex(status_gate.GateError, "counter regressed"):
            status_gate.verify(before, after, 1, 10.0)

        before = self.snapshot(1_000_000_000, 10, 10)
        before["edge_b"]["relay_forwarded"] = {"site-a": 12, "site-b": 13}
        before["edge_b"]["relay_forwarded_bytes"] = {"site-a": 700, "site-b": 800}
        after = self.snapshot(2_000_000_000, 20, 14)
        after["edge_b"]["relay_forwarded"] = {"site-a": 15, "site-b": 16}
        after["edge_b"]["relay_forwarded_bytes"] = {"site-a": 1000, "site-b": 1200}
        evidence = status_gate.verify(before, after, 1, 10.0)
        self.assertEqual(evidence["RAW_RELAY_SITE_A_DELTA"], 5)
        self.assertEqual(evidence["RAW_RELAY_SITE_B_DELTA"], 6)
        self.assertEqual(evidence["RAW_RELAY_SITE_A_BYTES_DELTA"], 360)
        self.assertEqual(evidence["RAW_RELAY_SITE_B_BYTES_DELTA"], 560)

    def test_soak_verifier_pins_the_full_interval_and_adjacent_sample(self):
        start = 1_000_000_000
        duration_ns = 7 * 24 * 60 * 60 * 1_000_000_000
        before = self.snapshot(start, 10, 20)
        previous = self.snapshot(start + duration_ns - 1_000_000_000, 1990, 80)
        after = self.snapshot(start + duration_ns, 2010, 81)
        evidence = status_gate.verify_soak(
            before,
            previous,
            after,
            1000,
            1.0,
            final=True,
            now_monotonic_ns=after["monotonic_ns"],
        )
        self.assertEqual(evidence["DIRECT_EVIDENCE_DURATION_MS"], 604800000)
        self.assertEqual(evidence["EDGE_A_RELAY_SENT_DELTA"], 0)
        self.assertEqual(evidence["RAW_RELAY_SITE_A_DELTA"], 61)

        # A non-final observation may precede the first telemetry/data update.
        unchanged = self.snapshot(start + 1_000_000_000, 10, 20)
        status_gate.verify_soak(
            before,
            before,
            unchanged,
            1000,
            1.0,
            final=False,
            now_monotonic_ns=unchanged["monotonic_ns"],
        )

    def test_soak_verifier_rejects_transient_regression_and_repeated_allowance(self):
        before = self.snapshot(1_000_000_000, 10, 0)
        previous = self.snapshot(2_000_000_000, 100, 32)

        regressed = self.snapshot(3_000_000_000, 50, 33)
        with self.assertRaisesRegex(status_gate.GateError, "between soak observations"):
            status_gate.verify_soak(
                before, previous, regressed, 1000, 1.0, final=False,
                now_monotonic_ns=regressed["monotonic_ns"],
            )

        repeated_setup_allowance = self.snapshot(3_000_000_000, 110, 64)
        with self.assertRaisesRegex(status_gate.GateError, "keepalive bound"):
            status_gate.verify_soak(
                before, previous, repeated_setup_allowance, 1000, 1.0,
                final=False,
                now_monotonic_ns=repeated_setup_allowance["monotonic_ns"],
            )

        replaced = self.snapshot(3_000_000_000, 110, 33)
        replaced["edge_a"]["direct_instance"] += 1
        with self.assertRaisesRegex(status_gate.GateError, "instance changed"):
            status_gate.verify_soak(
                before, previous, replaced, 1000, 1.0, final=False,
                now_monotonic_ns=replaced["monotonic_ns"],
            )

        late = self.snapshot(
            previous["monotonic_ns"]
            + int((status_gate.MAX_SOAK_SAMPLE_INTERVAL_SECONDS + 1) * 1_000_000_000),
            110,
            33,
        )
        with self.assertRaisesRegex(status_gate.GateError, "observation interval"):
            status_gate.verify_soak(
                before, previous, late, 1000, 1.0, final=False,
                now_monotonic_ns=late["monotonic_ns"],
            )

    def test_soak_capture_rejects_repeated_still_fresh_publications(self):
        previous = self.snapshot(1_000_000_000, 10, 0)
        repeated = self.snapshot(2_000_000_000, 10, 0)
        for label in ("edge_a", "edge_b"):
            repeated[label]["status_generation"] = previous[label]["status_generation"]
        with self.assertRaisesRegex(status_gate.GateError, "publication generation"):
            status_gate.verify_soak(
                previous, previous, repeated, 1000, 1.0, final=False,
                now_monotonic_ns=repeated["monotonic_ns"],
            )
        with (
            mock.patch.object(status_gate, "capture", return_value=repeated),
            mock.patch.object(status_gate.time, "monotonic", side_effect=[0.0, 1.0]),
            self.assertRaisesRegex(status_gate.GateError, "did not advance"),
        ):
            status_gate.capture_after_publications(
                self.root / "a.json", self.root / "b.json", previous, 0.5,
            )

    def test_soak_rejects_hidden_path_and_identity_round_trips(self):
        before = self.snapshot(1_000_000_000, 10, 0)
        previous = self.snapshot(2_000_000_000, 20, 1)

        path_round_trip = self.snapshot(3_000_000_000, 30, 2)
        for label in ("edge_a", "edge_b"):
            # The visible endpoint is direct again, but sticky generations
            # preserve direct -> none/relay -> direct transitions.
            path_round_trip[label]["selected_path_transitions"] += 2
        with self.assertRaisesRegex(status_gate.GateError, "selected_path_transitions"):
            status_gate.verify_soak(
                before, previous, path_round_trip, 1000, 1.0, final=False,
                now_monotonic_ns=path_round_trip["monotonic_ns"],
            )

        identity_round_trip = self.snapshot(3_000_000_000, 30, 2)
        for label in ("edge_a", "edge_b"):
            # Public expiry/slot metadata has reverted to the baseline values.
            identity_round_trip[label]["identity_transitions"] += 2
        with self.assertRaisesRegex(status_gate.GateError, "identity_transitions"):
            status_gate.verify_soak(
                before, previous, identity_round_trip, 1000, 1.0, final=False,
                now_monotonic_ns=identity_round_trip["monotonic_ns"],
            )

    def test_missing_or_malformed_authenticated_telemetry_is_rejected(self):
        missing = edge()
        del missing["relay_telemetry"]
        with self.assertRaises(status_gate.GateError):
            status_gate._edge(self.write("missing-telemetry.json", missing), "site-a")
        malformed = edge()
        malformed["relay_telemetry"]["unexpected"] = 1
        with self.assertRaises(status_gate.GateError):
            status_gate._edge(self.write("malformed-telemetry.json", malformed), "site-a")
        legacy_packet_only = edge()
        del legacy_packet_only["relay_telemetry"]["forwarded_bytes"]
        del legacy_packet_only["relay_telemetry"]["dropped_bytes"]
        with self.assertRaises(status_gate.GateError):
            status_gate._edge(self.write("packet-only-telemetry.json", legacy_packet_only), "site-a")
        for name, value in (
            ("control_session", 0),
            ("sequence", True),
            ("dropped_packets", status_gate.MAX_COUNTER + 1),
            ("dropped_bytes", status_gate.MAX_COUNTER + 1),
        ):
            invalid = edge()
            invalid["relay_telemetry"][name] = value
            with self.subTest(name=name), self.assertRaises(status_gate.GateError):
                status_gate._edge(self.write(f"invalid-{name}.json", invalid), "site-a")

    def test_identity_expiry_and_pin_slot_fail_closed(self):
        missing = edge()
        del missing["data_identity"]
        with self.assertRaisesRegex(status_gate.GateError, "data_identity"):
            status_gate._edge(self.write("missing-data-identity.json", missing), "site-a")

        expiring = edge()
        expiring["control_identity"]["peer"] = certificate(
            remaining=datetime.timedelta(seconds=299)
        )
        with self.assertRaisesRegex(status_gate.GateError, "lifetime"):
            status_gate._edge(self.write("expiring-identity.json", expiring), "site-a")

        invalid_slot = edge()
        invalid_slot["data_identity"]["peer"]["pin_slot"] = "unknown"
        with self.assertRaisesRegex(status_gate.GateError, "pin slot"):
            status_gate._edge(self.write("invalid-slot.json", invalid_slot), "site-a")

        next_outside_rotation = edge()
        next_outside_rotation["control_identity"]["peer"]["pin_slot"] = "next"
        with self.assertRaisesRegex(status_gate.GateError, "not in the current slot"):
            status_gate._edge(
                self.write("next-outside-rotation.json", next_outside_rotation),
                "site-a",
            )

    def test_identity_transition_inside_bulk_evidence_is_rejected(self):
        before = self.snapshot(1_000_000_000, 10, 20)
        after = self.snapshot(2_000_000_000, 20, 21)
        after["edge_a"]["data_identity"]["peer"]["pin_slot"] = "next"
        before["edge_a"]["data_identity"]["peer"]["pin_slot"] = "current"
        with self.assertRaisesRegex(status_gate.GateError, "non-current"):
            status_gate.verify(before, after, 1, 10.0)

    def test_counter_type_and_symlink_are_rejected(self):
        invalid = edge()
        invalid["path"]["direct_sent_packets"] = True
        path = self.write("invalid.json", invalid)
        with self.assertRaises(status_gate.GateError):
            status_gate._edge(path, "site-a")
        target = self.write("target.json", edge())
        link = self.root / "link.json"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaises(status_gate.GateError):
            status_gate._edge(link, "site-a")

    def test_hard_link_and_wrong_owner_are_rejected(self):
        target = self.write("hardlink-target.json", edge())
        link = self.root / "hardlink.json"
        try:
            os.link(target, link)
        except OSError:
            self.skipTest("hard links unavailable")
        with self.assertRaisesRegex(status_gate.GateError, "link count"):
            status_gate._read_json(target)
        link.unlink()
        with mock.patch.object(status_gate, "_effective_identity", return_value=(123456789, 123456789)):
            with self.assertRaisesRegex(status_gate.GateError, "owner"):
                status_gate._read_json(target)

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits required")
    def test_group_or_world_writable_status_is_rejected(self):
        target = self.write("unsafe-mode.json", edge())
        target.chmod(0o662)
        with self.assertRaisesRegex(status_gate.GateError, "permissions"):
            status_gate._read_json(target)

    def test_stale_status_and_counter_overflow_are_rejected(self):
        stale = edge()
        stale["updated"] = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)
        ).isoformat().replace("+00:00", "Z")
        with self.assertRaisesRegex(status_gate.GateError, "stale"):
            status_gate._edge(self.write("stale.json", stale), "site-a")
        overflow = edge(direct_sent=status_gate.MAX_COUNTER + 1)
        with self.assertRaises(status_gate.GateError):
            status_gate._edge(self.write("overflow.json", overflow), "site-a")
        for field in (
            "status_generation", "selected_path_transitions", "identity_transitions",
        ):
            exhausted = edge()
            exhausted[field] = status_gate.MAX_COUNTER
            with self.subTest(field=field), self.assertRaisesRegex(
                status_gate.GateError, "invalid|exhausted",
            ):
                status_gate._edge(
                    self.write(f"exhausted-{field}.json", exhausted), "site-a",
                )

    def test_snapshot_schema_duplicate_keys_wrap_and_staleness_fail_closed(self):
        before = self.snapshot(1_000_000_000, 100, 20)
        malformed = self.snapshot(2_000_000_000, 200, 21)
        malformed["unexpected"] = 1
        with self.assertRaises(status_gate.GateError):
            status_gate.verify(before, malformed, 1, 10.0)

        wrapped = self.snapshot(2_000_000_000, 10, 21)
        with self.assertRaises(status_gate.GateError):
            status_gate.verify(before, wrapped, 1, 10.0)

        stale_before = self.snapshot(1_000_000_000, 10, 20)
        stale_after = self.snapshot(2_000_000_000, 20, 21)
        with self.assertRaisesRegex(status_gate.GateError, "stale"):
            status_gate.verify(
                stale_before, stale_after, 1, 10.0,
                now_monotonic_ns=int(
                    (status_gate.MAX_FINAL_SNAPSHOT_AGE_SECONDS + 3) * 1_000_000_000
                ),
            )

        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"format":1,"format":1}\n', encoding="utf-8")
        with self.assertRaisesRegex(status_gate.GateError, "duplicate"):
            status_gate._read_json(duplicate)

    @mock.patch.object(status_gate, "_boot_id_sha256", return_value="a" * 64)
    def test_snapshot_read_rejects_extra_keys_and_symlinks(self, _boot_id):
        valid = self.write("snapshot.json", self.snapshot(1_000_000_000, 1, 1))
        self.assertEqual(status_gate.read_snapshot(valid)["format"], 1)
        malformed = self.snapshot(1_000_000_000, 1, 1)
        malformed["extra"] = 1
        with self.assertRaises(status_gate.GateError):
            status_gate.read_snapshot(self.write("malformed-snapshot.json", malformed))
        link = self.root / "snapshot-link.json"
        try:
            link.symlink_to(valid)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaises(status_gate.GateError):
            status_gate.read_snapshot(link)

    @mock.patch.object(status_gate, "_boot_id_sha256", return_value="a" * 64)
    def test_wait_telemetry_requires_both_sequences_to_advance(self, _boot_id):
        before = self.snapshot(1_000_000_000, 10, 20)
        before_path = self.write("before.json", before)
        a = self.write(
            "wait-a.json",
            edge(
                direct_sent=20, direct_received=20, progress=20,
                control_session=before["edge_a"]["control_session"],
                telemetry_sequence=before["edge_a"]["telemetry_sequence"] + 1,
                raw_a=21, raw_b=21,
            ),
        )
        b = self.write(
            "wait-b.json",
            edge(
                site="site-b",
                direct_sent=20, direct_received=20, progress=20,
                control_session=before["edge_b"]["control_session"],
                telemetry_sequence=before["edge_b"]["telemetry_sequence"] + 1,
                raw_a=21, raw_b=21,
            ),
        )
        self.assertEqual(
            status_gate.main([
                "wait-telemetry", "--edge-a", str(a), "--edge-b", str(b),
                "--before", str(before_path), "--timeout-seconds", "0.1",
            ]),
            0,
        )

        regressed = edge(
            direct_sent=20, direct_received=20, progress=20,
            control_session=before["edge_a"]["control_session"],
            telemetry_sequence=before["edge_a"]["telemetry_sequence"] - 1,
            raw_a=21, raw_b=21,
        )
        self.write("wait-a.json", regressed)
        errors = io.StringIO()
        started = time.monotonic()
        with contextlib.redirect_stderr(errors):
            result = status_gate.main([
                "wait-telemetry", "--edge-a", str(a), "--edge-b", str(b),
                "--before", str(before_path), "--timeout-seconds", "10",
            ])
        self.assertEqual(result, 1)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertIn("sequence regressed", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
