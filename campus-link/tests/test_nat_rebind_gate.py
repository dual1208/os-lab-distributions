import copy
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import nat_rebind_gate


ROOT = Path(__file__).resolve().parents[1]


def certificate():
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    return {"expires": expires.isoformat().replace("+00:00", "Z"), "pin_slot": "current"}


class NATRebindVerifierTests(unittest.TestCase):
    def setUp(self):
        relay_control = certificate()
        site_a_control = certificate()
        site_b_control = certificate()
        site_a_data = certificate()
        site_b_data = certificate()
        self.identities = {
            "edge_a": {
                "control_identity": {
                    "local": site_a_control, "peer": relay_control,
                },
                "data_identity": {
                    "local": site_a_data, "peer": site_b_data,
                    "path": "direct", "direct_epoch": 1,
                },
            },
            "edge_b": {
                "control_identity": {
                    "local": site_b_control, "peer": relay_control,
                },
                "data_identity": {
                    "local": site_b_data, "peer": site_a_data,
                    "path": "direct", "direct_epoch": 1,
                },
            },
        }

    def edge(self, label, amount, raw, epoch, instance):
        identity = copy.deepcopy(self.identities[label])
        identity["data_identity"]["direct_epoch"] = epoch
        return {
            "status_generation": amount,
            "selected_path_transitions": epoch,
            "identity_transitions": epoch,
            "selected": "direct",
            "direct_required": True,
            "direct_healthy": True,
            "direct_epoch": epoch,
            "direct_instance": instance,
            "relay_sent": 0,
            "relay_received": 0,
            "direct_sent": amount,
            "direct_received": amount + 1,
            "direct_progress": amount + 2,
            "watchdog_failures": 0,
            "fallbacks": 0,
            "queue_drops": 0,
            "invalid_packets": 0,
            "duplicate_packets": 0,
            "dropped": 0,
            "control_session": 11 if label == "edge_a" else 12,
            "telemetry_sequence": amount + 100,
            "relay_forwarded": {"site-a": raw, "site-b": raw},
            "relay_forwarded_bytes": {"site-a": raw * 64, "site-b": raw * 64},
            "relay_dropped": 0,
            "relay_dropped_bytes": 0,
            "control_identity": identity["control_identity"],
            "data_identity": identity["data_identity"],
            "clock": {
                "synchronized": True,
                "absolute_offset_millis": 10,
                "uncertainty_millis": 20,
            },
        }

    def snapshot(self, index, epoch, instance_a, instance_b):
        amount = 10 + index * 10
        return {
            "format": 1,
            "boot_id_sha256": "a" * 64,
            "monotonic_ns": (index + 1) * 1_000_000_000,
            "edge_a": self.edge("edge_a", amount, index, epoch, instance_a),
            "edge_b": self.edge("edge_b", amount, index, epoch, instance_b),
        }

    @staticmethod
    def progress(index, state="running", gap=100):
        records = index + 1
        first_send = 61_000_000_000
        first_receive = 62_000_000_000
        return {
            "format": 1,
            "state": state,
            "started_monotonic_ns": 500_000_000,
            "updated_monotonic_ns": 900_000_000 + index * 1_000_000_000,
            "tcp_connections": 1,
            "tcp_reconnects": 0,
            "records_completed": records,
            "sent_bytes": records * nat_rebind_gate.RECORD_BYTES,
            "received_bytes": records * nat_rebind_gate.RECORD_BYTES,
            "first_send_sequence": first_send,
            "last_send_sequence": first_send + records - 1,
            "first_receive_sequence": first_receive,
            "last_receive_sequence": first_receive + records - 1,
            "max_send_progress_gap_ms": gap,
            "max_receive_progress_gap_ms": gap,
            "transcript_sha256": hashlib.sha256(str(records).encode()).hexdigest(),
        }

    def evidence(self):
        statuses = [
            self.snapshot(0, 1, 10, 20),
            self.snapshot(1, 1, 10, 20),       # authenticated migration
            self.snapshot(2, 2, 11, 21),       # withdrawal/re-establishment
            self.snapshot(3, 2, 11, 21),       # authenticated migration
            self.snapshot(4, 3, 13, 23),       # withdrawal/re-establishment
        ]
        progresses = [self.progress(index) for index in range(5)]
        progresses.append(self.progress(5, state="pass"))
        return statuses, progresses

    def test_accepts_migration_and_symmetric_reestablishment(self):
        statuses, progresses = self.evidence()
        evidence = nat_rebind_gate.verify_evidence(
            statuses,
            progresses,
            process_continuity_checks=12,
            now_monotonic_ns=5_500_000_000,
        )
        self.assertEqual(evidence["MATCHED_DIRECT_EPOCH_CHECKS"], 4)
        self.assertEqual(evidence["MIGRATED_PATHS"], 2)
        self.assertEqual(evidence["REESTABLISHED_PATHS"], 2)
        self.assertEqual(evidence["HIGHER_DIRECT_INSTANCE_EDGE_CHECKS"], 4)
        self.assertEqual(evidence["TCP_CONNECTIONS"], 1)
        self.assertEqual(evidence["TCP_RECONNECTS"], 0)
        self.assertGreater(evidence["EDGE_A_DIRECT_SENT_DELTA"], 0)
        self.assertEqual(evidence["EDGE_A_RELAY_SENT_DELTA"], 0)
        self.assertEqual(tuple(evidence), nat_rebind_gate.EVIDENCE_KEYS)
        serialized_keys = " ".join(evidence).lower()
        for forbidden in ("address", "port", "pid", "invocation", "socket", "namespace"):
            self.assertNotIn(forbidden, serialized_keys)

    def test_rejects_one_sided_instance_replacement(self):
        statuses, progresses = self.evidence()
        statuses[1]["edge_b"]["direct_instance"] += 1
        with self.assertRaisesRegex(nat_rebind_gate.GateError, "mixed"):
            nat_rebind_gate.verify_evidence(
                statuses, progresses, process_continuity_checks=12
            )

    def test_rejects_cross_edge_epoch_mismatch(self):
        statuses, progresses = self.evidence()
        statuses[2]["edge_b"]["direct_epoch"] += 1
        statuses[2]["edge_b"]["data_identity"]["direct_epoch"] += 1
        with self.assertRaisesRegex(nat_rebind_gate.GateError, "direct status"):
            nat_rebind_gate.verify_evidence(
                statuses, progresses, process_continuity_checks=12
            )

    def test_rejects_relay_application_or_drop_counter_leakage(self):
        for key in ("relay_sent", "relay_received", "fallbacks", "dropped", "relay_dropped_bytes"):
            with self.subTest(key=key):
                statuses, progresses = self.evidence()
                statuses[3]["edge_a"][key] = 1
                with self.assertRaisesRegex(nat_rebind_gate.GateError, "counter"):
                    nat_rebind_gate.verify_evidence(
                        statuses, progresses, process_continuity_checks=12
                    )

    def test_rejects_reconnect_or_stream_replacement(self):
        statuses, progresses = self.evidence()
        progresses[3]["tcp_connections"] = 2
        progresses[3]["tcp_reconnects"] = 1
        with self.assertRaises(nat_rebind_gate.GateError):
            nat_rebind_gate.verify_evidence(
                statuses, progresses, process_continuity_checks=12
            )

    def test_rejects_missing_full_duplex_record_or_transcript_advance(self):
        statuses, progresses = self.evidence()
        progresses[2] = copy.deepcopy(progresses[1])
        progresses[2]["updated_monotonic_ns"] += 1
        with self.assertRaisesRegex(nat_rebind_gate.GateError, "did not advance"):
            nat_rebind_gate.verify_evidence(
                statuses, progresses, process_continuity_checks=12
            )

    def test_rejects_outage_over_bound(self):
        statuses, progresses = self.evidence()
        progresses[-1]["max_receive_progress_gap_ms"] = 25_001
        with self.assertRaisesRegex(nat_rebind_gate.GateError, "outage bound"):
            nat_rebind_gate.verify_evidence(
                statuses, progresses, process_continuity_checks=12
            )

    def test_rejects_raw_relay_byte_overrun(self):
        statuses, progresses = self.evidence()
        statuses[-1]["edge_a"]["relay_forwarded_bytes"]["site-a"] = 1_000_000
        statuses[-1]["edge_b"]["relay_forwarded_bytes"]["site-a"] = 1_000_000
        with self.assertRaisesRegex(nat_rebind_gate.GateError, "warm-association"):
            nat_rebind_gate.verify_evidence(
                statuses, progresses, process_continuity_checks=12
            )

    def test_rejects_wrong_process_continuity_count(self):
        statuses, progresses = self.evidence()
        with self.assertRaisesRegex(nat_rebind_gate.GateError, "continuity"):
            nat_rebind_gate.verify_evidence(
                statuses, progresses, process_continuity_checks=10
            )

    def test_wait_checkpoint_writes_one_private_post_baseline_record(self):
        prior = self.progress(0)
        advanced = self.progress(1)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "checkpoint.json"
            with mock.patch.object(
                nat_rebind_gate.stream_transport,
                "read_continuous_progress",
                side_effect=[prior, advanced],
            ):
                value = nat_rebind_gate.wait_checkpoint(
                    Path(temporary) / "live.json",
                    output,
                    prior=prior,
                    required_state="running",
                    timeout_seconds=1,
                )
            self.assertEqual(value["records_completed"], 2)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), advanced)
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_wait_checkpoint_refuses_preexisting_output_and_early_pass(self):
        prior = self.progress(0)
        early_pass = self.progress(1, state="pass")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "checkpoint.json"
            output.write_text("occupied", encoding="utf-8")
            with self.assertRaisesRegex(nat_rebind_gate.GateError, "already exists"):
                nat_rebind_gate.wait_checkpoint(
                    Path(temporary) / "live.json",
                    output,
                    prior=prior,
                    required_state="running",
                    timeout_seconds=1,
                )
            output.unlink()
            with mock.patch.object(
                nat_rebind_gate.stream_transport,
                "read_continuous_progress",
                return_value=early_pass,
            ):
                with self.assertRaisesRegex(nat_rebind_gate.GateError, "ended before"):
                    nat_rebind_gate.wait_checkpoint(
                        Path(temporary) / "live.json",
                        output,
                        prior=prior,
                        required_state="running",
                        timeout_seconds=1,
                    )


class NATRebindSourceContractTests(unittest.TestCase):
    @staticmethod
    def read(relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_spec_precedes_and_defines_exact_sanitized_marker(self):
        contract = self.read("NAT-REBINDING-GATE-INTEGRATION.md")
        self.assertIn("one `accept`", contract)
        self.assertIn("one `connect`", contract)
        self.assertIn("byte-for-byte equal", contract)
        self.assertIn("MIGRATED_PATHS + REESTABLISHED_PATHS", contract)
        self.assertIn("The marker contains no address", contract)
        self.assertIn("GATE=nat-rebinding", contract)
        self.assertIn("TCP_CONNECTIONS=1", contract)
        self.assertIn("TCP_RECONNECTS=0", contract)

    def test_contract_runner_and_verifier_share_one_exact_marker_schema(self):
        contract = self.read("NAT-REBINDING-GATE-INTEGRATION.md")
        marker = re.search(
            r"Its exact format-1 key order is:\n\n```text\n(.*?)\n```",
            contract,
            re.DOTALL,
        )
        self.assertIsNotNone(marker)
        contract_keys = [line.split("=", 1)[0] for line in marker.group(1).splitlines()]
        prefix = [
            "FORMAT", "STATUS", "GATE", "MODE", "RUN_ID", "CANDIDATE_SHA256",
            "RUN_MANIFEST_SHA256", "PREREQUISITE_MARKER_SHA256",
            "START_MONOTONIC_MS", "COMPLETE_MONOTONIC_MS", "FAULT_SITES",
            "FORCED_MAPPING_CHANGES", "RESTORATION_MAPPING_CHANGES",
            "MAPPING_CHANGE_OBSERVATIONS", "SOCKET_MAPPING_PROFILE_CHECKS",
            "UNTOUCHED_WAN_MAPPING_CHECKS", "CONNTRACK_SCOPED_DELETIONS",
            "NAT_RULESET_RESTORATIONS", "FAULT_RECOVERY_TIMEOUT_MS",
        ]
        self.assertEqual(contract_keys, prefix + list(nat_rebind_gate.EVIDENCE_KEYS))

        script = self.read("scripts/nat-rebinding-gate.sh")
        array = re.search(
            r"readonly -a NAT_REBIND_EVIDENCE_KEYS=\(\n(.*?)\n\)",
            script,
            re.DOTALL,
        )
        self.assertIsNotNone(array)
        self.assertEqual(array.group(1).split(), list(nat_rebind_gate.EVIDENCE_KEYS))

        helper = self.read("scripts/gate-evidence.sh")
        helper_array = re.search(
            r"readonly -a CAMPUS_LINK_NAT_REBIND_EVIDENCE_KEYS=\(\n(.*?)\n\)",
            helper,
            re.DOTALL,
        )
        self.assertIsNotNone(helper_array)
        self.assertEqual(
            helper_array.group(1).split(), list(nat_rebind_gate.EVIDENCE_KEYS)
        )

    def test_runner_uses_one_stream_and_four_ordered_mapping_transitions(self):
        script = self.read("scripts/nat-rebinding-gate.sh")
        self.assertEqual(script.count(" continuous-client \\\n"), 1)
        self.assertEqual(script.count(" serve-once \\\n"), 1)
        first = script.index("run_site_trial site-a")
        second = script.index("run_site_trial site-b")
        self.assertLess(first, second)
        self.assertIn("MAPPING_CHANGE_OBSERVATIONS=4", script)
        self.assertIn("SOCKET_MAPPING_PROFILE_CHECKS=4", script)
        self.assertIn("socket_mapping_profile_checks == 4", script)
        self.assertIn("UNTOUCHED_WAN_MAPPING_CHECKS=4", script)
        self.assertIn("untouched_wan_mapping_checks == 4", script)
        self.assertIn("TCP_CONNECTIONS=1", script)
        self.assertIn("TCP_RECONNECTS=0", script)

    def test_mapping_inventory_waits_for_producer_and_consumer_status(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")
        script = self.read("scripts/nat-rebinding-gate.sh")
        start = script.index("collect_complete_lines()")
        end = script.index("\n}\n", start) + 3
        function = script[start:end]
        for call in (
            "collect_complete_lines socket_rows awk",
            "collect_complete_lines values mapping_ports",
            "collect_complete_lines occupied_ports sorted_socket_mapping_ports",
            "collect_complete_lines ports all_socket_mapping_ports",
        ):
            self.assertIn(call, script)
        self.assertIn(
            'forced_range=$(choose_forced_range "${source}" "${source_port}" '
            '"${source_port}") ||',
            script,
        )

        harness = f"""set -euo pipefail
mode=$1
{function}
producer() {{
  printf '41000\\n42000\\n'
  [[ ${{mode}} != producer-failure ]] || return 7
}}
if [[ ${{mode}} == consumer-failure ]]; then
  mapfile() {{
    builtin mapfile "$@"
    return 9
  }}
fi
values=()
collect_complete_lines values producer
[[ ${{values[*]}} == '41000 42000' ]]
"""
        valid = subprocess.run(
            [bash, "-c", harness, "--", "valid"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        for mode in ("producer-failure", "consumer-failure"):
            completed = subprocess.run(
                [bash, "-c", harness, "--", mode],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, mode)

    def test_nat_and_conntrack_mutations_are_exact_and_reversible(self):
        script = self.read("scripts/nat-rebinding-gate.sh")
        self.assertIn('-s "${source}/32" -o "${wan_device}"', script)
        self.assertIn('-p udp --sport "${source_port}"', script)
        self.assertIn('conntrack -D -p udp --orig-src "${source}" --sport "${source_port}"', script)
        self.assertIn('cmp -s -- "${evidence_dir}/nat.before"', script)
        self.assertIn("site_a_rule_active", script)
        self.assertIn("site_b_rule_active", script)
        self.assertNotIn("iptables -F", script)
        self.assertNotIn("iptables -t nat -F", script)
        self.assertNotIn("conntrack -F", script)

    def test_translated_tuple_never_enters_marker_or_console_summary(self):
        script = self.read("scripts/nat-rebinding-gate.sh")
        result = script[script.index("result_source=$(mktemp"):]
        for private_name in (
            "old_mapping", "forced_mapping", "restored_mapping", "source_port",
            "wan_device", "edge_a_invocation", "edge_b_invocation",
        ):
            self.assertNotIn(private_name, result)

    def test_unit_is_chained_immediately_after_fault_stream(self):
        unit = self.read("systemd/campus-link-nat-rebinding.service")
        self.assertIn("After=campus-link-fault-in-stream.service", unit)
        self.assertIn("AssertPathExists=/run/campus-link/fault-in-stream.result", unit)
        self.assertIn(" production", unit)

        chain = self.read("scripts/qualification-chain.sh")
        fault = chain.index("run_gate campus-link-fault-in-stream.service fault-in-stream")
        nat = chain.index("run_gate campus-link-nat-rebinding.service nat-rebinding")
        day = chain.index("run_gate campus-link-24h-soak.service 24h-soak")
        self.assertLess(fault, nat)
        self.assertLess(nat, day)
        self.assertIn('"${RUN_DIR}/nat-rebinding.result"', chain)

        day_unit = self.read("systemd/campus-link-24h-soak.service")
        self.assertIn("After=campus-link-nat-rebinding.service", day_unit)
        self.assertIn(
            "AssertPathExists=/run/campus-link/nat-rebinding.result", day_unit
        )
        soak = self.read("scripts/soak-a11-b22.sh")
        self.assertIn(
            "prerequisite=/run/campus-link/nat-rebinding.result", soak
        )
        self.assertIn("prerequisite_gate=nat-rebinding", soak)

    def test_release_install_rollback_cleanup_and_fingerprint_cover_gate(self):
        installer = self.read("scripts/install-edge-lab.sh")
        rollback = self.read("scripts/rollback-edge.sh")
        restore = self.read("scripts/restore-offline.sh")
        helper = self.read("scripts/gate-evidence.sh")
        destinations = (
            "/usr/local/libexec/campus-link-nat-rebinding-gate",
            "/usr/local/libexec/campus-link-nat-rebind-gate.py",
            "/etc/systemd/system/campus-link-nat-rebinding.service",
        )
        for destination in destinations:
            self.assertIn(destination, installer)
            self.assertIn(destination, rollback)
            self.assertIn(destination, helper)
        self.assertIn("campus-link-nat-rebinding.service", restore)
        self.assertIn("/run/campus-link/nat-rebinding.result", restore)

    def test_central_validation_is_exact_and_overflow_safe(self):
        helper = self.read("scripts/gate-evidence.sh")
        self.assertIn(
            'campus_link_validate_gate_marker "${nat}" "${manifest}" '
            "nat-rebinding production",
            helper,
        )
        self.assertIn(
            'campus_link_validate_nat_rebinding_values "${nat}"', helper
        )
        self.assertIn(
            '[[ ${through} == nat-rebinding ]] && return 0', helper
        )
        guard = helper.index(
            "records <= 9223372036854775807 / record_bytes"
        )
        product = helper.index("expected_bytes=$((records * record_bytes))", guard)
        self.assertLess(guard, product)
        self.assertIn("last_a - first_a == records - 1", helper)
        self.assertIn("last_b - first_b == records - 1", helper)
        self.assertIn("migrated + reestablished == 4", helper)
        self.assertIn("higher == reestablished * 2", helper)
        self.assertIn("packet_lower <= byte_upper", helper)
        self.assertIn("byte_lower <= packet_upper", helper)


if __name__ == "__main__":
    unittest.main()
