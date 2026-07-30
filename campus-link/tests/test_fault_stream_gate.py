#!/usr/bin/env python3
"""Static production contracts for the supervised fault-in-stream gate."""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FaultStreamGateContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_production_defaults_are_multi_gib_and_idle_expiring(self):
        script = self.read("scripts/fault-in-stream.sh")
        self.assertIn("CAMPUS_LINK_FAULT_STREAM_BYTES:-2147483648", script)
        self.assertIn("CAMPUS_LINK_RELAY_OUTAGE_MS:-15000", script)
        self.assertIn("CAMPUS_LINK_DIRECT_FAULT_HOLD_MS:-15000", script)
        self.assertIn("stream_bytes >= 2147483648", script)
        self.assertIn("relay_outage_target_ms >= 15000", script)
        self.assertIn("direct_fault_target_ms >= 15000", script)
        self.assertIn("MAX_APPLICATION_OUTAGE_BOUND_MS=25000", script)
        self.assertIn("MODE=${2:-production}", script)
        self.assertIn("isolated-test)", script)
        self.assertIn("fault-in-stream \"${MODE}\"", script)

    def test_one_connection_overlaps_both_distinct_faults(self):
        script = self.read("scripts/fault-in-stream.sh")
        transport = self.read("tests/stream_transport.py")
        client = script.index("client \\")
        control = script.index("set_control_block campus-a", client)
        direct = script.index("set_direct_block campus-a", control)
        completion = script.index('wait "${client_pid}"', direct)
        self.assertLess(client, control)
        self.assertLess(control, direct)
        self.assertLess(direct, completion)
        self.assertIn("wait-control-outage", script[control:direct])
        self.assertIn("wait-control-reconnected", script[control:direct])
        self.assertGreaterEqual(script[control:direct].count("wait-control-outage"), 2)
        self.assertIn("RELAY_PROGRESS_MIN_BYTES=1048576", script)
        self.assertIn("relay_progress_a_to_b_delta_bytes >= RELAY_PROGRESS_MIN_BYTES", script)
        self.assertIn("relay_progress_b_to_a_delta_bytes >= RELAY_PROGRESS_MIN_BYTES", script)
        self.assertIn("RELAY_PROGRESS_SAMPLES_EACH_DIRECTION=3", script)
        for direction in ("A_TO_B", "B_TO_A"):
            for point in ("BEFORE", "DURING", "NEAR_UNBLOCK"):
                self.assertIn(f"RELAY_PROGRESS_{direction}_{point}_BYTES", script)
        self.assertIn("RELAY_NEAR_UNBLOCK_GUARD_MS", script)
        self.assertIn("a-to-b-progress.json", script)
        self.assertIn("b-to-a-progress.json", script)
        self.assertIn("wait-direct-outage", script[direct:completion])
        self.assertIn("--after-received-bytes", script[direct:completion])
        self.assertIn("PASS rounds=1 connection_reused=true", script)
        self.assertIn("serve-session-once \\", script)
        self.assertIn("def serve_session_once(args):", transport)
        self.assertIn("listener.listen(1)", transport)
        self.assertIn("records != 1", transport)
        self.assertIn("PASS connections=1 reconnects=0 records=1", transport)
        self.assertIn('server_log_expected=$(mktemp', script)
        self.assertIn('cmp -s -- "${evidence_dir}/server.log"', script)
        self.assertIn(
            'campus_link_require_root_file "${evidence_dir}/server.log" 600',
            script,
        )
        self.assertNotIn('wc -l < "${evidence_dir}/server.log"', script)

    def test_fault_server_and_writer_lifetime_are_normative(self):
        protocol = self.read("PROTOCOL.md")
        transport = self.read("tests/stream_transport.py")
        self.assertIn("accepts exactly one application TCP session", protocol)
        self.assertIn("PASS connections=1 reconnects=0 records=1", protocol)
        self.assertIn("must not retain the\nPython process lifetime", protocol)
        self.assertIn("daemon=True", transport)

    def test_server_terminal_log_is_compared_as_exact_bytes(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")

        script = self.read("scripts/fault-in-stream.sh")
        start = script.index('server_log_expected=$(mktemp')
        end = script.index(
            '\npython3 -B "${STATUS_GATE}" wait-telemetry', start,
        )
        validation = script[start:end]
        self.assertIn("campus_link_require_root_file", validation)
        self.assertGreaterEqual(validation.count("stat -c '%h'"), 2)
        self.assertIn("cmp -s --", validation)
        self.assertNotIn("grep", validation)
        self.assertNotIn("wc -l", validation)

        harness = """set -euo pipefail
evidence_dir=$(mktemp -d)
trap 'rm -rf -- "${evidence_dir}"' EXIT
custody_ok=1
link_count=1
campus_link_require_root_file() { (( custody_ok != 0 )); }
stat() { printf '%s\\n' "${link_count}"; }
case $1 in
  exact) printf 'PASS connections=1 reconnects=0 records=1\\n' ;;
  trailing) printf 'PASS connections=1 reconnects=0 records=1\\nEXTRA' ;;
  duplicate) printf 'PASS connections=1 reconnects=0 records=1\\nPASS connections=1 reconnects=0 records=1' ;;
  missing-newline) printf 'PASS connections=1 reconnects=0 records=1' ;;
  leading) printf 'EXTRA\\nPASS connections=1 reconnects=0 records=1\\n' ;;
  bad-custody) custody_ok=0; printf 'PASS connections=1 reconnects=0 records=1\\n' ;;
  bad-link) link_count=2; printf 'PASS connections=1 reconnects=0 records=1\\n' ;;
  *) exit 2 ;;
esac > "${evidence_dir}/server.log"
""" + validation + """
printf 'accepted\\n'
"""
        for case, should_pass in (
            ("exact", True),
            ("trailing", False),
            ("duplicate", False),
            ("missing-newline", False),
            ("leading", False),
            ("bad-custody", False),
            ("bad-link", False),
        ):
            with self.subTest(case=case):
                completed = subprocess.run(
                    [bash, "-c", harness, "--", case],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode == 0, should_pass)
                if should_pass:
                    self.assertEqual(completed.stdout, "accepted\n")

    def test_worst_case_timeline_expires_idle_and_preserves_recovery_budget(self):
        script = self.read("scripts/fault-in-stream.sh")

        def constant(name):
            match = re.search(rf"readonly {name}=([0-9]+)", script)
            self.assertIsNotNone(match, name)
            return int(match.group(1))

        idle = constant("DIRECT_IDLE_TIMEOUT_MS")
        guard = constant("STALL_GUARD_MS")
        maximum = constant("MAX_APPLICATION_OUTAGE_BOUND_MS")
        no_path = constant("MUX_NO_PATH_DEADLINE_MS")
        hold = int(re.search(
            r"CAMPUS_LINK_DIRECT_FAULT_HOLD_MS:-([0-9]+)", script,
        ).group(1))
        self.assertGreater(hold, idle)
        self.assertGreaterEqual(maximum - hold - guard, 9_000)
        self.assertGreater(maximum - hold - guard, 5_000)
        self.assertLess(maximum, no_path)
        self.assertIn('--timeout-seconds 10', script)
        self.assertIn("recovered_a_to_b_ns > direct_unblocked_ms", script)
        self.assertIn("recovered_b_to_a_ns > direct_unblocked_ms", script)

    def test_impaired_throughput_floor_is_bidirectional_and_chain_enforced(self):
        script = self.read("scripts/fault-in-stream.sh")
        helper = self.read("scripts/gate-evidence.sh")
        transport_tests = self.read("tests/test_stream_transport.py")
        self.assertIn("IMPAIRED_MIN_MILLI_MBIT_S=2000", script)
        self.assertIn("--min-send-mbit-s 2 --min-receive-mbit-s 2", script)
        self.assertIn("MEASURED_A_TO_B_MILLI_MBIT_S", script)
        self.assertIn("MEASURED_B_TO_A_MILLI_MBIT_S", script)
        self.assertIn("measured_a >= impaired_floor", helper)
        self.assertIn("measured_b >= impaired_floor", helper)
        self.assertIn("test_round_below_either_throughput_floor_fails", transport_tests)

    def test_faults_are_plane_specific_and_cleanup_is_bounded(self):
        script = self.read("scripts/fault-in-stream.sh")
        netem = self.read("scripts/test-netem.sh")
        self.assertIn("-p tcp", script)
        self.assertIn("campus-link-fault-stream-control", script)
        self.assertIn("-p udp", script)
        self.assertIn("campus-link-fault-stream-direct", script)
        self.assertIn("clear_control_block campus-a cl-a-wan", script)
        self.assertIn("clear_direct_block campus-b cl-b-wan", script)
        self.assertIn("FAULT_CLEANUP_TOTAL_MILLISECONDS=30000", script)
        self.assertIn("FAULT_NETWORK_CLEANUP_MILLISECONDS=8000", script)
        self.assertIn("FAULT_RULE_DELETE_LIMIT=16", script)
        self.assertIn("delete_exact_rule_bounded()", script)
        self.assertIn('iptables -w 1 -C "$@"', script)
        self.assertIn('iptables -w 1 -D "$@"', script)
        self.assertIn('iptables -w 1 -S "${chain}"', script)
        self.assertNotIn("while ip netns exec", script)
        self.assertIn('clear-profile >/dev/null 2>&1 || cleanup_ok=0', script)
        self.assertIn("tc qdisc show dev cl-a-wan", netem)
        self.assertIn("tc qdisc show dev cl-b-wan", netem)
        self.assertNotIn("iptables -F", script)
        self.assertNotIn("/run/campus-link/status.json", script)

    def test_netem_profile_matches_the_normative_fixed_profile(self):
        netem = self.read("scripts/test-netem.sh")
        fault = self.read("scripts/fault-in-stream.sh")
        self.assertIn("delay 100ms 20ms loss 1% reorder 0.1% 25%", netem)
        self.assertIn('"${NETEM}" "${REPO_ROOT}" apply-profile', fault)
        self.assertIn("NETEM_DELAY_MS=100", fault)
        self.assertIn("NETEM_JITTER_MS=20", fault)
        self.assertIn("NETEM_LOSS_BASIS_POINTS=100", fault)
        self.assertIn("NETEM_REORDER_BASIS_POINTS=10", fault)

    def test_process_memory_identity_and_zero_relay_evidence_are_required(self):
        script = self.read("scripts/fault-in-stream.sh")
        helper = self.read("scripts/gate-evidence.sh")
        status = self.read("tests/status_gate.py")
        self.assertGreaterEqual(script.count("assert_process_continuity"), 7)
        self.assertIn("MemoryMax", script)
        self.assertIn("MemoryCurrent", script)
        self.assertIn("MEMORY_CEILING_BYTES=100663296", script)
        for key in (
            "direct_required", "direct_instance", "relay_received", "queue_drops", "dropped",
            "FAULT_EXACT_PATH_IDENTITY_CHECKS",
        ):
            self.assertIn(key, status)
        for key in (
            "FAULT_EDGE_A_RELAY_SENT_DELTA",
            "FAULT_EDGE_A_RELAY_RECEIVED_DELTA",
            "FAULT_EDGE_A_QUEUE_DROPS_DELTA",
            "FAULT_EDGE_A_DROPPED_DELTA",
        ):
            self.assertIn(key, helper)

    def test_memory_aggregation_rejects_malformed_empty_and_extra_fields(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")

        script = self.read("scripts/fault-in-stream.sh")
        start = script.index('memory_peak_source=$(mktemp')
        end = script.index("\nmemory_peak_a=", start)
        aggregation = script[start:end]
        self.assertNotIn("< <(", aggregation)
        self.assertIn("if ! awk -F", aggregation)
        self.assertIn('${evidence_dir}/.memory-peaks.XXXXXX', aggregation)
        self.assertIn('${#memory_peak_lines[@]} -eq 1', aggregation)

        harness = """set -euo pipefail
evidence_dir=$(mktemp -d)
trap 'rm -rf -- "${evidence_dir}"' EXIT
MEMORY_CEILING_BYTES=100663296
case $1 in
  valid) printf '10\\t20\\n30\\t15\\n' ;;
  zero) printf '0\\t0\\n' ;;
  malformed) printf '10\\t20\\nbogus\\t30\\n' ;;
  empty) : ;;
  extra) printf '10\\t20\\n30\\t40\\textra\\n' ;;
  leading-zero) printf '01\\t20\\n' ;;
  above-ceiling) printf '100663297\\t20\\n' ;;
  overflow) printf '9223372036854775807\\t20\\n' ;;
  *) exit 2 ;;
esac > "${evidence_dir}/memory.tsv"
""" + aggregation + """
printf '%s %s\\n' "${peak_a}" "${peak_b}"
"""
        cases = (
            ("valid", 0, "30 20"),
            ("zero", 0, "0 0"),
            ("malformed", 1, None),
            ("empty", 1, None),
            ("extra", 1, None),
            ("leading-zero", 1, None),
            ("above-ceiling", 1, None),
            ("overflow", 1, None),
        )
        for case, expected_status, expected_output in cases:
            with self.subTest(case=case):
                completed = subprocess.run(
                    [bash, "-c", harness, "--", case],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if expected_status == 0:
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(completed.stdout.strip(), expected_output)
                else:
                    self.assertNotEqual(completed.returncode, 0)

    def test_kernel_memory_peaks_are_mandatory_canonical_and_combined(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")

        script = self.read("scripts/fault-in-stream.sh")
        function_start = script.index("read_unit_uint()")
        function_end = script.index("\n\nprogress_uint()", function_start)
        read_unit = script[function_start:function_end]
        peak_start = script.index(
            "memory_peak_a=$(read_unit_uint campus-link-edge-a.service MemoryPeak)",
        )
        peak_end = script.index("\n(( process_continuity_checks", peak_start)
        kernel_peaks = script[peak_start:peak_end]
        self.assertIn(
            "memory_peak_b=$(read_unit_uint campus-link-edge-b.service MemoryPeak) || exit 1",
            kernel_peaks,
        )
        self.assertNotIn("[[ ${memory_peak_a} =~", kernel_peaks)

        harness = """set -euo pipefail
MOCK_A=$1
MOCK_B=$2
STATUS_A=$3
STATUS_B=$4
MEMORY_CEILING_BYTES=100663296
peak_a=10
peak_b=20
systemctl() {
  local unit=${@: -1}
  case ${unit} in
    campus-link-edge-a.service) printf '%s\\n' "${MOCK_A}"; return "${STATUS_A}" ;;
    campus-link-edge-b.service) printf '%s\\n' "${MOCK_B}"; return "${STATUS_B}" ;;
    *) return 2 ;;
  esac
}
""" + read_unit + """
""" + kernel_peaks + """
printf '%s %s\\n' "${peak_a}" "${peak_b}"
"""
        cases = (
            ("30", "15", "0", "0", 0, "30 20"),
            ("", "15", "0", "0", 1, None),
            ("30", "", "0", "0", 1, None),
            ("[not set]", "15", "0", "0", 1, None),
            ("030", "15", "0", "0", 1, None),
            ("10000000000000000", "15", "0", "0", 1, None),
            ("30", "15", "9", "0", 1, None),
            ("30", "15", "0", "9", 1, None),
            ("100663297", "15", "0", "0", 1, None),
        )
        for value_a, value_b, status_a, status_b, expected_status, output in cases:
            with self.subTest(
                value_a=value_a,
                value_b=value_b,
                status_a=status_a,
                status_b=status_b,
            ):
                completed = subprocess.run(
                    [bash, "-c", harness, "--", value_a, value_b, status_a, status_b],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if expected_status == 0:
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(completed.stdout.strip(), output)
                else:
                    self.assertNotEqual(completed.returncode, 0)

    def test_service_chain_installer_and_fingerprint_include_the_gate(self):
        service = self.read("systemd/campus-link-fault-in-stream.service")
        nat = self.read("systemd/campus-link-nat-rebinding.service")
        day = self.read("systemd/campus-link-24h-soak.service")
        chain = self.read("scripts/qualification-chain.sh")
        installer = self.read("scripts/install-edge-lab.sh")
        helper = self.read("scripts/gate-evidence.sh")
        self.assertIn("After=campus-link-accelerated-fault.service", service)
        self.assertIn(" production", service)
        self.assertIn("After=campus-link-fault-in-stream.service", nat)
        self.assertIn("AssertPathExists=/run/campus-link/fault-in-stream.result", nat)
        self.assertIn("After=campus-link-nat-rebinding.service", day)
        self.assertIn("AssertPathExists=/run/campus-link/nat-rebinding.result", day)
        self.assertLess(
            chain.index("run_gate campus-link-fault-in-stream.service"),
            chain.index("run_gate campus-link-nat-rebinding.service"),
        )
        self.assertLess(
            chain.index("run_gate campus-link-nat-rebinding.service"),
            chain.index("run_gate campus-link-24h-soak.service"),
        )
        self.assertIn("campus-link-fault-in-stream", installer)
        self.assertIn("campus-link-fault-in-stream.service", installer)
        self.assertIn("/usr/local/libexec/campus-link-fault-in-stream", helper)
        self.assertIn("/etc/systemd/system/campus-link-fault-in-stream.service", helper)

    def test_chain_refuses_test_mode_or_weak_fixed_bounds(self):
        helper = self.read("scripts/gate-evidence.sh")
        self.assertRegex(
            helper,
            re.compile(
                r'campus_link_validate_gate_marker "\$\{fault\}" "\$\{manifest\}" '
                r"fault-in-stream production"
            ),
        )
        self.assertIn("fault_bytes >= 2147483648", helper)
        self.assertIn("relay_outage >= 15000", helper)
        self.assertIn("relay_progress_a >= 1048576", helper)
        self.assertIn("relay_progress_b >= 1048576", helper)
        self.assertIn("relay_before_a < relay_during_a", helper)
        self.assertIn("relay_before_b < relay_during_b", helper)
        self.assertIn("relay_progress_a == relay_near_a - relay_before_a", helper)
        self.assertIn("relay_progress_b == relay_near_b - relay_before_b", helper)
        self.assertIn("relay_samples == 3", helper)
        self.assertIn("relay_guard <= 1000", helper)
        self.assertIn("fault_hold >= 15000", helper)
        self.assertIn("max_outage_a <= 25000", helper)
        self.assertIn("max_outage_b <= 25000", helper)
        self.assertIn("peak_a <= memory_ceiling", helper)
        self.assertIn("campus_link_validate_fault_evidence_values", helper)

    def test_numeric_helpers_and_callers_fail_closed(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")
        script = self.read("scripts/fault-in-stream.sh")
        start = script.index("read_unit_uint()")
        end = script.index("\n\nedge_a_restarts=", start)
        functions = script[start:end]
        harness = f"""set -euo pipefail
HELPER=$1
MOCK_VALUE=$2
MOCK_STATUS=$3
systemctl() {{ printf '%s\\n' "${{MOCK_VALUE}}"; return "${{MOCK_STATUS}}"; }}
campus_link_marker_value() {{ printf '%s\\n' "${{MOCK_VALUE}}"; return "${{MOCK_STATUS}}"; }}
{functions}
case $HELPER in
  unit) command=(read_unit_uint example.service NRestarts) ;;
  progress) command=(progress_uint example.env RECEIVED_BYTES) ;;
  rate) command=(rate_to_milli_mbit "${{MOCK_VALUE}}") ;;
  *) exit 2 ;;
esac
if value=$("${{command[@]}}"); then
  printf '%s\\n' "${{value}}"
  exit 0
fi
exit 1
"""
        cases = (
            ("unit", "12", "0", 0, "12"),
            ("unit", "12", "9", 1, None),
            ("unit", "010", "0", 1, None),
            ("progress", "123", "0", 0, "123"),
            ("progress", "9223372036854775807", "0", 0, "9223372036854775807"),
            ("progress", "9223372036854775808", "0", 1, None),
            ("progress", "123", "9", 1, None),
            ("progress", "+123", "0", 1, None),
            ("rate", "2.005", "0", 0, "2005"),
            ("rate", "02.005", "0", 1, None),
        )
        for helper, value, status, expected_status, expected_output in cases:
            with self.subTest(helper=helper, value=value, status=status):
                completed = subprocess.run(
                    [bash, "-c", harness, "--", helper, value, status],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if expected_status == 0:
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(completed.stdout.strip(), expected_output)
                else:
                    self.assertNotEqual(completed.returncode, 0)

        calls = list(
            re.finditer(
                r"\$\((?:read_unit_uint|progress_uint|rate_to_milli_mbit)\b[^)]*\)",
                script,
                re.S,
            )
        )
        self.assertGreaterEqual(len(calls), 20)
        for call in calls:
            self.assertRegex(script[call.end() : call.end() + 24], r"^\s*\|\| (?:return|exit) 1")


if __name__ == "__main__":
    unittest.main()
