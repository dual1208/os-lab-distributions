import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ContinuousSoakContractTests(unittest.TestCase):
    @staticmethod
    def read(relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_normative_contract_requires_one_full_duplex_socket(self):
        protocol = self.read("PROTOCOL.md")
        self.assertIn("### Continuous 24-hour soak and seven-day burn-in", protocol)
        self.assertRegex(
            protocol, r"exactly one TCP\nconnection from A11 to B22"
        )
        self.assertIn("The client performs one\n`connect`, the server performs one `accept`", protocol)
        self.assertIn("independent 30-second\ndeadlines", protocol)
        self.assertIn("average at least 2.000 Mbit/s", protocol)
        self.assertIn("120-second completion grace", protocol)
        self.assertIn("record is exactly 16 MiB", protocol)
        self.assertIn("sequence of successful fresh health connections\nis not soak evidence", protocol)
        self.assertIn(
            "The new snapshot is then checked against both the fixed baseline",
            protocol,
        )
        self.assertRegex(
            protocol,
            r"totals are bounded cumulatively from the single initial\s+snapshot",
        )
        self.assertIn("`status_generation`", protocol)
        self.assertIn("`selected_path_transitions` and `identity_transitions`", protocol)
        self.assertIn("publication generations have advanced", protocol)
        self.assertRegex(
            protocol,
            r"A raw numeric `kill -0` is never child\s+identity\s+evidence",
        )
        self.assertIn("Signals are sent only through a\nLinux pidfd", protocol)
        self.assertIn("two-FIFO readiness/acknowledgement handshake", protocol)
        self.assertIn("remains alive and blocked for at most five seconds", protocol)

    def test_runner_has_no_fresh_connection_probe_or_reconnect_path(self):
        script = self.read("scripts/soak-a11-b22.sh")
        self.assertIn("readonly STREAM_RECORD_BYTES=16777216", script)
        self.assertIn("readonly MIN_STREAM_BYTES_PER_SECOND=250000", script)
        self.assertIn('serve-once \\\n', script)
        self.assertIn('continuous-client \\\n', script)
        self.assertIn('verify-soak \\\n', script)
        self.assertIn('--after "${status_previous}" --timeout-seconds 5', script)
        self.assertIn('--raw-relay-rate 1 --final', script)
        self.assertIn(
            "PASS connections=1 reconnects=0 records=%s\\n", script
        )
        self.assertIn(
            'cmp -s -- "${evidence_dir}/server.log" '
            '"${evidence_dir}/server.expected"',
            script,
        )
        self.assertNotIn("probe_direction", script)
        self.assertNotRegex(script, r"\bhealth\b")
        self.assertNotIn("campus-link-a11-b22.py", script)
        self.assertIn('[[ ${stream_connections} == 1 && ${stream_reconnects} == 0 ]]', script)
        self.assertNotIn("kill -0", script)
        self.assertIn('"${STREAM_PROBE}" signal-pid', script)
        self.assertIn("readonly CHILD_HANDSHAKE_TIMEOUT_SECONDS=5", script)
        self.assertIn("launch_tracked_child server_pid server_start_ticks", script)
        self.assertIn("launch_tracked_child client_pid client_start_ticks", script)
        self.assertIn('observed_pid} == "${pid}"', script)
        self.assertIn('track_child "${pid}" "${observed_ticks}"', script)
        self.assertIn("case ${client_state} in", script)
        self.assertIn("case ${server_state} in", script)

    def test_both_directions_have_independent_progress_and_absolute_bounds(self):
        script = self.read("scripts/soak-a11-b22.sh")
        self.assertIn("readonly PROGRESS_TIMEOUT_MS=30000", script)
        self.assertIn("readonly COMPLETION_GRACE_SECONDS=120", script)
        self.assertIn("last_send_advance_ms", script)
        self.assertIn("last_receive_advance_ms", script)
        self.assertIn("fail_soak A_TO_B progress-timeout", script)
        self.assertIn("fail_soak B_TO_A progress-timeout", script)
        self.assertIn("fail_soak A_TO_B throughput-floor", script)
        self.assertIn("fail_soak B_TO_A throughput-floor", script)
        self.assertIn("fail_soak BOTH observation-deadline", script)
        self.assertIn("fail_soak BOTH completion-grace", script)

    def test_progress_parser_fails_closed_even_when_called_from_conditionals(self):
        script = self.read("scripts/soak-a11-b22.sh")
        self.assertIn("[[ ${output} != *$'\\n'* ]] || return 1", script)
        self.assertIn("[[ -z ${extra:-} ]] || return 1", script)
        self.assertIn(
            "[[ ${stream_state} == running || ${stream_state} == pass ]] || return 1",
            script,
        )
        self.assertIn(
            "[[ ${stream_transcript_sha256} =~ ^[a-f0-9]{64}$ ]] || return 1",
            script,
        )

    def test_pass_marker_is_sanitized_and_exactly_accounts_for_stream(self):
        script = self.read("scripts/soak-a11-b22.sh")
        for field in (
            "TCP_CONNECTIONS=1",
            "TCP_RECONNECTS=0",
            "FULL_DUPLEX_RECORDS=%s",
            "STREAM_BYTES_A_TO_B=%s",
            "STREAM_BYTES_B_TO_A=%s",
            "FIRST_A_TO_B_SEQUENCE=%s",
            "LAST_A_TO_B_SEQUENCE=%s",
            "FIRST_B_TO_A_SEQUENCE=%s",
            "LAST_B_TO_A_SEQUENCE=%s",
            "STREAM_TRANSCRIPT_SHA256=%s",
            "PROGRESS_TIMEOUT_MS=%s",
            "COMPLETION_GRACE_SECONDS=%s",
            "MAX_PROGRESS_GAP_A_TO_B_MS=%s",
            "MAX_PROGRESS_GAP_B_TO_A_MS=%s",
            "PROGRESS_OBSERVATIONS=%s",
            "DIRECT_STATUS_OBSERVATIONS=%s",
        ):
            self.assertIn(field, script)
        self.assertIn('"${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}"', script)
        self.assertIn('cat -- "${evidence_dir}/status-verified.env"', script)
        self.assertIn(
            "stream_sent == stream_records * STREAM_RECORD_BYTES", script
        )
        self.assertIn(
            "stream_received == stream_records * STREAM_RECORD_BYTES", script
        )
        result_format = re.search(
            r"printf 'FORMAT=1\\nSTATUS=pass.*?' \\\n", script, re.DOTALL
        )
        self.assertIsNotNone(result_format)
        self.assertNotRegex(
            result_format.group(0), r"(?:ADDRESS|SOURCE|DESTINATION|PORT|PID|NONCE)="
        )

    def test_record_count_is_bounded_before_arithmetic_and_marker_publish(self):
        protocol = self.read("PROTOCOL.md")
        script = self.read("scripts/soak-a11-b22.sh")
        maximum = 549755813887
        record_bytes = 16777216
        wrap_count = (1 << 40) + 2000
        wrapped_product = (wrap_count * record_bytes) & ((1 << 64) - 1)

        self.assertEqual(wrapped_product, 33554432000)
        self.assertGreater(wrap_count, maximum)
        self.assertIn(
            "FULL_DUPLEX_RECORDS <= 549755813887", protocol
        )
        self.assertIn(
            "readonly MAX_STREAM_RECORDS=549755813887", script
        )
        self.assertIn("is_shell_uint() {", script)
        self.assertIn("maximum=9223372036854775807", script)
        self.assertIn('is_shell_uint "${value}" || return 1', script)
        self.assertNotIn('[[ ${value} =~ ^[0-9]{1,18}$ ]]', script)
        self.assertGreaterEqual(
            script.count("stream_records <= MAX_STREAM_RECORDS"), 2
        )

        cap = script.index(
            "(( stream_records <= MAX_STREAM_RECORDS )) || "
            "fail_soak BOTH record-count-overflow"
        )
        multiply = script.index(
            "(( stream_sent == stream_records * STREAM_RECORD_BYTES ))"
        )
        validate_stream = script.index(
            'campus_link_validate_continuous_stream_values "${result_source}"'
        )
        validate_direct = script.index(
            'campus_link_validate_direct_evidence_values "${result_source}"'
        )
        publish = script.index(
            'campus_link_atomic_marker "${RESULT}" "${result_source}"'
        )
        self.assertLess(cap, multiply)
        self.assertLess(multiply, validate_stream)
        self.assertLess(validate_stream, validate_direct)
        self.assertLess(validate_direct, publish)

    def test_soak_cleanup_is_bounded_and_pid_reuse_safe(self):
        protocol = self.read("PROTOCOL.md")
        script = self.read("scripts/soak-a11-b22.sh")
        self.assertIn("absolute 25-second cleanup transaction", protocol)
        self.assertIn("PID/start-tick identity before signaling", protocol)
        self.assertIn("readonly SOAK_CLEANUP_TOTAL_MILLISECONDS=25000", script)
        self.assertIn("readonly SOAK_CLEANUP_TERM_GRACE_MILLISECONDS=5000", script)
        self.assertIn(
            'inspect_process_identity "${pid}" "${pid_start_ticks[index]:-}" state',
            script,
        )
        self.assertIn(
            'signal_tracked_child "${pid}" "${pid_start_ticks[index]}" TERM',
            script,
        )
        self.assertIn(
            'signal_tracked_child "${pid}" "${pid_start_ticks[index]}" KILL',
            script,
        )
        self.assertNotRegex(script, r"\bkill\s+-(?:TERM|KILL|0)\b")
        self.assertIn(
            'cleanup_tracked_children "${deadline}" "${kill_at}"', script
        )

    def test_chain_revalidates_duration_bound_direct_and_raw_relay_evidence(self):
        helper = self.read("scripts/gate-evidence.sh")
        self.assertIn(
            '"${CAMPUS_LINK_CONTINUOUS_STREAM_KEYS[@]}" \\\n'
            '    "${CAMPUS_LINK_DIRECT_EVIDENCE_KEYS[@]}"',
            helper,
        )
        self.assertIn(
            'campus_link_validate_direct_evidence_values "${day}"', helper
        )
        self.assertIn(
            'campus_link_validate_direct_evidence_values "${week}"', helper
        )

    def test_24_hour_and_seven_day_services_bound_completion_grace(self):
        day = self.read("systemd/campus-link-24h-soak.service")
        week = self.read("systemd/campus-link-7d-burn-in.service")
        self.assertIn("TimeoutStartSec=26h", day)
        self.assertIn("TimeoutStartSec=8d", week)
        for unit in (day, week):
            self.assertIn("OOMPolicy=stop", unit)
            self.assertIn("MemoryMax=768M", unit)
            self.assertIn("TasksMax=256", unit)
            self.assertIn("LimitNOFILE=512", unit)


if __name__ == "__main__":
    unittest.main()
