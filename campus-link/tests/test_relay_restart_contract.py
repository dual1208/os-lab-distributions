#!/usr/bin/env python3
"""Production contracts for authenticated, same-socket relay restart testing."""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RelayRestartContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    @staticmethod
    def normalized(text: str) -> str:
        """Compare contracts independently of prose wrapping and shell continuations."""
        return " ".join(text.replace("\\\n", " ").split())

    def test_protocol_requires_asymmetric_session_and_phase_authority(self):
        protocol = self.normalized(self.read("PROTOCOL.md"))
        for contract in (
            "dedicated Ed25519 key pair",
            "second, independently generated Ed25519",
            "fixed ten-minute expiry",
            "literal actions `permit` and `restart`",
            "zero command-line arguments",
            "256-bit canonical-hex session secret",
            "permit-public-key digest",
            "server challenge",
            "domain-separated release transcript",
            "domain-separated commit transcript",
            "crash-durably",
            "explicit no-resume semantics",
            "dedicated local process group",
            "same application socket",
            "fresh per-direction receive-byte and monotonic-timestamp",
            "fixed discoverable identity",
            "nonempty effective `DropInPaths` set",
        ):
            self.assertIn(self.normalized(contract), protocol)

    def test_authorized_wrapper_exposes_only_two_fixed_zero_argv_actions(self):
        source = self.read("scripts/relay-restart-authorized.sh")
        self.assertTrue(source.startswith("#!/bin/bash -p\n"))
        self.assertIn("[[ $# -eq 0 ]]", source)
        self.assertRegex(source, r"(?m)^  permit\)$")
        self.assertRegex(source, r"(?m)^  restart\)$")
        self.assertIn(
            "exec /usr/bin/sudo -n -- "
            "/usr/local/libexec/campus-link-relay-restart-permit-authorize",
            source,
        )
        self.assertIn(
            "exec /usr/bin/sudo -n -- "
            "/usr/local/libexec/campus-link-relay-restart-actuator",
            source,
        )
        for forbidden in (
            "restart\\ ",
            "permit\\ ",
            '"${run_id}"',
            '"${signature_base64}"',
            "eval ",
            "bash -c",
            "sh -c",
        ):
            self.assertNotIn(forbidden, source)

    def test_privileged_chain_minimizes_and_validates_environment(self):
        for relative in (
            "scripts/relay-restart-authorized.sh",
            "scripts/relay-restart-actuator.sh",
            "scripts/relay-restart-permit-authorize.sh",
            "scripts/relay-restart-driver.sh",
            "scripts/relay-restart-transport.sh",
        ):
            with self.subTest(relative=relative):
                source = self.read(relative)
                self.assertTrue(source.startswith("#!/bin/bash -p\n"))
                self.assertIn("[[ -z ${BASH_ENV+x} && -z ${ENV+x} ]]", source)
                for variable in (
                    "LD_PRELOAD",
                    "LD_LIBRARY_PATH",
                    "LD_AUDIT",
                    "OPENSSL_CONF",
                    "OPENSSL_MODULES",
                    "OPENSSL_ENGINES",
                ):
                    self.assertIn(f"${{{variable}+x}}", source)
                self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", source)
                self.assertIn("LC_ALL=C", source)
                self.assertIn("ulimit -S -c 0", source)
                self.assertIn("ulimit -H -c 0", source)
        for relative in (
            "scripts/relay-restart-actuator.sh",
            "scripts/relay-restart-permit-authorize.sh",
        ):
            self.assertIn("[[ ! -t 0 && ! -t 1 && ! -t 2 ]]", self.read(relative))

    def test_release_digest_requires_one_exact_logical_name(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")
        driver = self.read("scripts/relay-restart-driver.sh")
        start = driver.index("release_digest()")
        end = driver.index("\n\nexpected_actuator_digest=", start)
        function = driver[start:end]
        digest = "a" * 64
        harness = f"""set -euo pipefail
ENTRY=$1
REQUEST=$2
DIGEST=$3
RELEASE_MANIFEST=$(mktemp)
trap 'rm -f -- "${{RELEASE_MANIFEST}}"' EXIT
printf '%s  %s\\n' "${{DIGEST}}" "${{ENTRY}}" > "${{RELEASE_MANIFEST}}"
{function}
if value=$(release_digest "${{REQUEST}}"); then
  printf '%s\\n' "${{value}}"
  exit 0
fi
exit 1
"""
        exact = "scripts/relay-restart-actuator.sh"
        valid = subprocess.run(
            [bash, "-c", harness, "--", exact, exact, digest],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(valid.stdout.strip(), digest)
        prefix_only = subprocess.run(
            [bash, "-c", harness, "--", f"{exact}-extra", exact, digest],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(prefix_only.returncode, 0)
        self.assertIn(
            "expected_actuator_digest=$(release_digest scripts/relay-restart-actuator.sh) || exit 1",
            driver,
        )

    def test_live_replay_ledger_waits_for_enumerator_status(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")
        for relative in (
            "scripts/relay-restart-actuator.sh",
            "scripts/relay-restart-permit-authorize.sh",
        ):
            with self.subTest(relative=relative):
                source = self.read(relative)
                start = source.index("validate_used_ledger()")
                end = source.index("\n}\n", start) + 3
                function = source[start:end]
                self.assertIn("find_pid=$!", function)
                self.assertIn('wait "${find_pid}" || return 1', function)
                harness = f"""set -euo pipefail
FIND_STATUS=$1
USED_DIR=$(mktemp -d)
trap 'rm -rf -- "${{USED_DIR}}"' EXIT
require_root_file() {{ return 0; }}
find() {{
  printf '%s\\0' "${{USED_DIR}}/0123456789abcdef0123456789abcdef"
  return "${{FIND_STATUS}}"
}}
{function}
count=$(validate_used_ledger) || exit 1
[[ ${{count}} == 1 ]]
"""
                valid = subprocess.run(
                    [bash, "-c", harness, "--", "0"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(valid.returncode, 0, valid.stderr)
                failed = subprocess.run(
                    [bash, "-c", harness, "--", "7"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(failed.returncode, 0)

    def test_permit_is_binary_exact_bound_and_durable_before_ack(self):
        driver = self.read("scripts/relay-restart-driver.sh")
        authorizer = self.read("scripts/relay-restart-permit-authorize.sh")
        for field in (
            "ACTION=relay-restart-permit",
            "CANDIDATE_SHA256",
            "RUN_MANIFEST_SHA256",
            "DEPLOYMENT_ATTESTATION_SHA256",
            "PERMIT_KEY_SHA256",
            "SESSION_SHA256",
            "ISSUED_UNIX",
            "NOT_AFTER_UNIX",
            "SIGNATURE_BASE64",
        ):
            self.assertIn(field, driver)
            self.assertIn(field, authorizer)
        self.assertIn("[[ $# -eq 0 ]]", authorizer)
        self.assertIn("MAX_ENVELOPE_BYTES=2048", authorizer)
        self.assertIn("dd iflag=fullblock", authorizer)
        self.assertIn('cmp -s -- "${raw_envelope}" "${canonical_envelope}"', authorizer)
        self.assertIn("openssl pkeyutl -verify", authorizer)
        self.assertIn('cmp -s -- "${signature_text}" "${signature_canonical}"', authorizer)
        verify = authorizer.index("openssl pkeyutl -verify")
        lock = authorizer.index('exec 9<>"${RUNTIME_DIR}/actuator.lock"')
        mutation = authorizer.index('mv -fT -- "${expected_source}.installed"')
        flush = authorizer.index('sync -f -- "${STATE_DIR}"', mutation)
        acknowledgement = authorizer.index("printf 'FORMAT=1\\nSTATUS=pass", flush)
        self.assertLess(verify, lock)
        self.assertLess(lock, mutation)
        self.assertLess(mutation, flush)
        self.assertLess(flush, acknowledgement)
        self.assertIn("idempotent=1", authorizer)
        self.assertIn("issued_unix > old_issued_unix", authorizer)
        self.assertIn("SESSION_BOUND=1", authorizer)
        self.assertIn("PERMIT_ATTEMPTS=2", driver)
        self.assertIn('"campus-link-fault@${target}" permit < "${permit_envelope}"', driver)
        self.assertIn('cmp -s -- "${permit_ack}" "${permit_expected_ack}"', driver)
        self.assertNotIn('"permit ${run_id}', driver)

    def test_actuator_exact_frames_challenges_and_post_start_restart_pin(self):
        source = self.read("scripts/relay-restart-actuator.sh")
        self.assertIn("[[ $# -eq 0 ]]", source)
        self.assertIn("OPEN_FRAME_BYTES=103", source)
        self.assertIn("RELEASE_FRAME_BYTES=195", source)
        self.assertIn("COMMIT_FRAME_BYTES=194", source)
        self.assertIn("read_exact_frame()", source)
        self.assertIn("dd iflag=fullblock", source)
        self.assertIn("assert_no_buffered_input()", source)
        self.assertIn("assert_exact_eof()", source)
        self.assertIn("STOPPED_CHALLENGE", source)
        self.assertIn("STARTED_CHALLENGE", source)
        self.assertIn("ACTION=relay-restart-release", source)
        self.assertIn("ACTION=relay-restart-commit", source)
        self.assertIn("openssl pkeyutl -verify", source)
        self.assertIn("post_start_restarts=$(read_unit_restarts)", source)
        self.assertIn("(( post_start_restarts == 0 ))", source)
        self.assertIn("active_restarts=$(read_unit_restarts) || return 1", source)
        self.assertIn(
            '[[ ${active_restarts} == "${post_start_restarts}" ]] || return 1',
            source,
        )
        self.assertIn("NRESTARTS_DELTA=0", source)
        self.assertNotIn('== "${before_restarts}"', source)
        open_read = source.index('read_exact_frame "${open_frame}"')
        lock = source.index('exec 9<>"${RUNTIME_DIR}/actuator.lock"')
        consume = source.index('mv -T -- "${EXPECTED_PERMIT}" "${used_marker}"')
        durable = source.index('sync -f -- "${STATE_DIR}"', consume)
        stop = source.index('systemctl_mutate stop "${UNIT}"')
        restart_clock = source.index("restart_started_ms=$(monotonic_ms)")
        self.assertLess(open_read, lock)
        self.assertLess(lock, consume)
        self.assertLess(consume, durable)
        self.assertLess(durable, stop)
        self.assertLess(restart_clock, stop)
        self.assertIn(
            "restart_duration_ms=$((completed_ms - restart_started_ms))", source
        )
        release_read = source.index(
            'read_exact_frame "${phase_frame}" "${RELEASE_FRAME_BYTES}"'
        )
        release_verify = source.index("openssl pkeyutl -verify", release_read)
        final_stopped_check = source.index("assert_no_relay_listeners", release_verify)
        start = source.index('systemctl_mutate start "${UNIT}"', final_stopped_check)
        self.assertLess(release_read, release_verify)
        self.assertLess(release_verify, final_stopped_check)
        self.assertLess(final_stopped_check, start)
        commit_read = source.index(
            'read_exact_frame "${phase_frame}" "${COMMIT_FRAME_BYTES}"'
        )
        commit_verify = source.index("openssl pkeyutl -verify", commit_read)
        eof = source.index('assert_exact_eof "${input_probe}"', commit_verify)
        final_ack = source.index("printf 'STATUS=pass", eof)
        self.assertLess(commit_read, commit_verify)
        self.assertLess(commit_verify, eof)
        self.assertLess(eof, final_ack)
        recovery_cancel = source.index("cancel_recovery", commit_verify)
        revalidate = source.index("assert_started_instance", recovery_cancel)
        monitor_cancel = source.index("cancel_monitor", revalidate)
        ownership_clear = source.index("recovery_armed=0", monitor_cancel)
        self.assertLess(recovery_cancel, revalidate)
        self.assertLess(revalidate, monitor_cancel)
        self.assertLess(monitor_cancel, ownership_clear)
        self.assertLess(ownership_clear, final_ack)
        self.assertNotIn("assert_started_instance || break", source)
        self.assertNotIn("assert_no_relay_listeners || break", source)

    def test_actuator_has_bounded_independent_recovery(self):
        source = self.read("scripts/relay-restart-actuator.sh")
        unit = self.read("systemd/campus-link-relay.service")
        self.assertIn("RECOVERY_DELAY_SECONDS=225", source)
        self.assertIn("RECOVERY_ACTION_TIMEOUT_SECONDS=30", source)
        self.assertIn("TRANSACTION_TIMEOUT_MILLISECONDS=180000", source)
        self.assertIn("systemd-run --quiet --collect", source)
        self.assertIn('--on-active="${RECOVERY_DELAY_SECONDS}s"', source)
        self.assertIn("recovery_armed=1", source)
        self.assertIn("cancel_recovery()", source)
        self.assertIn("delayed recovery remains armed", source)
        self.assertIn(
            "START_INHIBIT=${RUNTIME_DIR}/inhibit-start", source
        )
        self.assertIn(
            '--property="ExecStartPre=/usr/bin/rm -f -- ${START_INHIBIT}"',
            source,
        )
        self.assertIn('-- /usr/bin/systemctl start "${UNIT}"', source)
        self.assertNotIn("ExecStartPost=", source)
        self.assertIn("assert_manifest_bound_start_inhibit()", source)
        self.assertIn(
            'manifest_digest} == "${run_manifest_sha256}"', source
        )
        self.assertIn(
            'fragment} == "${UNIT_FRAGMENT}"', source
        )
        self.assertIn('reload_state} == no', source)
        self.assertIn(
            'dropins=$(systemctl_query show -p DropInPaths --value "${UNIT}")',
            source,
        )
        self.assertIn('[[ -z ${dropins} ]] || return 1', source)
        self.assertNotIn("validate_global_service_dropins()", source)
        self.assertIn("RECOVERY_BASE=campus-link-relay-fault-recovery", source)
        self.assertIn("TimeoutStartSec=15s", unit)
        self.assertIn("TimeoutStopSec=15s", unit)
        self.assertIn(
            "ConditionPathExists=!/run/campus-link-relay-fault/inhibit-start",
            unit,
        )
        self.assertNotIn("systemctl mask", source)

        unit_section, service_section = unit.split("[Service]", 1)
        self.assertEqual(
            unit_section.count(
                "ConditionPathExists=!/run/campus-link-relay-fault/inhibit-start"
            ),
            1,
        )
        self.assertNotIn("ConditionPathExists=", service_section)

        consume = source.index('mv -T -- "${EXPECTED_PERMIT}" "${used_marker}"')
        stale_reject = source.rindex(
            '[[ ! -e ${START_INHIBIT} && ! -L ${START_INHIBIT} ]]',
            0,
            consume,
        )
        manifest_proof = source.rindex(
            "assert_manifest_bound_start_inhibit", 0, consume
        )
        arm = source.index("systemd-run --quiet --collect", manifest_proof)
        recovery_owned = source.rindex("recovery_armed=1", 0, arm)
        recovery_verified = source.index(
            'systemctl_query is-active --quiet "${RECOVERY_BASE}.timer"', arm
        )
        marker_install = source.index(
            'mv -T -- "${inhibit_source}" "${START_INHIBIT}"', recovery_verified
        )
        marker_proof = source.index("assert_start_inhibit", marker_install)
        restart_clock = source.index("restart_started_ms=$(monotonic_ms)", marker_proof)
        stop = source.index('systemctl_mutate stop "${UNIT}"', restart_clock)
        self.assertLess(stale_reject, consume)
        self.assertLess(manifest_proof, consume)
        self.assertLess(recovery_owned, arm)
        self.assertLess(arm, recovery_verified)
        self.assertLess(recovery_verified, marker_install)
        self.assertLess(marker_install, marker_proof)
        self.assertLess(marker_proof, restart_clock)
        self.assertLess(restart_clock, stop)

        release_read = source.index(
            'read_exact_frame "${phase_frame}" "${RELEASE_FRAME_BYTES}"'
        )
        release_verify = source.index("openssl pkeyutl -verify", release_read)
        stopped_monitor_cancel = source.index("cancel_monitor", release_verify)
        repeated_marker_proof = source.index(
            "assert_start_inhibit", stopped_monitor_cancel
        )
        repeated_inactive_proof = source.index(
            'systemctl_query show -p ActiveState --value "${UNIT}"',
            repeated_marker_proof,
        )
        repeated_listener_proof = source.index(
            "assert_no_relay_listeners", repeated_inactive_proof
        )
        marker_remove = source.index(
            "remove_start_inhibit", repeated_listener_proof
        )
        exact_start = source.index(
            'systemctl_mutate start "${UNIT}"', marker_remove
        )
        self.assertLess(release_verify, stopped_monitor_cancel)
        self.assertLess(stopped_monitor_cancel, repeated_marker_proof)
        self.assertLess(repeated_marker_proof, repeated_inactive_proof)
        self.assertLess(repeated_inactive_proof, repeated_listener_proof)
        self.assertLess(repeated_listener_proof, marker_remove)
        self.assertLess(marker_remove, exact_start)

        cleanup = source[source.index("restore_relay() {") : source.index("trap restore_relay EXIT")]
        cleanup_deadline = cleanup.index("operation_deadline_ms=")
        cleanup_monitor = cleanup.index("cancel_monitor")
        cleanup_remove = cleanup.index("remove_start_inhibit")
        cleanup_start = cleanup.index('systemctl_mutate start "${UNIT}"')
        cleanup_active = cleanup.index('systemctl_query is-active --quiet "${UNIT}"')
        cleanup_cancel = cleanup.index("cancel_recovery")
        self.assertLess(cleanup_deadline, cleanup_monitor)
        self.assertLess(cleanup_monitor, cleanup_remove)
        self.assertLess(cleanup_remove, cleanup_start)
        self.assertLess(cleanup_start, cleanup_active)
        self.assertLess(cleanup_active, cleanup_cancel)

    def test_driver_pins_host_key_signs_after_gate_and_owns_process_group(self):
        source = self.read("scripts/relay-restart-driver.sh")
        transport = self.read("scripts/relay-restart-transport.sh")
        for option in (
            "BatchMode=yes",
            "ClearAllForwardings=yes",
            "GlobalKnownHostsFile=/dev/null",
            "IdentitiesOnly=yes",
            "KbdInteractiveAuthentication=no",
            "PasswordAuthentication=no",
            "PermitLocalCommand=no",
            "ProxyCommand=none",
            "RequestTTY=no",
            "StrictHostKeyChecking=yes",
            "UpdateHostKeys=no",
        ):
            self.assertIn(option, transport)
        self.assertIn("HostKeyAlias=campus-link-relay-fault", transport)
        self.assertIn("expected_transport_digest", source)
        self.assertIn("exec setsid --wait", source)
        self.assertIn("process_start_ticks()", source)
        self.assertIn('kill -TERM -- "-${transport_pgid}"', source)
        self.assertIn('kill -KILL -- "-${transport_pgid}"', source)
        self.assertIn('wait "${relay_ssh_pid}"', source)
        self.assertIn('tee -- "${raw_ack}"', transport)
        self.assertIn('cmp -s -- "${raw_ack}" "${ack}"', source)
        self.assertIn("RAW_PHASE_STABILITY_MILLISECONDS=150", source)
        self.assertIn("assert_raw_phase_exact()", source)
        self.assertIn("TRANSPORT_TIMEOUT_SECONDS=260", transport)
        marker = transport.index('> "${pgid_marker}"')
        launch_gate = transport.index("cmp -s --", marker)
        ssh = transport.index('"campus-link-fault@${target}" restart', launch_gate)
        self.assertLess(marker, launch_gate)
        self.assertLess(launch_gate, ssh)
        self.assertIn("transport_group_exists()", source)
        self.assertIn("START\\n", source)
        release_gate = source.index(
            'campus_link_validate_schema "${release_marker}" FORMAT RUN_ID RELEASE'
        )
        release_sign = source.index("ACTION=relay-restart-release", release_gate)
        stopped_raw = source.index(
            'assert_raw_phase_exact "${phase}" "${stopped_deadline_ms}"'
        )
        stopped_marker = source.index('campus_link_atomic_marker "${active_marker}"')
        release_raw = source.index(
            'assert_raw_phase_exact "${phase}" "${release_deadline_ms}"',
            release_gate,
        )
        release_send = source.index('cat -- "${phase_command}" >&7', release_raw)
        started_raw = source.index(
            'assert_raw_phase_exact "${ack}" "${started_deadline_ms}"'
        )
        started_gate = source.index('campus_link_atomic_marker "${started_marker}"')
        commit_gate = source.index(
            'campus_link_validate_schema "${commit_marker}" FORMAT RUN_ID COMMIT',
            started_gate,
        )
        commit_sign = source.index("ACTION=relay-restart-commit", commit_gate)
        commit_raw = source.index(
            'assert_raw_phase_exact "${ack}" "${commit_deadline_ms}"',
            commit_sign,
        )
        commit_send = source.index('cat -- "${phase_command}" >&7', commit_raw)
        close_stdin = source.index("exec 7>&-", commit_sign)
        self.assertLess(stopped_raw, stopped_marker)
        self.assertLess(release_gate, release_sign)
        self.assertLess(release_sign, release_raw)
        self.assertLess(release_raw, release_send)
        self.assertLess(started_raw, started_gate)
        self.assertLess(started_gate, commit_gate)
        self.assertLess(commit_gate, commit_sign)
        self.assertLess(commit_sign, commit_raw)
        self.assertLess(commit_raw, commit_send)
        self.assertLess(commit_sign, close_stdin)

    def test_cleanup_signals_are_identity_bound_and_session_wide(self):
        driver = self.read("scripts/relay-restart-driver.sh")
        transport = self.read("scripts/relay-restart-transport.sh")

        group_signal = driver[
            driver.index("signal_transport_group() {") :
            driver.index("transport_group_exists() {")
        ]
        leader_check = group_signal.index("transport_group_matches")
        self.assertLess(leader_check, group_signal.index('kill -TERM -- "-${transport_pgid}"'))
        self.assertLess(leader_check, group_signal.index('kill -KILL -- "-${transport_pgid}"'))
        group_inspection = driver[
            driver.index("transport_group_exists() {") :
            driver.index("inspect_transport_group() {")
        ]
        self.assertIn("$3 == expected", group_inspection)
        self.assertNotIn("$2 == expected && $3 == expected", group_inspection)

        member_signal = transport[
            transport.index("signal_session_members() {") :
            transport.index("inspect_session_members() {")
        ]
        self.assertIn("ps -eo pid=,sid=", member_signal)
        self.assertIn("session_member_snapshot", member_signal)
        revalidation = member_signal.index("inspect_session_member_identity")
        self.assertLess(revalidation, member_signal.index('kill "-${signal}" "${pid}"'))
        self.assertNotIn("${pgid} == \"${process_pgid}\"", member_signal)
        absence = transport[
            transport.index("inspect_session_members() {") :
            transport.index("wait_child_until() {")
        ]
        self.assertIn("$2 == expected_sid", absence)
        self.assertNotIn("expected_pgid", absence)

    def test_frame_sizes_are_exact(self):
        run_id = "a" * 32
        challenge = "b" * 64
        signature = "A" * 86 + "=="
        self.assertEqual(len(f"open {run_id} {challenge}\n".encode()), 103)
        self.assertEqual(
            len(f"release {run_id} {challenge} {signature}\n".encode()), 195
        )
        self.assertEqual(
            len(f"commit {run_id} {challenge} {signature}\n".encode()), 194
        )

    def test_ack_schema_and_sanitized_result_are_exact(self):
        driver = self.read("scripts/relay-restart-driver.sh")
        fault = self.read("scripts/fault-in-stream.sh")
        helper = self.read("scripts/gate-evidence.sh")
        stopped_schema = (
            "FORMAT ACTION ACTUATOR_SHA256 AUTHORIZED_COMMAND_SHA256 \\\n"
            "  PERMIT_AUTHORIZER_SHA256 RUN_ID BEFORE_INVOCATION_SHA256 \\\n"
            "  HOLD_MILLISECONDS STOPPED STOPPED_CHALLENGE"
        )
        final_schema = (
            "FORMAT ACTION ACTUATOR_SHA256 AUTHORIZED_COMMAND_SHA256 \\\n"
            "  PERMIT_AUTHORIZER_SHA256 RUN_ID BEFORE_INVOCATION_SHA256 \\\n"
            "  HOLD_MILLISECONDS STOPPED STOPPED_CHALLENGE STARTED \\\n"
            "  AFTER_INVOCATION_SHA256 RESTART_DURATION_MS ACTIVE STARTED_CHALLENGE \\\n"
            "  STATUS COMMITTED SIGNED_RELEASE SIGNED_COMMIT FINAL_INVOCATION_SHA256 \\\n"
            "  NRESTARTS_DELTA COMMIT_STABILITY_MILLISECONDS"
        )
        stopped_schema = self.normalized(stopped_schema)
        final_schema = self.normalized(final_schema)
        self.assertIn(stopped_schema, self.normalized(driver))
        self.assertIn(stopped_schema, self.normalized(fault))
        self.assertIn(final_schema, self.normalized(driver))
        self.assertIn(final_schema, self.normalized(fault))
        result_format = re.search(r"printf 'FORMAT=1\\nSTATUS=pass.*?' \\", fault, re.DOTALL)
        self.assertIsNotNone(result_format)
        for secret_field in (
            "BEFORE_INVOCATION_SHA256",
            "AFTER_INVOCATION_SHA256",
            "STOPPED_CHALLENGE",
            "STARTED_CHALLENGE",
            "SESSION_SHA256",
            "PERMIT_SHA256",
        ):
            self.assertNotIn(secret_field, result_format.group(0))
        for value in (
            "RELAY_PROCESS_RESTARTS=1",
            "RELAY_RESTART_ACKS=1",
            "RELAY_RESTART_SIGNED_PERMITS=1",
            "RELAY_RESTART_SESSION_BINDINGS=1",
            "RELAY_RESTART_PERMIT_CONSUMPTIONS=1",
            "RELAY_RESTART_SIGNED_PHASES=2",
            "RELAY_RESTART_COMMITS=1",
            "RELAY_RESTART_NRESTARTS_DELTA=0",
            "RELAY_RESTART_COMMIT_STABILITY_MS=%s",
        ):
            self.assertIn(value, fault)
            self.assertIn(value.split("=")[0], helper)

    def test_restart_is_inside_original_stream_and_cleanup_reaps(self):
        fault = self.read("scripts/fault-in-stream.sh")
        client = fault.index("client \\")
        restart = fault.index('"${RELAY_RESTART_DRIVER}" "${run_id}"', client)
        stopped = fault.index(
            'campus_link_validate_schema "${relay_restart_active}"', restart
        )
        progress = fault.index("during-restart-b-to-a.env", stopped)
        release = fault.index(".relay-restart-release.", progress)
        started = fault.index(
            'campus_link_validate_schema "${relay_restart_started}"', release
        )
        reconnect = fault.index("wait-control-reconnected", started)
        commit = fault.index(".relay-restart-commit.", reconnect)
        reaped = fault.index('wait_relay_restart_until "${relay_restart_outer_deadline_ms}"', commit)
        final_snapshot = fault.index(
            'capture_status "${evidence_dir}/relay-restart-recovered.json"', reaped
        )
        client_completion = fault.index('wait "${client_pid}"', final_snapshot)
        self.assertLess(client, restart)
        self.assertLess(restart, stopped)
        self.assertLess(stopped, progress)
        self.assertLess(progress, release)
        self.assertLess(release, started)
        self.assertLess(started, reconnect)
        self.assertLess(reconnect, commit)
        self.assertLess(commit, reaped)
        self.assertLess(reaped, final_snapshot)
        self.assertLess(final_snapshot, client_completion)
        self.assertIn('kill -TERM "${pids[@]}"', fault)
        self.assertIn('kill -KILL "${pid}"', fault)
        self.assertGreaterEqual(fault.count('wait "${pid}"'), 1)
        self.assertIn('if wait "${server_pid}"', fault)

    def test_nested_restart_deadlines_and_cleanup_margins_are_strict(self):
        actuator = self.read("scripts/relay-restart-actuator.sh")
        driver = self.read("scripts/relay-restart-driver.sh")
        transport = self.read("scripts/relay-restart-transport.sh")
        fault = self.read("scripts/fault-in-stream.sh")

        def value(source: str, name: str) -> int:
            match = re.search(rf"readonly {name}=([0-9]+)", source)
            self.assertIsNotNone(match, name)
            return int(match.group(1))

        remote = value(actuator, "TRANSACTION_TIMEOUT_MILLISECONDS")
        restart = value(actuator, "MAX_RESTART_DURATION_MILLISECONDS")
        operation_sum = value(
            actuator, "RESTART_REMOTE_OPERATION_BUDGET_MILLISECONDS"
        )
        transport_budget = value(driver, "TRANSPORT_BUDGET_MILLISECONDS")
        driver_budget = value(driver, "DRIVER_TIMEOUT_MILLISECONDS")
        fault_budget = value(fault, "RELAY_RESTART_OUTER_BUDGET_MILLISECONDS")
        self.assertLess(operation_sum, restart)
        self.assertLess(remote, transport_budget)
        self.assertEqual(
            transport_budget,
            value(transport, "TRANSPORT_TIMEOUT_SECONDS") * 1000,
        )
        self.assertLess(transport_budget, driver_budget)
        self.assertLess(driver_budget, fault_budget)
        self.assertLess(
            value(driver, "DRIVER_CLEANUP_BUDGET_MILLISECONDS"),
            value(fault, "RELAY_RESTART_DRIVER_CLEANUP_MILLISECONDS"),
        )
        self.assertLess(
            remote + value(actuator, "ACTUATOR_CLEANUP_TIMEOUT_MILLISECONDS"),
            value(actuator, "RECOVERY_DELAY_SECONDS") * 1000,
        )
        self.assertLess(
            value(actuator, "RECOVERY_DELAY_SECONDS") * 1000
            + value(actuator, "RECOVERY_ACTION_TIMEOUT_SECONDS") * 1000,
            transport_budget,
        )
        cancel_monitor = actuator[
            actuator.index("cancel_monitor() {") : actuator.index("cancel_recovery() {")
        ]
        self.assertIn('wait -n "${monitor_pid}" "${watchdog_pid}"', cancel_monitor)
        self.assertIn('kill -KILL "${monitor_pid}"', cancel_monitor)
        self.assertIn(
            "operation_deadline_ms=${restart_deadline_ms}", actuator
        )
        self.assertIn(
            "operation_deadline_ms=${transaction_deadline_ms}", actuator
        )
        self.assertEqual(value(actuator, "QUERY_TIMEOUT_MILLISECONDS"), 2000)
        self.assertEqual(value(actuator, "SOCKET_QUERY_TIMEOUT_MILLISECONDS"), 1000)
        self.assertEqual(
            value(actuator, "RESTART_REMOTE_OPERATION_BUDGET_MILLISECONDS"),
            101150,
        )
        self.assertIn(
            'run_bounded "${operation_deadline_ms}" "${CRYPTO_TIMEOUT_MILLISECONDS}"',
            actuator,
        )
        self.assertIn(
            'value=$(run_bounded "${operation_deadline_ms}"', actuator
        )

    def test_install_rollback_fingerprint_and_deploy_cover_all_authority(self):
        edge_install = self.read("scripts/install-edge-lab.sh")
        edge_rollback = self.read("scripts/rollback-edge.sh")
        relay_install = self.read("scripts/install-relay.sh")
        relay_rollback = self.read("scripts/rollback-relay.sh")
        helper = self.read("scripts/gate-evidence.sh")
        deploy = (ROOT.parent / "scripts" / "Deploy-CampusLink.ps1").read_text(
            encoding="utf-8"
        )
        for path in (
            "/usr/local/libexec/campus-link-relay-restart-driver",
            "/usr/local/libexec/campus-link-relay-restart-transport",
        ):
            self.assertIn(path, edge_install)
            self.assertIn(path, edge_rollback)
            self.assertIn(path, helper)
        for path in (
            "/etc/campus-link/relay-fault/id_ed25519",
            "/etc/campus-link/relay-fault/permit_ed25519.pem",
            "/etc/campus-link/relay-fault/permit_ed25519.pub.pem",
            "/etc/campus-link/relay-fault/known_hosts",
            "/etc/campus-link/relay-fault/target",
        ):
            self.assertIn(path, helper)
        for destination in (
            "/usr/local/libexec/campus-link-provision-relay-fault-access",
            "/usr/local/libexec/campus-link-relay-restart-actuator",
            "/usr/local/libexec/campus-link-relay-restart-authorized",
            "/usr/local/libexec/campus-link-relay-restart-permit-authorize",
        ):
            self.assertIn(destination, relay_install)
            self.assertIn(destination, relay_rollback)
        for artifact in ("relay-restart-driver", "relay-restart-transport"):
            self.assertIn(
                f"verify scripts/{artifact}.sh /usr/local/libexec/campus-link-{artifact}",
                deploy,
            )
        for artifact in (
            "relay-restart-actuator.sh",
            "relay-restart-authorized.sh",
            "relay-restart-permit-authorize.sh",
        ):
            self.assertIn(f"verify scripts/{artifact} {artifact}", deploy)
        for source in (relay_install, relay_rollback):
            self.assertIn(
                "START_INHIBIT=${FAULT_RUNTIME_DIR}/inhibit-start", source
            )
            self.assertIn(
                "[[ ! -e ${START_INHIBIT} && ! -L ${START_INHIBIT} ]]",
                source,
            )
            self.assertIn(
                "RECOVERY_BASE=campus-link-relay-fault-recovery", source
            )
            self.assertIn("assert_no_pending_recovery", source)
            self.assertIn(
                '[[ ${load_state} == not-found ]] || return 1', source
            )


if __name__ == "__main__":
    unittest.main()
