#!/usr/bin/env python3
"""Static fail-closed restart-cascade contract for accelerated recovery."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class EdgeRecoveryRestartContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "scripts/test-edge-recovery.sh").read_text(encoding="utf-8")
        cls.accelerated = (ROOT / "scripts/accelerated-fault-soak.sh").read_text(
            encoding="utf-8"
        )
        cls.integration = (
            ROOT / "ACCELERATED-STREAM-GATE-INTEGRATION.md"
        ).read_text(encoding="utf-8")
        cls.protocol = (ROOT / "PROTOCOL.md").read_text(encoding="utf-8")

    def test_protocol_pins_one_target_restart_and_unchanged_survivor(self) -> None:
        normalized = " ".join(self.protocol.split())
        for phrase in (
            "Before every accelerated edge-recovery kill",
            "Every recovery poll",
            "two-second post-health guard",
            "survivor's two values remain exactly unchanged",
            "either the captured value or exactly that value plus one",
            "counter reset or decrement, overflow, or larger jump fails closed",
            "one distinct canonical `InvocationID`",
        ):
            self.assertIn(phrase, normalized)

    def test_one_property_read_validates_canonical_identity_and_counter(self) -> None:
        read_state = self.script[
            self.script.index("read_unit_state() {") :
            self.script.index("require_active_identity() {")
        ]
        self.assertIn(
            "--property=ActiveState --property=InvocationID --property=NRestarts",
            read_state,
        )
        self.assertIn("seen_active == 1 && seen_invocation == 1 && seen_restarts == 1", read_state)
        self.assertIn("^[0-9a-f]{32}$", read_state)
        self.assertIn("^(0|[1-9][0-9]{0,14})$", read_state)
        self.assertIn("duplicate InvocationID", read_state)
        self.assertIn("unexpected supervised property", read_state)

    def test_each_kill_snapshots_both_units_before_signal(self) -> None:
        trial = self.script[
            self.script.index("run_trial() {") : self.script.index("for trial in")
        ]
        kill = trial.index('systemctl kill --kill-whom=main --signal=KILL "${unit}"')
        before_kill = trial[:kill]
        self.assertIn('require_active_identity "${unit}"', before_kill)
        self.assertIn('require_active_identity "${survivor_unit}"', before_kill)
        for snapshot in (
            "target_before_invocation=${UNIT_INVOCATION_ID}",
            "target_before_restarts=${UNIT_RESTART_COUNT}",
            "survivor_invocation=${UNIT_INVOCATION_ID}",
            "survivor_restarts=${UNIT_RESTART_COUNT}",
        ):
            self.assertIn(snapshot, before_kill)
        self.assertIn("target_expected_restarts=$((target_before_restarts + 1))", before_kill)

    def test_every_poll_checks_survivor_and_bounded_target_transition(self) -> None:
        trial = self.script[
            self.script.index("run_trial() {") : self.script.index("for trial in")
        ]
        poll = trial.index("while ((", trial.index("systemctl kill"))
        first_health = trial.index('if [[ -n ${target_invocation} ]]', poll)
        poll_prefix = trial[poll:first_health]
        self.assertIn('assert_survivor_state "${survivor_unit}"', poll_prefix)
        self.assertIn('observe_target_restart "${unit}"', poll_prefix)
        self.assertIn("target_incremented=${OBSERVED_TARGET_INCREMENTED}", poll_prefix)

        observer = self.script[
            self.script.index("observe_target_restart() {") :
            self.script.index("assert_target_pinned() {")
        ]
        self.assertIn('"${before_restarts}")', observer)
        self.assertIn('"${expected_restarts}")', observer)
        self.assertIn("increment_seen == 0", observer)
        self.assertIn("restart count reset, overflowed, or jumped", observer)
        self.assertIn("replacement invocation changed again", observer)

    def test_health_requires_replacement_then_continuously_guards_both_units(self) -> None:
        trial = self.script[
            self.script.index("run_trial() {") : self.script.index("for trial in")
        ]
        health = trial.index('if [[ -n ${target_invocation} ]]')
        guard = trial.index("guard_deadline=$((finished + POST_HEALTH_GUARD_MS))", health)
        result = trial.index(
            "printf '%s\\t%s\\t%s\\t%s\\t1\\t0\\t%s", guard
        )
        guarded = trial[guard:result]
        self.assertIn("POST_HEALTH_GUARD_MS=2000", self.script)
        self.assertGreaterEqual(guarded.count('assert_survivor_state "${survivor_unit}"'), 2)
        self.assertGreaterEqual(guarded.count('assert_target_pinned "${unit}"'), 2)
        self.assertIn('kill_switch_active "${namespace}"', guarded)
        self.assertIn('health "${namespace/campus/oslab}"', guarded)
        self.assertGreaterEqual(guarded.count("assert_stream_live"), 2)
        self.assertIn("finish_stream_transaction", guarded)
        self.assertNotIn("sleep 2", trial)

    def test_each_direction_names_the_other_edge_as_survivor(self) -> None:
        self.assertIn(
            "run_trial site-a campus-link-edge-a.service campus-link-edge-b.service",
            self.script,
        )
        self.assertIn(
            "run_trial site-b campus-link-edge-b.service campus-link-edge-a.service",
            self.script,
        )

    def test_one_preestablished_non_reconnecting_stream_owns_each_kill(self) -> None:
        trial = self.script[
            self.script.index("run_trial() {") : self.script.index("for trial in")
        ]
        prepare = trial.index('start_stream_transaction "${stream_index}"')
        state_snapshot = trial.index('require_active_identity "${unit}"')
        signal = trial.index('systemctl kill --kill-whom=main --signal=KILL "${unit}"')
        self.assertLess(prepare, state_snapshot)
        self.assertLess(state_snapshot, signal)
        starter = self.script[
            self.script.index("start_stream_transaction() {") :
            self.script.index("finish_stream_transaction() {")
        ]
        self.assertIn("serve-once", starter)
        self.assertIn("continuous-client", starter)
        self.assertIn('--stop-file "${TRIAL_STOP_FILE}"', starter)
        self.assertIn("TRIAL_CLIENT_INSTANCE=$(process_instance", starter)
        self.assertIn("TRIAL_SERVER_INSTANCE=$(process_instance", starter)
        self.assertIn("STREAM_RECORDS > 0", starter)
        identity = self.script[
            self.script.index("process_established_socket() {") :
            self.script.index("assert_stream_live() {")
        ]
        self.assertIn("${#sockets[@]} == 1", identity)
        self.assertIn('$4 == "01" && $10 == inode', identity)
        self.assertIn("first_socket", identity)
        self.assertIn("second_socket", identity)

    def test_every_restart_poll_pins_process_connection_and_progress_identity(self) -> None:
        trial = self.script[
            self.script.index("run_trial() {") : self.script.index("for trial in")
        ]
        signal = trial.index("systemctl kill")
        poll = trial.index("while ((", signal)
        self.assertIn("assert_stream_live", trial[signal:poll])
        self.assertIn("assert_stream_live", trial[poll:])
        continuity = self.script[
            self.script.index("assert_stream_live() {") :
            self.script.index("start_stream_transaction() {")
        ]
        for requirement in (
            'kill -0 "${TRIAL_CLIENT_PID}" "${TRIAL_SERVER_PID}"',
            '${current_client_instance} == "${TRIAL_CLIENT_INSTANCE}"',
            '${current_server_instance} == "${TRIAL_SERVER_INSTANCE}"',
            '${STREAM_STARTED_NS} == "${TRIAL_STARTED_NS}"',
            '${STREAM_FIRST_SEND} == "${TRIAL_FIRST_SEND}"',
            '${STREAM_FIRST_RECEIVE} == "${TRIAL_FIRST_RECEIVE}"',
            "STREAM_RECORDS >= TRIAL_RECORDS",
            "STREAM_SENT >= TRIAL_SENT",
            "STREAM_RECEIVED >= TRIAL_RECEIVED",
            "stream transcript changed without a complete record",
            "stream record advanced without digest progress",
        ):
            self.assertIn(requirement, continuity)

    def test_recovery_requires_later_bidirectional_record_and_digest(self) -> None:
        trial = self.script[
            self.script.index("run_trial() {") : self.script.index("for trial in")
        ]
        recovery = trial[
            trial.index("target_incremented=${OBSERVED_TARGET_INCREMENTED}") :
        ]
        self.assertIn("TRIAL_RESTART_BASELINE_SET == 1", recovery)
        self.assertIn("TRIAL_RECORDS > TRIAL_RESTART_RECORDS", recovery)
        self.assertIn("TRIAL_SENT > TRIAL_RESTART_SENT", recovery)
        self.assertIn("TRIAL_RECEIVED > TRIAL_RESTART_RECEIVED", recovery)
        self.assertIn(
            '${TRIAL_TRANSCRIPT_SHA256} != "${TRIAL_RESTART_TRANSCRIPT_SHA256}"',
            recovery,
        )
        baseline = recovery.index("TRIAL_RESTART_RECORDS=${TRIAL_RECORDS}")
        health = recovery.index('health "${namespace/campus/oslab}"')
        self.assertLess(baseline, health)
        self.assertLess(
            recovery.index("post_restart_progress_checks="),
            recovery.index("finish_stream_transaction"),
        )
        self.assertIn("TRIAL_POST_RECORDS=${TRIAL_RECORDS}", recovery)
        self.assertIn(
            "TRIAL_POST_TRANSCRIPT_SHA256=${TRIAL_TRANSCRIPT_SHA256}", recovery
        )

    def test_finalization_is_record_boundary_accounted_and_no_reconnect(self) -> None:
        finalizer = self.script[
            self.script.index("finish_stream_transaction() {") :
            self.script.index("cleanup() {")
        ]
        self.assertIn("printf 'CAMPUS_LINK_STOP=1\\n'", finalizer)
        self.assertIn("STREAM_STATE} == pass", finalizer)
        self.assertIn("STREAM_RECORDS * STREAM_RECORD_BYTES", finalizer)
        self.assertIn("PASS connections=1 reconnects=0", finalizer)
        self.assertIn('"${TRIAL_PRE_TRANSCRIPT_SHA256}"', finalizer)
        self.assertIn('"${TRIAL_RESTART_TRANSCRIPT_SHA256}"', finalizer)
        self.assertIn('"${TRIAL_POST_TRANSCRIPT_SHA256}"', finalizer)
        self.assertNotRegex(finalizer, r"\bconnect\b|\baccept\b")

    def test_integration_contract_declares_exact_sanitized_marker(self) -> None:
        self.assertIn("No fresh\nhealth connection", self.integration)
        self.assertIn("at most 30,000 ms", self.integration)
        for key in (
            "MAX_RECOVERY_MS",
            "STREAM_RECORD_BYTES",
            "STREAM_PROGRESS_TIMEOUT_MS",
            "TCP_CONNECTIONS",
            "TCP_RECONNECTS",
            "FULL_DUPLEX_RECORDS",
            "STREAM_BYTES_A_TO_B",
            "STREAM_BYTES_B_TO_A",
            "PRE_RESTART_PROGRESS_CHECKS",
            "REPLACEMENT_ACTIVE_CHECKPOINTS",
            "POST_RESTART_PROGRESS_CHECKS",
            "STREAM_SURVIVAL_CHECKS",
            "MAX_PROGRESS_GAP_A_TO_B_MS",
            "MAX_PROGRESS_GAP_B_TO_A_MS",
            "STREAM_DIGEST_DIRECTIONS",
            "STREAM_TRANSCRIPT_SHA256",
        ):
            self.assertIn(f"{key}=", self.integration)

    def test_accelerated_runner_validates_every_cycle_before_aggregation(self) -> None:
        self.assertIn('cycle_output=$("${EDGE_RECOVERY}" "${REPO_ROOT}" full)', self.accelerated)
        self.assertIn("[[ ${cycle_output} != *$'\\n'* ]]", self.accelerated)
        self.assertIn("[[ ${pass} == PASS", self.accelerated)
        for relation in (
            "cycle_trials == 60",
            "cycle_connections == cycle_trials",
            "cycle_reconnects == 0",
            "cycle_records >= cycle_trials * 2",
            "cycle_a_to_b == cycle_records * STREAM_RECORD_BYTES",
            "cycle_b_to_a == cycle_records * STREAM_RECORD_BYTES",
            "cycle_pre == cycle_trials",
            "cycle_replacement == cycle_trials",
            "cycle_post == cycle_trials",
            "cycle_recovery <= STREAM_PROGRESS_TIMEOUT_MS",
            "cycle_directions == cycle_trials * 2",
        ):
            self.assertIn(relation, self.accelerated)
        self.assertNotIn("trials=$((trials + 60))", self.accelerated)

    def test_accelerated_marker_contains_only_sanitized_stream_aggregates(self) -> None:
        start = self.accelerated.index("printf 'FORMAT=1")
        end = self.accelerated.index("campus_link_validate_gate_marker", start)
        marker = self.accelerated[start:end]
        for key in (
            "MAX_RECOVERY_MS",
            "STREAM_RECORD_BYTES",
            "STREAM_PROGRESS_TIMEOUT_MS",
            "TCP_CONNECTIONS",
            "TCP_RECONNECTS",
            "FULL_DUPLEX_RECORDS",
            "STREAM_BYTES_A_TO_B",
            "STREAM_BYTES_B_TO_A",
            "PRE_RESTART_PROGRESS_CHECKS",
            "REPLACEMENT_ACTIVE_CHECKPOINTS",
            "POST_RESTART_PROGRESS_CHECKS",
            "STREAM_SURVIVAL_CHECKS",
            "MAX_PROGRESS_GAP_A_TO_B_MS",
            "MAX_PROGRESS_GAP_B_TO_A_MS",
            "STREAM_DIGEST_DIRECTIONS",
            "STREAM_TRANSCRIPT_SHA256",
        ):
            self.assertIn(f"{key}=", marker)
        self.assertNotRegex(
            marker,
            r"(?:ADDRESS|SOURCE|DESTINATION|PORT|PID|INVOCATION|SOCKET|KEY|TOKEN)=",
        )


if __name__ == "__main__":
    unittest.main()
