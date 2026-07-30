#!/usr/bin/env python3
"""Fail-closed, sanitized evidence for the campus-link NAT-rebinding gate."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from pathlib import Path

import status_gate
import stream_transport


RECORD_BYTES = 1_048_576
RECOVERY_TIMEOUT_MS = 25_000
MAX_GATE_INTERVAL_NS = 5 * 60 * 1_000_000_000
MAX_UINT64 = (1 << 64) - 1
STATUS_LABELS = (
    "before",
    "site_a_forced",
    "site_a_restored",
    "site_b_forced",
    "site_b_restored",
)
PROGRESS_LABELS = (*STATUS_LABELS, "final")
PROGRESS_KEYS = {
    "format",
    "state",
    "started_monotonic_ns",
    "updated_monotonic_ns",
    "tcp_connections",
    "tcp_reconnects",
    "records_completed",
    "sent_bytes",
    "received_bytes",
    "first_send_sequence",
    "last_send_sequence",
    "first_receive_sequence",
    "last_receive_sequence",
    "max_send_progress_gap_ms",
    "max_receive_progress_gap_ms",
    "transcript_sha256",
}
EVIDENCE_KEYS = (
    "MATCHED_DIRECT_EPOCH_CHECKS",
    "MIGRATED_PATHS",
    "REESTABLISHED_PATHS",
    "HIGHER_DIRECT_INSTANCE_EDGE_CHECKS",
    "PROCESS_CONTINUITY_CHECKS",
    "TCP_CONNECTIONS",
    "TCP_RECONNECTS",
    "STREAM_RECORD_BYTES",
    "FULL_DUPLEX_RECORDS",
    "STREAM_BYTES_A_TO_B",
    "STREAM_BYTES_B_TO_A",
    "FIRST_A_TO_B_SEQUENCE",
    "LAST_A_TO_B_SEQUENCE",
    "FIRST_B_TO_A_SEQUENCE",
    "LAST_B_TO_A_SEQUENCE",
    "STREAM_TRANSCRIPT_SHA256",
    "MAX_PROGRESS_GAP_A_TO_B_MS",
    "MAX_PROGRESS_GAP_B_TO_A_MS",
    "EDGE_A_DIRECT_SENT_DELTA",
    "EDGE_A_DIRECT_RECEIVED_DELTA",
    "EDGE_A_DIRECT_PROGRESS_DELTA",
    "EDGE_A_RELAY_SENT_DELTA",
    "EDGE_A_RELAY_RECEIVED_DELTA",
    "EDGE_B_DIRECT_SENT_DELTA",
    "EDGE_B_DIRECT_RECEIVED_DELTA",
    "EDGE_B_DIRECT_PROGRESS_DELTA",
    "EDGE_B_RELAY_SENT_DELTA",
    "EDGE_B_RELAY_RECEIVED_DELTA",
    "RAW_RELAY_PACKET_LIMIT_PER_SITE",
    "RAW_RELAY_BYTE_LIMIT_PER_SITE",
    "RAW_RELAY_SITE_A_DELTA",
    "RAW_RELAY_SITE_A_BYTES_DELTA",
    "RAW_RELAY_SITE_B_DELTA",
    "RAW_RELAY_SITE_B_BYTES_DELTA",
)


class GateError(RuntimeError):
    pass


def _uint(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_UINT64:
        raise GateError(f"invalid {label}")
    return value


def validate_progress(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != PROGRESS_KEYS:
        raise GateError("continuous progress schema is invalid")
    if value["format"] != 1 or type(value["format"]) is not int:
        raise GateError("continuous progress format is invalid")
    if value["state"] not in {"running", "pass"}:
        raise GateError("continuous progress state is invalid")
    for key in PROGRESS_KEYS - {"state", "transcript_sha256"}:
        _uint(value[key], f"continuous progress {key}")
    if (
        value["started_monotonic_ns"] == 0
        or value["updated_monotonic_ns"] < value["started_monotonic_ns"]
        or value["tcp_connections"] != 1
        or value["tcp_reconnects"] != 0
    ):
        raise GateError("continuous connection identity is invalid")
    records = value["records_completed"]
    for direction in ("send", "receive"):
        first = value[f"first_{direction}_sequence"]
        last = value[f"last_{direction}_sequence"]
        if records > MAX_UINT64 - first:
            raise GateError("continuous sequence range overflow")
        if last != first + max(0, records - 1):
            raise GateError("continuous sequence is not contiguous")
    transcript = value["transcript_sha256"]
    if (
        not isinstance(transcript, str)
        or len(transcript) != 64
        or any(character not in "0123456789abcdef" for character in transcript)
    ):
        raise GateError("continuous transcript is invalid")
    if value["state"] == "pass" and (
        records == 0 or value["sent_bytes"] == 0 or value["received_bytes"] == 0
    ):
        raise GateError("continuous pass is empty")
    return value


def _same_stream(prior: dict, current: dict, *, require_advance: bool) -> None:
    for key in (
        "started_monotonic_ns",
        "tcp_connections",
        "tcp_reconnects",
        "first_send_sequence",
        "first_receive_sequence",
    ):
        if current[key] != prior[key]:
            raise GateError("continuous stream identity changed")
    for key in (
        "updated_monotonic_ns",
        "records_completed",
        "sent_bytes",
        "received_bytes",
        "last_send_sequence",
        "last_receive_sequence",
        "max_send_progress_gap_ms",
        "max_receive_progress_gap_ms",
    ):
        if current[key] < prior[key]:
            raise GateError("continuous stream evidence regressed")
    if require_advance and not (
        current["records_completed"] > prior["records_completed"]
        and current["sent_bytes"] > prior["sent_bytes"]
        and current["received_bytes"] > prior["received_bytes"]
        and current["transcript_sha256"] != prior["transcript_sha256"]
    ):
        raise GateError("continuous full-duplex record did not advance")


def _write_checkpoint(path: Path, value: dict) -> None:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as target:
            target.write(encoded)
            target.flush()
            os.fsync(target.fileno())
    finally:
        os.close(descriptor)


def wait_checkpoint(
    source: Path,
    output: Path,
    *,
    prior: dict | None,
    required_state: str,
    timeout_seconds: float,
) -> dict:
    if (
        required_state not in {"running", "pass"}
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 60
    ):
        raise GateError("invalid progress wait bound")
    if output.exists() or output.is_symlink():
        raise GateError("progress checkpoint already exists")
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            value = validate_progress(stream_transport.read_continuous_progress(source))
        except FileNotFoundError:
            if prior is not None:
                raise GateError("continuous progress disappeared")
            value = None
        except (OSError, ValueError, stream_transport.ProgressEvidenceError) as error:
            raise GateError("continuous progress is invalid") from error
        if value is not None:
            if prior is None:
                if value["state"] != "running":
                    raise GateError("continuous stream ended before the first checkpoint")
                if value["records_completed"] > 0:
                    _write_checkpoint(output, value)
                    return value
            else:
                _same_stream(prior, value, require_advance=False)
                if value["state"] == required_state:
                    try:
                        _same_stream(prior, value, require_advance=True)
                    except GateError:
                        pass
                    else:
                        _write_checkpoint(output, value)
                        return value
                elif value["state"] == "pass":
                    raise GateError("continuous stream ended before the requested boundary")
        if time.monotonic() >= deadline:
            raise GateError("continuous stream progress deadline exceeded")
        time.sleep(0.05)


def _validate_status_sequence(statuses: list[dict]) -> tuple[int, int, int]:
    for snapshot in statuses:
        try:
            status_gate._validate_snapshot(snapshot)
        except (status_gate.GateError, KeyError, TypeError, ValueError) as error:
            raise GateError("direct status evidence is invalid") from error
    boot = statuses[0]["boot_id_sha256"]
    timestamps = [snapshot["monotonic_ns"] for snapshot in statuses]
    if any(snapshot["boot_id_sha256"] != boot for snapshot in statuses):
        raise GateError("direct status snapshots span different boots")
    if any(later <= earlier for earlier, later in zip(timestamps, timestamps[1:])):
        raise GateError("direct status snapshot order is invalid")
    duration_ns = timestamps[-1] - timestamps[0]
    if duration_ns <= 0 or duration_ns > MAX_GATE_INTERVAL_NS:
        raise GateError("NAT-rebinding evidence interval is outside bounds")

    migrated = 0
    reestablished = 0
    baseline = statuses[0]
    for label in ("edge_a", "edge_b"):
        first = baseline[label]
        for snapshot in statuses:
            edge = snapshot[label]
            if (
                edge["selected"] != "direct"
                or edge["direct_healthy"] is not True
                or edge["direct_required"] is not True
                or edge["control_session"] != first["control_session"]
                or edge["control_identity"] != first["control_identity"]
                or edge["data_identity"]["local"] != first["data_identity"]["local"]
                or edge["data_identity"]["peer"] != first["data_identity"]["peer"]
            ):
                raise GateError("authenticated direct boundary changed identity")

    for prior_snapshot, current_snapshot in zip(statuses, statuses[1:]):
        prior_instances = []
        current_instances = []
        for label in ("edge_a", "edge_b"):
            prior = prior_snapshot[label]
            current = current_snapshot[label]
            prior_instances.append(prior["direct_instance"])
            current_instances.append(current["direct_instance"])
            if current["direct_epoch"] < prior["direct_epoch"]:
                raise GateError("direct epoch regressed")
            if current["data_identity"]["direct_epoch"] != current["direct_epoch"]:
                raise GateError("direct data identity is not epoch-bound")
            for counter in ("direct_sent", "direct_received", "direct_progress"):
                if current[counter] <= prior[counter]:
                    raise GateError("direct path did not carry the continued stream")
            for counter in (
                "relay_sent",
                "relay_received",
                "fallbacks",
                "queue_drops",
                "invalid_packets",
                "duplicate_packets",
                "dropped",
                "relay_dropped",
                "relay_dropped_bytes",
            ):
                if current[counter] != prior[counter]:
                    raise GateError("direct-only or drop counter changed")
            if current["telemetry_sequence"] < prior["telemetry_sequence"]:
                raise GateError("authenticated relay telemetry regressed")
            for counter in ("relay_forwarded", "relay_forwarded_bytes"):
                for site in ("site-a", "site-b"):
                    if current[counter][site] < prior[counter][site]:
                        raise GateError("authenticated relay forwarding counter regressed")

        same_instances = all(
            current == prior for prior, current in zip(prior_instances, current_instances)
        )
        higher_instances = all(
            current > prior for prior, current in zip(prior_instances, current_instances)
        )
        prior_epoch = prior_snapshot["edge_a"]["direct_epoch"]
        current_epoch = current_snapshot["edge_a"]["direct_epoch"]
        if same_instances and current_epoch == prior_epoch:
            migrated += 1
        elif higher_instances:
            reestablished += 1
        else:
            raise GateError("direct path transition was mixed or unauthenticated")
    return duration_ns, migrated, reestablished


def verify_evidence(
    statuses: list[dict],
    progresses: list[dict],
    *,
    process_continuity_checks: int,
    now_monotonic_ns: int | None = None,
) -> dict[str, int | str]:
    if len(statuses) != len(STATUS_LABELS) or len(progresses) != len(PROGRESS_LABELS):
        raise GateError("NAT-rebinding evidence boundary count is invalid")
    if process_continuity_checks != 12:
        raise GateError("process continuity evidence count is invalid")
    duration_ns, migrated, reestablished = _validate_status_sequence(statuses)
    if migrated + reestablished != 4:
        raise GateError("not every mapping transition was classified")
    if now_monotonic_ns is not None:
        if type(now_monotonic_ns) is not int or now_monotonic_ns <= 0:
            raise GateError("invalid final evidence time")
        age = now_monotonic_ns - statuses[-1]["monotonic_ns"]
        if age < -2_000_000_000 or age > 60_000_000_000:
            raise GateError("final direct status snapshot is not fresh")

    normalized_progress = [validate_progress(item) for item in progresses]
    if any(item["state"] != "running" for item in normalized_progress[:-1]):
        raise GateError("a fault boundary did not retain the running stream")
    if normalized_progress[-1]["state"] != "pass":
        raise GateError("continuous stream did not close cleanly")
    for prior, current in zip(normalized_progress, normalized_progress[1:]):
        _same_stream(prior, current, require_advance=True)
    for snapshot, progress in zip(statuses, normalized_progress[:-1]):
        if progress["updated_monotonic_ns"] > snapshot["monotonic_ns"]:
            raise GateError("stream checkpoint is not bound to its direct status boundary")
    if normalized_progress[0]["started_monotonic_ns"] >= statuses[0]["monotonic_ns"]:
        raise GateError("continuous stream did not precede the first direct snapshot")

    final_progress = normalized_progress[-1]
    records = final_progress["records_completed"]
    if records < 6 or records > MAX_UINT64 // RECORD_BYTES:
        raise GateError("continuous record count is outside bounds")
    expected_bytes = records * RECORD_BYTES
    if (
        final_progress["sent_bytes"] != expected_bytes
        or final_progress["received_bytes"] != expected_bytes
    ):
        raise GateError("continuous stream byte accounting is invalid")
    if (
        final_progress["max_send_progress_gap_ms"] > RECOVERY_TIMEOUT_MS
        or final_progress["max_receive_progress_gap_ms"] > RECOVERY_TIMEOUT_MS
    ):
        raise GateError("continuous stream recovery exceeded the outage bound")

    first_status = statuses[0]
    final_status = statuses[-1]
    evidence: dict[str, int | str] = {
        "MATCHED_DIRECT_EPOCH_CHECKS": 4,
        "MIGRATED_PATHS": migrated,
        "REESTABLISHED_PATHS": reestablished,
        "HIGHER_DIRECT_INSTANCE_EDGE_CHECKS": reestablished * 2,
        "PROCESS_CONTINUITY_CHECKS": process_continuity_checks,
        "TCP_CONNECTIONS": final_progress["tcp_connections"],
        "TCP_RECONNECTS": final_progress["tcp_reconnects"],
        "STREAM_RECORD_BYTES": RECORD_BYTES,
        "FULL_DUPLEX_RECORDS": records,
        "STREAM_BYTES_A_TO_B": final_progress["sent_bytes"],
        "STREAM_BYTES_B_TO_A": final_progress["received_bytes"],
        "FIRST_A_TO_B_SEQUENCE": final_progress["first_send_sequence"],
        "LAST_A_TO_B_SEQUENCE": final_progress["last_send_sequence"],
        "FIRST_B_TO_A_SEQUENCE": final_progress["first_receive_sequence"],
        "LAST_B_TO_A_SEQUENCE": final_progress["last_receive_sequence"],
        "STREAM_TRANSCRIPT_SHA256": final_progress["transcript_sha256"],
        "MAX_PROGRESS_GAP_A_TO_B_MS": final_progress["max_send_progress_gap_ms"],
        "MAX_PROGRESS_GAP_B_TO_A_MS": final_progress["max_receive_progress_gap_ms"],
    }
    for label in ("edge_a", "edge_b"):
        prefix = label.upper()
        for counter in ("direct_sent", "direct_received", "direct_progress"):
            delta = final_status[label][counter] - first_status[label][counter]
            if delta <= 0:
                raise GateError("final direct counter did not advance")
            evidence[f"{prefix}_{counter.upper()}_DELTA"] = delta
        for counter in ("relay_sent", "relay_received"):
            delta = final_status[label][counter] - first_status[label][counter]
            if delta != 0:
                raise GateError("relay application counter changed")
            evidence[f"{prefix}_{counter.upper()}_DELTA"] = delta

    duration_ms = (duration_ns + 999_999) // 1_000_000
    packet_limit, byte_limit = status_gate._raw_relay_limits(duration_ms, 1.0)
    evidence["RAW_RELAY_PACKET_LIMIT_PER_SITE"] = packet_limit
    evidence["RAW_RELAY_BYTE_LIMIT_PER_SITE"] = byte_limit
    for site in ("site-a", "site-b"):
        prior_packets = min(
            first_status[label]["relay_forwarded"][site]
            for label in ("edge_a", "edge_b")
        )
        current_packets = max(
            final_status[label]["relay_forwarded"][site]
            for label in ("edge_a", "edge_b")
        )
        prior_bytes = min(
            first_status[label]["relay_forwarded_bytes"][site]
            for label in ("edge_a", "edge_b")
        )
        current_bytes = max(
            final_status[label]["relay_forwarded_bytes"][site]
            for label in ("edge_a", "edge_b")
        )
        packet_delta = current_packets - prior_packets
        byte_delta = current_bytes - prior_bytes
        if not 0 <= packet_delta <= packet_limit or not 0 <= byte_delta <= byte_limit:
            raise GateError("raw relay forwarding exceeded the warm-association bound")
        key_site = site.upper().replace("-", "_")
        evidence[f"RAW_RELAY_{key_site}_DELTA"] = packet_delta
        evidence[f"RAW_RELAY_{key_site}_BYTES_DELTA"] = byte_delta
    if tuple(evidence) != EVIDENCE_KEYS:
        raise GateError("internal NAT-rebinding evidence schema mismatch")
    return evidence


def _read_progress(path: Path) -> dict:
    try:
        return validate_progress(stream_transport.read_continuous_progress(path))
    except (OSError, ValueError, stream_transport.ProgressEvidenceError) as error:
        raise GateError("continuous checkpoint is invalid") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    for command, state in (("wait-running", "running"), ("wait-pass", "pass")):
        wait = commands.add_parser(command)
        wait.add_argument("--progress", required=True, type=Path)
        wait.add_argument("--output", required=True, type=Path)
        wait.add_argument("--after", type=Path)
        wait.add_argument("--timeout-seconds", required=True, type=float)
        wait.set_defaults(required_state=state)
    verify = commands.add_parser("verify")
    for label in STATUS_LABELS:
        verify.add_argument(f"--status-{label.replace('_', '-')}", required=True, type=Path)
    for label in PROGRESS_LABELS:
        verify.add_argument(f"--progress-{label.replace('_', '-')}", required=True, type=Path)
    verify.add_argument("--process-continuity-checks", required=True, type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command in {"wait-running", "wait-pass"}:
            prior = _read_progress(args.after) if args.after is not None else None
            wait_checkpoint(
                args.progress,
                args.output,
                prior=prior,
                required_state=args.required_state,
                timeout_seconds=args.timeout_seconds,
            )
            return 0
        statuses = [
            status_gate.read_snapshot(getattr(args, f"status_{label}"))
            for label in STATUS_LABELS
        ]
        progresses = [
            _read_progress(getattr(args, f"progress_{label}"))
            for label in PROGRESS_LABELS
        ]
        evidence = verify_evidence(
            statuses,
            progresses,
            process_continuity_checks=args.process_continuity_checks,
            now_monotonic_ns=time.monotonic_ns(),
        )
        for key in EVIDENCE_KEYS:
            print(f"{key}={evidence[key]}")
        return 0
    except (GateError, status_gate.GateError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"NAT-rebinding gate failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
