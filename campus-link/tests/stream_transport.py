#!/usr/bin/env python3
"""Bounded full-duplex streaming integrity and liveness harness.

The protocol deliberately streams deterministic, sequence-unique chunks.  It
never builds a complete payload in memory, and every byte is checked by the
receiver before the sender's streaming SHA-256 is acknowledged.
"""

import argparse
import dataclasses
import hashlib
import hmac
import math
import re
import select
import socket
import struct
import threading
import time


KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
CHUNK_SIZE = 64 * KIB
DIGEST_SIZE = hashlib.sha256().digest_size
MAX_STREAM_BYTES = 8 * GIB
MAX_ROUNDS = 1_000_000

SESSION_MAGIC = b"CLSTRM2\0"
ACK_MAGIC = b"CLACK2\0\0"
SESSION_HEADER = struct.Struct("!8sQQQQ")
ACK = struct.Struct("!8sQ32s")


class TransportHarnessError(Exception):
    """Base class for deterministic harness failures."""


class PhaseDeadlineExceeded(TransportHarnessError):
    pass


class ProgressDeadlineExceeded(TransportHarnessError):
    pass


class ProtocolError(TransportHarnessError):
    pass


class IntegrityError(TransportHarnessError):
    pass


class ThroughputFloorError(TransportHarnessError):
    pass


def parse_byte_count(value):
    """Parse a bounded IEC byte count such as 4GiB or 1048576."""

    match = re.fullmatch(r"([0-9]+)(B|KiB|MiB|GiB)?", str(value).strip(), re.IGNORECASE)
    if not match:
        raise ValueError("byte count must be an integer with optional B/KiB/MiB/GiB suffix")
    number = int(match.group(1))
    multiplier = {
        None: 1,
        "b": 1,
        "kib": KIB,
        "mib": MIB,
        "gib": GIB,
    }[match.group(2).lower() if match.group(2) else None]
    result = number * multiplier
    if result > MAX_STREAM_BYTES:
        raise ValueError(f"stream exceeds the {MAX_STREAM_BYTES}-byte safety limit")
    return result


def payload_chunk(sequence, chunk_index, size, total_length):
    """Return one deterministic chunk unique to sequence and chunk position."""

    if not 0 <= sequence < 1 << 64 or chunk_index < 0 or size < 0:
        raise ValueError("invalid stream sequence, chunk index, or size")
    if not 0 <= total_length <= MAX_STREAM_BYTES or size > CHUNK_SIZE:
        raise ValueError("invalid bounded stream length or chunk size")
    seed = hashlib.sha256(
        b"campus-link-stream-v2\0"
        + struct.pack("!QQQ", sequence, chunk_index, total_length)
    ).digest()
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


def payload_chunks(sequence, length, chunk_size=CHUNK_SIZE):
    """Yield a bounded amount of sequence-unique data without whole buffering."""

    if not 0 <= length <= MAX_STREAM_BYTES or not 1 <= chunk_size <= CHUNK_SIZE:
        raise ValueError("invalid bounded stream length or chunk size")
    remaining = length
    chunk_index = 0
    while remaining:
        size = min(remaining, chunk_size)
        yield payload_chunk(sequence, chunk_index, size, length)
        remaining -= size
        chunk_index += 1


def stream_digest(sequence, length, chunk_size=CHUNK_SIZE):
    digest = hashlib.sha256()
    for chunk in payload_chunks(sequence, length, chunk_size):
        digest.update(chunk)
    return digest.digest()


class PhaseDeadline:
    """One absolute deadline shared by every operation in a test phase."""

    def __init__(self, timeout_seconds, clock=time.monotonic):
        if timeout_seconds <= 0:
            raise ValueError("phase timeout must be positive")
        self.clock = clock
        self.started = clock()
        self.expires = self.started + timeout_seconds

    def remaining(self):
        remaining = self.expires - self.clock()
        if remaining <= 0:
            raise PhaseDeadlineExceeded("whole-phase deadline exceeded")
        return remaining


class ProgressDeadline:
    """A thread-safe progress deadline bounded by an absolute phase deadline."""

    def __init__(self, phase, timeout_seconds, clock=None):
        if timeout_seconds <= 0:
            raise ValueError("progress timeout must be positive")
        self.phase = phase
        self.clock = clock or phase.clock
        self.timeout_seconds = timeout_seconds
        self._lock = threading.Lock()
        self._last_progress = self.clock()
        self._bytes = 0

    def advance(self, count):
        if count <= 0:
            return
        with self._lock:
            self._bytes += count
            self._last_progress = self.clock()

    @property
    def bytes_progressed(self):
        with self._lock:
            return self._bytes

    def wait_timeout(self):
        phase_remaining = self.phase.remaining()
        now = self.clock()
        with self._lock:
            progress_remaining = self._last_progress + self.timeout_seconds - now
        if progress_remaining <= 0:
            raise ProgressDeadlineExceeded("stream made no progress before its deadline")
        return min(phase_remaining, progress_remaining)


class SequenceValidator:
    """Require monotonically contiguous record sequences on one TCP session."""

    def __init__(self):
        self.last = None

    def accept(self, sequence):
        if not 0 <= sequence < 1 << 64:
            raise ProtocolError("record sequence is outside uint64")
        if self.last is not None and sequence != self.last + 1:
            raise ProtocolError("missing, duplicate, or reordered record sequence")
        self.last = sequence


@dataclasses.dataclass(frozen=True)
class TransferResult:
    sequence: int
    length: int
    digest: bytes
    seconds: float

    @property
    def bits_per_second(self):
        return (self.length * 8) / max(self.seconds, 1e-9)


@dataclasses.dataclass(frozen=True)
class RoundResult:
    sent: TransferResult
    received: TransferResult


def _wait_for_socket(conn, progress, readable):
    while True:
        timeout = progress.wait_timeout()
        try:
            readable_set, writable_set, _ = select.select(
                [conn] if readable else [],
                [] if readable else [conn],
                [],
                timeout,
            )
        except InterruptedError:
            continue
        if readable_set or writable_set:
            return
        # The other full-duplex worker may have advanced the shared progress
        # clock while this select was sleeping. Re-evaluate both deadlines.
        progress.wait_timeout()


def send_all(conn, data, progress):
    view = memoryview(data)
    sent = 0
    while sent < len(view):
        _wait_for_socket(conn, progress, readable=False)
        try:
            count = conn.send(view[sent:])
        except (BlockingIOError, InterruptedError):
            continue
        if count == 0:
            raise EOFError("connection closed while sending")
        sent += count
        progress.advance(count)


def receive_exact(conn, size, progress, allow_clean_eof=False):
    if size < 0:
        raise ValueError("negative receive size")
    data = bytearray(size)
    view = memoryview(data)
    received = 0
    while received < size:
        _wait_for_socket(conn, progress, readable=True)
        try:
            count = conn.recv_into(view[received:])
        except (BlockingIOError, InterruptedError):
            continue
        if count == 0:
            if allow_clean_eof and received == 0:
                return None
            raise EOFError(f"connection ended with {size - received} bytes outstanding")
        received += count
        progress.advance(count)
    return bytes(data)


def send_stream(conn, sequence, length, progress):
    started = progress.phase.clock()
    digest = hashlib.sha256()
    for chunk in payload_chunks(sequence, length):
        send_all(conn, chunk, progress)
        digest.update(chunk)
    final_digest = digest.digest()
    send_all(conn, final_digest, progress)
    return TransferResult(
        sequence=sequence,
        length=length,
        digest=final_digest,
        seconds=progress.phase.clock() - started,
    )


def receive_stream(conn, sequence, length, progress):
    started = progress.phase.clock()
    digest = hashlib.sha256()
    for expected in payload_chunks(sequence, length):
        actual = receive_exact(conn, len(expected), progress)
        if not hmac.compare_digest(actual, expected):
            raise IntegrityError("sequence-unique payload chunk mismatch")
        digest.update(actual)
    claimed = receive_exact(conn, DIGEST_SIZE, progress)
    actual_digest = digest.digest()
    if not hmac.compare_digest(claimed, actual_digest):
        raise IntegrityError("streaming SHA-256 mismatch")
    return TransferResult(
        sequence=sequence,
        length=length,
        digest=actual_digest,
        seconds=progress.phase.clock() - started,
    )


def _shutdown(conn):
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _join_worker(worker, phase, conn):
    try:
        remaining = phase.remaining()
    except PhaseDeadlineExceeded:
        _shutdown(conn)
        worker.join(timeout=1)
        raise
    worker.join(timeout=remaining)
    if worker.is_alive():
        _shutdown(conn)
        worker.join(timeout=1)
        raise PhaseDeadlineExceeded("full-duplex worker exceeded the whole-phase deadline")


def _validate_ack(wire, expected):
    magic, sequence, digest = ACK.unpack(wire)
    if (
        magic != ACK_MAGIC
        or sequence != expected.sequence
        or not hmac.compare_digest(digest, expected.digest)
    ):
        raise IntegrityError("peer did not acknowledge the exact transmitted stream")


def _enforce_throughput_floors(round_result, min_send_mbit_s, min_receive_mbit_s):
    checks = (
        ("send", round_result.sent, min_send_mbit_s),
        ("receive", round_result.received, min_receive_mbit_s),
    )
    for direction, result, floor in checks:
        if floor and result.bits_per_second < floor * 1_000_000:
            raise ThroughputFloorError(
                f"{direction} throughput {result.bits_per_second / 1_000_000:.3f} "
                f"Mbit/s is below the {floor:.3f} Mbit/s floor"
            )


def run_client_session(
    conn,
    *,
    rounds=2,
    send_bytes=MIB,
    receive_bytes=MIB,
    send_sequence=10_000_000,
    receive_sequence=20_000_000,
    progress_timeout=30,
    phase_timeout=300,
    round_delay=0,
    min_send_mbit_s=0,
    min_receive_mbit_s=0,
):
    """Run contiguous full-duplex records on one already-connected socket."""

    _validate_session_options(
        rounds,
        send_bytes,
        receive_bytes,
        round_delay,
        send_sequence,
        receive_sequence,
        min_send_mbit_s,
        min_receive_mbit_s,
    )
    conn.setblocking(False)
    phase = PhaseDeadline(phase_timeout)
    results = []
    for round_index in range(rounds):
        if round_index and round_delay:
            if round_delay >= phase.remaining():
                raise PhaseDeadlineExceeded("record delay exceeds the whole-phase deadline")
            time.sleep(round_delay)
        send_id = send_sequence + round_index
        receive_id = receive_sequence + round_index
        control_progress = ProgressDeadline(phase, progress_timeout)
        header = SESSION_HEADER.pack(
            SESSION_MAGIC, send_id, send_bytes, receive_id, receive_bytes
        )
        send_all(conn, header, control_progress)

        send_progress = ProgressDeadline(phase, progress_timeout)
        receive_progress = ProgressDeadline(phase, progress_timeout)
        sender_result = []
        sender_error = []

        def sender():
            try:
                sender_result.append(
                    send_stream(conn, send_id, send_bytes, send_progress)
                )
            except BaseException as error:  # propagate worker failures to the caller
                sender_error.append(error)
                _shutdown(conn)

        worker = threading.Thread(target=sender, name="stream-transport-client-writer")
        worker.start()
        try:
            received = receive_stream(
                conn, receive_id, receive_bytes, receive_progress
            )
            _join_worker(worker, phase, conn)
            if sender_error:
                raise sender_error[0]
            sent = sender_result[0]
            send_all(
                conn,
                ACK.pack(ACK_MAGIC, received.sequence, received.digest),
                ProgressDeadline(phase, progress_timeout),
            )
            ack_wire = receive_exact(
                conn, ACK.size, ProgressDeadline(phase, progress_timeout)
            )
        except BaseException:
            _shutdown(conn)
            worker.join(timeout=1)
            raise
        _validate_ack(ack_wire, sent)
        round_result = RoundResult(sent=sent, received=received)
        _enforce_throughput_floors(
            round_result, min_send_mbit_s, min_receive_mbit_s
        )
        results.append(round_result)
    return results


def serve_connection(
    conn,
    *,
    max_stream_bytes=MAX_STREAM_BYTES,
    progress_timeout=30,
    phase_timeout=3600,
):
    """Serve repeated full-duplex records until a clean TCP close."""

    if not 0 <= max_stream_bytes <= MAX_STREAM_BYTES:
        raise ValueError("invalid server stream limit")
    conn.setblocking(False)
    phase = PhaseDeadline(phase_timeout)
    inbound_sequences = SequenceValidator()
    outbound_sequences = SequenceValidator()
    results = []
    while True:
        control_progress = ProgressDeadline(phase, progress_timeout)
        header_wire = receive_exact(
            conn, SESSION_HEADER.size, control_progress, allow_clean_eof=True
        )
        if header_wire is None:
            return results
        magic, inbound_id, inbound_length, outbound_id, outbound_length = (
            SESSION_HEADER.unpack(header_wire)
        )
        if magic != SESSION_MAGIC:
            raise ProtocolError("invalid streaming session magic")
        if inbound_length > max_stream_bytes or outbound_length > max_stream_bytes:
            raise ProtocolError("peer requested a stream above the server safety limit")
        inbound_sequences.accept(inbound_id)
        outbound_sequences.accept(outbound_id)

        send_progress = ProgressDeadline(phase, progress_timeout)
        receive_progress = ProgressDeadline(phase, progress_timeout)
        sender_result = []
        sender_error = []

        def sender():
            try:
                sender_result.append(
                    send_stream(
                        conn, outbound_id, outbound_length, send_progress
                    )
                )
            except BaseException as error:
                sender_error.append(error)
                _shutdown(conn)

        worker = threading.Thread(target=sender, name="stream-transport-server-writer")
        worker.start()
        try:
            received = receive_stream(
                conn, inbound_id, inbound_length, receive_progress
            )
            _join_worker(worker, phase, conn)
            if sender_error:
                raise sender_error[0]
            sent = sender_result[0]
            reciprocal_ack = receive_exact(
                conn, ACK.size, ProgressDeadline(phase, progress_timeout)
            )
            _validate_ack(reciprocal_ack, sent)
            send_all(
                conn,
                ACK.pack(ACK_MAGIC, received.sequence, received.digest),
                ProgressDeadline(phase, progress_timeout),
            )
        except BaseException:
            _shutdown(conn)
            worker.join(timeout=1)
            raise
        results.append(RoundResult(sent=sent, received=received))


def _validate_session_options(
    rounds,
    send_bytes,
    receive_bytes,
    round_delay,
    send_sequence,
    receive_sequence,
    min_send_mbit_s,
    min_receive_mbit_s,
):
    if not 1 <= rounds <= MAX_ROUNDS:
        raise ValueError(f"rounds must be between 1 and {MAX_ROUNDS}")
    if not 0 <= send_bytes <= MAX_STREAM_BYTES:
        raise ValueError("send byte count is outside the bounded range")
    if not 0 <= receive_bytes <= MAX_STREAM_BYTES:
        raise ValueError("receive byte count is outside the bounded range")
    if round_delay < 0:
        raise ValueError("round delay cannot be negative")
    for name, sequence in (
        ("send", send_sequence),
        ("receive", receive_sequence),
    ):
        if sequence < 0 or sequence + rounds > 1 << 64:
            raise ValueError(f"{name} sequence range is outside uint64")
    for name, floor in (
        ("send", min_send_mbit_s),
        ("receive", min_receive_mbit_s),
    ):
        if not math.isfinite(floor) or floor < 0:
            raise ValueError(f"minimum {name} throughput must be finite and nonnegative")


def open_client(source, destination, port, progress_timeout, phase_timeout):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(min(progress_timeout, phase_timeout))
    try:
        conn.bind((source, 0))
        conn.connect((destination, port))
    except BaseException:
        conn.close()
        raise
    conn.setblocking(False)
    return conn


def serve_forever(args):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.bind, args.port))
        listener.listen(64)
        while True:
            conn, _ = listener.accept()

            def handle(accepted=conn):
                with accepted:
                    try:
                        rounds = serve_connection(
                            accepted,
                            max_stream_bytes=args.max_stream_bytes,
                            progress_timeout=args.progress_timeout,
                            phase_timeout=args.phase_timeout,
                        )
                        print(f"SESSION=pass rounds={len(rounds)}", flush=True)
                    except Exception as error:
                        print(f"SESSION=fail class={type(error).__name__}", flush=True)

            threading.Thread(target=handle, daemon=True).start()


def run_client(args):
    with open_client(
        args.source,
        args.destination,
        args.port,
        args.progress_timeout,
        args.phase_timeout,
    ) as conn:
        results = run_client_session(
            conn,
            rounds=args.rounds,
            send_bytes=args.send_bytes,
            receive_bytes=args.receive_bytes,
            send_sequence=args.send_sequence,
            receive_sequence=args.receive_sequence,
            progress_timeout=args.progress_timeout,
            phase_timeout=args.phase_timeout,
            round_delay=args.round_delay,
            min_send_mbit_s=args.min_send_mbit_s,
            min_receive_mbit_s=args.min_receive_mbit_s,
        )
    for index, result in enumerate(results, start=1):
        print(
            f"ROUND={index} send_bytes={result.sent.length} "
            f"send_sha256={result.sent.digest.hex()} "
            f"send_mbit_s={result.sent.bits_per_second / 1_000_000:.3f} "
            f"receive_bytes={result.received.length} "
            f"receive_sha256={result.received.digest.hex()} "
            f"receive_mbit_s={result.received.bits_per_second / 1_000_000:.3f}",
            flush=True,
        )
    print(f"PASS rounds={len(results)} connection_reused=true", flush=True)


def parser():
    root = argparse.ArgumentParser()
    subcommands = root.add_subparsers(dest="command", required=True)

    server = subcommands.add_parser("serve")
    server.add_argument("--bind", required=True)
    server.add_argument("--port", type=int, default=18082)
    server.add_argument("--max-stream-bytes", type=parse_byte_count, default=MAX_STREAM_BYTES)
    server.add_argument("--progress-timeout", type=float, default=30)
    server.add_argument("--phase-timeout", type=float, default=3600)
    server.set_defaults(function=serve_forever)

    client = subcommands.add_parser("client")
    client.add_argument("--source", required=True)
    client.add_argument("--destination", required=True)
    client.add_argument("--port", type=int, default=18082)
    client.add_argument("--rounds", type=int, default=2)
    client.add_argument("--send-bytes", type=parse_byte_count, default=MIB)
    client.add_argument("--receive-bytes", type=parse_byte_count, default=MIB)
    client.add_argument("--send-sequence", type=int, default=10_000_000)
    client.add_argument("--receive-sequence", type=int, default=20_000_000)
    client.add_argument("--round-delay", type=float, default=0)
    client.add_argument("--progress-timeout", type=float, default=30)
    client.add_argument("--phase-timeout", type=float, default=300)
    client.add_argument("--min-send-mbit-s", type=float, default=0)
    client.add_argument("--min-receive-mbit-s", type=float, default=0)
    client.set_defaults(function=run_client)
    return root


if __name__ == "__main__":
    arguments = parser().parse_args()
    arguments.function(arguments)


