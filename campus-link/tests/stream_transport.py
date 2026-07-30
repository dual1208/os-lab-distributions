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
import json
import math
import os
import queue
import re
import select
import signal
import socket
import stat
import struct
import tempfile
import threading
import time
from pathlib import Path


KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
CHUNK_SIZE = 64 * KIB
DIGEST_SIZE = hashlib.sha256().digest_size
MAX_STREAM_BYTES = 8 * GIB
MAX_ROUNDS = 1_000_000
MAX_PROGRESS_BYTES = 4096
PROGRESS_FORMAT = 1
CONTINUOUS_PROGRESS_FORMAT = 1
MAX_CONTINUOUS_SECONDS = 8 * 24 * 60 * 60
CONTINUOUS_STOP_MARKER = b"CAMPUS_LINK_STOP=1\n"

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


class ProgressEvidenceError(TransportHarnessError):
    pass


class ProcessIdentityError(TransportHarnessError):
    pass


MAX_PROC_STAT_BYTES = 4096


def _parse_proc_start_ticks(data):
    """Parse field 22 from one bounded Linux /proc/<pid>/stat record."""

    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_PROC_STAT_BYTES:
        raise ProcessIdentityError("process stat size is outside bounds")
    delimiter = data.rfind(b") ")
    if delimiter < 0:
        raise ProcessIdentityError("process stat command delimiter is absent")
    fields = data[delimiter + 2:].split()
    if len(fields) < 20 or re.fullmatch(rb"[1-9][0-9]*", fields[19]) is None:
        raise ProcessIdentityError("process start tick is malformed")
    value = int(fields[19])
    if value >= 1 << 64:
        raise ProcessIdentityError("process start tick is outside uint64")
    return value


def _open_proc_process(pid):
    if os.name != "posix" or type(pid) is not int or pid <= 0:
        raise ProcessIdentityError("pidfd signaling requires a positive Linux PID")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    proc = os.open("/proc", flags)
    try:
        descriptor = os.open(str(pid), flags, dir_fd=proc)
    finally:
        os.close(proc)
    return descriptor


def _proc_identity(descriptor):
    info = os.fstat(descriptor)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    stat_descriptor = os.open("stat", flags, dir_fd=descriptor)
    try:
        data = os.read(stat_descriptor, MAX_PROC_STAT_BYTES + 1)
    finally:
        os.close(stat_descriptor)
    return (info.st_dev, info.st_ino), _parse_proc_start_ticks(data)


def process_start_ticks(pid):
    """Read one Linux process start tick without following a procfs symlink."""

    descriptor = _open_proc_process(pid)
    try:
        _, ticks = _proc_identity(descriptor)
        return ticks
    finally:
        os.close(descriptor)


def signal_process_identity(pid, expected_start_ticks, signal_number):
    """Signal only the pidfd bound to one revalidated Linux process identity.

    ``False`` means the matching process disappeared before a signal was
    necessary. A reused PID, malformed identity, or unavailable pidfd support
    is an error rather than permission to issue a numeric signal.
    """

    approved_signals = {signal.SIGTERM}
    if hasattr(signal, "SIGKILL"):
        approved_signals.add(signal.SIGKILL)
    if (
        os.name != "posix"
        or type(pid) is not int
        or pid <= 0
        or pid == os.getpid()
        or type(expected_start_ticks) is not int
        or not 0 < expected_start_ticks < 1 << 64
        or signal_number not in approved_signals
    ):
        raise ProcessIdentityError("invalid process signaling identity")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise ProcessIdentityError("Linux pidfd signaling is unavailable")
    try:
        before_descriptor = _open_proc_process(pid)
    except (FileNotFoundError, ProcessLookupError):
        return False
    try:
        try:
            before_identity, before_ticks = _proc_identity(before_descriptor)
        except (FileNotFoundError, ProcessLookupError):
            return False
        if before_ticks != expected_start_ticks:
            raise ProcessIdentityError("process start tick changed before pidfd open")
        try:
            pidfd = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            return False
        try:
            try:
                after_descriptor = _open_proc_process(pid)
            except (FileNotFoundError, ProcessLookupError):
                return False
            try:
                try:
                    after_identity, after_ticks = _proc_identity(after_descriptor)
                except (FileNotFoundError, ProcessLookupError):
                    return False
            finally:
                os.close(after_descriptor)
            if after_identity != before_identity or after_ticks != expected_start_ticks:
                raise ProcessIdentityError("process identity changed around pidfd open")
            try:
                signal.pidfd_send_signal(pidfd, signal_number, None, 0)
            except ProcessLookupError:
                return False
            return True
        finally:
            os.close(pidfd)
    finally:
        os.close(before_descriptor)


class _ObserverDispatcher:
    """Run observer callbacks without letting one retain process lifetime."""

    _STOP = object()
    _QUEUE_LIMIT = 1024

    def __init__(self, observer, phase):
        self.observer = observer
        self.phase = phase
        self.items = queue.Queue(maxsize=self._QUEUE_LIMIT)
        self.errors = []
        self.worker = threading.Thread(
            target=self._run,
            name="stream-transport-progress-observer",
            daemon=True,
        )
        self.worker.start()

    def _run(self):
        try:
            while True:
                item = self.items.get()
                if item is self._STOP:
                    return
                self.observer.advance(item)
        except BaseException as error:
            self.errors.append(error)

    def _raise_error(self):
        if self.errors:
            raise self.errors[0]

    def submit(self, count):
        self._raise_error()
        if not self.worker.is_alive():
            raise ProgressEvidenceError("progress observer stopped without success")
        try:
            self.items.put_nowait(count)
        except queue.Full as error:
            raise ProgressEvidenceError(
                "progress observer backlog exceeded its bound"
            ) from error

    def finish(self):
        while True:
            self._raise_error()
            if not self.worker.is_alive():
                raise ProgressEvidenceError("progress observer stopped without success")
            timeout = min(self.phase.remaining(), 0.05)
            try:
                self.items.put(self._STOP, timeout=timeout)
                break
            except queue.Full:
                continue
        self.worker.join(timeout=self.phase.remaining())
        if self.worker.is_alive():
            raise PhaseDeadlineExceeded(
                "progress observer exceeded the whole-phase deadline"
            )
        self._raise_error()

    def abort(self):
        try:
            self.items.put_nowait(self._STOP)
        except queue.Full:
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

    def __init__(self, phase, timeout_seconds, clock=None, observer=None):
        if timeout_seconds <= 0:
            raise ValueError("progress timeout must be positive")
        self.phase = phase
        self.clock = clock or phase.clock
        self.timeout_seconds = timeout_seconds
        self._lock = threading.Lock()
        self._last_progress = self.clock()
        self._bytes = 0
        self._observer = (
            _ObserverDispatcher(observer, phase) if observer is not None else None
        )

    def advance(self, count):
        if count <= 0:
            return
        with self._lock:
            self._bytes += count
            self._last_progress = self.clock()
        if self._observer is not None:
            self._observer.submit(count)

    def finish_observer(self):
        if self._observer is not None:
            self._observer.finish()

    def abort_observer(self):
        if self._observer is not None:
            self._observer.abort()

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


def _unique_progress_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProgressEvidenceError(f"duplicate progress key {key}")
        value[key] = item
    return value


def _validate_progress_parent(path):
    if not path.is_absolute():
        raise ProgressEvidenceError("progress path must be absolute")
    parent = path.parent
    info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ProgressEvidenceError("progress parent is not a real directory")
    if os.name == "posix":
        if info.st_uid != os.geteuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ProgressEvidenceError("progress parent custody is unsafe")


class ProgressReporter:
    """Atomically publish bounded receive progress for an external fault gate."""

    def __init__(
        self, path, receive_sequence, *, interval_seconds=0.1,
        clock_ns=time.monotonic_ns,
    ):
        self.path = Path(path)
        _validate_progress_parent(self.path)
        if self.path.exists() or self.path.is_symlink():
            raise ProgressEvidenceError("progress output already exists")
        if not 0 <= receive_sequence < 1 << 64:
            raise ValueError("receive sequence is outside uint64")
        if not math.isfinite(interval_seconds) or interval_seconds <= 0:
            raise ValueError("progress publication interval must be positive")
        self.receive_sequence = receive_sequence
        self.interval_ns = max(1, int(interval_seconds * 1_000_000_000))
        self.clock_ns = clock_ns
        self._lock = threading.Lock()
        self._received_bytes = 0
        self._last_publish_ns = 0
        self._phase = None

    def bind_phase(self, phase):
        if self._phase is not None and self._phase is not phase:
            raise ProgressEvidenceError("progress reporter was rebound to another phase")
        self._phase = phase

    def advance(self, count):
        if count <= 0:
            return
        publish = None
        with self._lock:
            self._received_bytes += count
            now = self.clock_ns()
            if now - self._last_publish_ns >= self.interval_ns:
                self._last_publish_ns = now
                publish = (now, self._received_bytes)
        if publish is not None:
            self._publish(*publish)

    def finish(self):
        if self._phase is not None:
            return _run_callback_bounded(
                self._finish,
                self._phase,
                "stream-transport-progress-finish",
            )
        return self._finish()

    def _finish(self):
        with self._lock:
            now = self.clock_ns()
            self._last_publish_ns = now
            received = self._received_bytes
        self._publish(now, received)

    def _publish(self, monotonic_ns, received_bytes):
        value = {
            "format": PROGRESS_FORMAT,
            "monotonic_ns": monotonic_ns,
            "receive_sequence": self.receive_sequence,
            "received_bytes": received_bytes,
        }
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent,
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(encoded)
                target.flush()
                os.fsync(target.fileno())
            descriptor = None
            os.replace(temporary, self.path)
            temporary = None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass


def read_progress(path):
    path = Path(path)
    _validate_progress_parent(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProgressEvidenceError("progress evidence is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ProgressEvidenceError("progress evidence is not a private regular file")
        if os.name == "posix" and (
            opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ProgressEvidenceError("progress evidence custody is unsafe")
        if opened.st_size <= 0 or opened.st_size > MAX_PROGRESS_BYTES:
            raise ProgressEvidenceError("progress evidence size is outside bounds")
        data = os.read(descriptor, MAX_PROGRESS_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_PROGRESS_BYTES:
        raise ProgressEvidenceError("progress evidence exceeds size bound")
    value = json.loads(
        data,
        object_pairs_hook=_unique_progress_object,
        parse_constant=lambda item: (_ for _ in ()).throw(
            ProgressEvidenceError(f"invalid progress constant {item}")
        ),
    )
    if not isinstance(value, dict) or set(value) != {
        "format", "monotonic_ns", "receive_sequence", "received_bytes",
    }:
        raise ProgressEvidenceError("progress evidence schema is invalid")
    if type(value["format"]) is not int or value["format"] != PROGRESS_FORMAT:
        raise ProgressEvidenceError("progress evidence format is invalid")
    for key in ("monotonic_ns", "receive_sequence", "received_bytes"):
        item = value[key]
        if type(item) is not int or item < 0 or item >= 1 << 64:
            raise ProgressEvidenceError(f"progress evidence {key} is invalid")
    if value["monotonic_ns"] == 0:
        raise ProgressEvidenceError("progress evidence timestamp is invalid")
    return value


def wait_for_progress(
    path, *, receive_sequence, minimum_received_bytes=1,
    after_received_bytes=None, timeout_seconds=30,
):
    if (
        not 0 <= receive_sequence < 1 << 64
        or not 0 <= minimum_received_bytes < 1 << 64
        or after_received_bytes is not None
        and not 0 <= after_received_bytes < 1 << 64
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("invalid progress wait bound")
    deadline = time.monotonic() + timeout_seconds
    last_error = None
    while True:
        try:
            value = read_progress(path)
            if value["receive_sequence"] != receive_sequence:
                raise ProgressEvidenceError("progress sequence does not match the stream")
            if (
                value["received_bytes"] >= minimum_received_bytes
                and (
                    after_received_bytes is None
                    or value["received_bytes"] > after_received_bytes
                )
            ):
                return value
        except FileNotFoundError as error:
            last_error = error
        if time.monotonic() >= deadline:
            raise ProgressDeadlineExceeded("receive progress did not satisfy the wait") from last_error
        time.sleep(0.05)


class _ContinuousDirectionObserver:
    def __init__(self, reporter, direction):
        self.reporter = reporter
        self.direction = direction

    def advance(self, count):
        self.reporter.advance(self.direction, count)


class ContinuousSessionReporter:
    """Publish sanitized cumulative evidence for exactly one TCP connection."""

    _TRANSCRIPT_DOMAIN = b"campus-link-continuous-session-v1\0"

    def __init__(
        self,
        path,
        first_send_sequence,
        first_receive_sequence,
        *,
        started_monotonic_ns,
        interval_seconds=1,
        clock_ns=time.monotonic_ns,
        phase=None,
    ):
        self.path = Path(path)
        _validate_progress_parent(self.path)
        if self.path.exists() or self.path.is_symlink():
            raise ProgressEvidenceError("continuous progress output already exists")
        for sequence in (first_send_sequence, first_receive_sequence):
            if not 0 <= sequence < 1 << 64:
                raise ValueError("continuous sequence is outside uint64")
        if not 0 < started_monotonic_ns < 1 << 64:
            raise ValueError("continuous start timestamp is invalid")
        if not math.isfinite(interval_seconds) or interval_seconds <= 0:
            raise ValueError("continuous publication interval must be positive")
        self.first_send_sequence = first_send_sequence
        self.first_receive_sequence = first_receive_sequence
        self.started_monotonic_ns = started_monotonic_ns
        self.interval_ns = max(1, int(interval_seconds * 1_000_000_000))
        self.clock_ns = clock_ns
        self._phase = phase
        self._lock = threading.Lock()
        self._state = "running"
        self._records_completed = 0
        self._sent_bytes = 0
        self._received_bytes = 0
        self._last_send_progress_ns = started_monotonic_ns
        self._last_receive_progress_ns = started_monotonic_ns
        self._max_send_gap_ns = 0
        self._max_receive_gap_ns = 0
        self._last_publish_ns = 0
        self._transcript = hashlib.sha256(self._TRANSCRIPT_DOMAIN)
        if self._phase is None:
            self._publish_initial(started_monotonic_ns)
        else:
            _run_callback_bounded(
                lambda: self._publish_initial(started_monotonic_ns),
                self._phase,
                "stream-transport-continuous-start",
            )

    def _publish_initial(self, started_monotonic_ns):
        with self._lock:
            self._publish_locked(started_monotonic_ns)

    @property
    def send_observer(self):
        return _ContinuousDirectionObserver(self, "send")

    @property
    def receive_observer(self):
        return _ContinuousDirectionObserver(self, "receive")

    def _note_gap_locked(self, direction, now):
        if direction == "send":
            gap = max(0, now - self._last_send_progress_ns)
            self._max_send_gap_ns = max(self._max_send_gap_ns, gap)
        elif direction == "receive":
            gap = max(0, now - self._last_receive_progress_ns)
            self._max_receive_gap_ns = max(self._max_receive_gap_ns, gap)
        else:
            raise ValueError("unknown continuous direction")

    def advance(self, direction, count):
        if count <= 0:
            return
        with self._lock:
            if self._state != "running":
                raise ProgressEvidenceError("continuous progress advanced after completion")
            now = self.clock_ns()
            if not self.started_monotonic_ns <= now < 1 << 64:
                raise ProgressEvidenceError("continuous progress clock is invalid")
            self._note_gap_locked(direction, now)
            if direction == "send":
                self._sent_bytes += count
                self._last_send_progress_ns = now
            else:
                self._received_bytes += count
                self._last_receive_progress_ns = now
            if self._sent_bytes >= 1 << 64 or self._received_bytes >= 1 << 64:
                raise ProgressEvidenceError("continuous byte counter overflow")
            if now - self._last_publish_ns >= self.interval_ns:
                self._publish_locked(now)

    def record_complete(self, result):
        if self._phase is not None:
            return _run_callback_bounded(
                lambda: self._record_complete(result),
                self._phase,
                "stream-transport-continuous-record",
            )
        return self._record_complete(result)

    def _record_complete(self, result):
        with self._lock:
            if self._state != "running":
                raise ProgressEvidenceError("continuous record completed after session")
            expected_send = self.first_send_sequence + self._records_completed
            expected_receive = self.first_receive_sequence + self._records_completed
            if (
                expected_send >= 1 << 64
                or expected_receive >= 1 << 64
                or result.sent.sequence != expected_send
                or result.received.sequence != expected_receive
            ):
                raise ProgressEvidenceError("continuous record sequence is not contiguous")
            now = self.clock_ns()
            self._note_gap_locked("send", now)
            self._note_gap_locked("receive", now)
            self._transcript.update(
                struct.pack(
                    "!QQQQ",
                    result.sent.sequence,
                    result.sent.length,
                    result.received.sequence,
                    result.received.length,
                )
            )
            self._transcript.update(result.sent.digest)
            self._transcript.update(result.received.digest)
            self._records_completed += 1
            if now - self._last_publish_ns >= self.interval_ns:
                self._publish_locked(now)

    def finish(self):
        if self._phase is not None:
            return _run_callback_bounded(
                self._finish,
                self._phase,
                "stream-transport-continuous-finish",
            )
        return self._finish()

    def _finish(self):
        with self._lock:
            if self._state != "running":
                raise ProgressEvidenceError("continuous session completed twice")
            if (
                self._records_completed == 0
                or self._sent_bytes == 0
                or self._received_bytes == 0
            ):
                raise ProgressEvidenceError("continuous session has no full-duplex record")
            now = self.clock_ns()
            self._note_gap_locked("send", now)
            self._note_gap_locked("receive", now)
            self._state = "pass"
            self._publish_locked(now)

    @staticmethod
    def _milliseconds_ceil(nanoseconds):
        return (nanoseconds + 999_999) // 1_000_000

    def _value_locked(self, now):
        completed = self._records_completed
        return {
            "format": CONTINUOUS_PROGRESS_FORMAT,
            "state": self._state,
            "started_monotonic_ns": self.started_monotonic_ns,
            "updated_monotonic_ns": now,
            "tcp_connections": 1,
            "tcp_reconnects": 0,
            "records_completed": completed,
            "sent_bytes": self._sent_bytes,
            "received_bytes": self._received_bytes,
            "first_send_sequence": self.first_send_sequence,
            "last_send_sequence": self.first_send_sequence + max(0, completed - 1),
            "first_receive_sequence": self.first_receive_sequence,
            "last_receive_sequence": self.first_receive_sequence + max(0, completed - 1),
            "max_send_progress_gap_ms": self._milliseconds_ceil(
                self._max_send_gap_ns
            ),
            "max_receive_progress_gap_ms": self._milliseconds_ceil(
                self._max_receive_gap_ns
            ),
            "transcript_sha256": self._transcript.hexdigest(),
        }

    def _publish_locked(self, now):
        if not self.started_monotonic_ns <= now < 1 << 64:
            raise ProgressEvidenceError("continuous publication clock is invalid")
        self._last_publish_ns = now
        encoded = (
            json.dumps(
                self._value_locked(now), sort_keys=True, separators=(",", ":")
            )
            + "\n"
        ).encode()
        if len(encoded) > MAX_PROGRESS_BYTES:
            raise ProgressEvidenceError("continuous progress exceeds size bound")
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent,
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(encoded)
                target.flush()
                os.fsync(target.fileno())
            descriptor = None
            os.replace(temporary, self.path)
            temporary = None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass


_CONTINUOUS_PROGRESS_KEYS = {
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


def read_continuous_progress(path):
    """Read one exact, root-private continuous-session progress object."""

    path = Path(path)
    _validate_progress_parent(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProgressEvidenceError("continuous progress is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ProgressEvidenceError("continuous progress is not private")
        if os.name == "posix" and (
            opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ProgressEvidenceError("continuous progress custody is unsafe")
        if opened.st_size <= 0 or opened.st_size > MAX_PROGRESS_BYTES:
            raise ProgressEvidenceError("continuous progress size is outside bounds")
        data = os.read(descriptor, MAX_PROGRESS_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_PROGRESS_BYTES:
        raise ProgressEvidenceError("continuous progress exceeds size bound")
    value = json.loads(
        data,
        object_pairs_hook=_unique_progress_object,
        parse_constant=lambda item: (_ for _ in ()).throw(
            ProgressEvidenceError(f"invalid continuous constant {item}")
        ),
    )
    if not isinstance(value, dict) or set(value) != _CONTINUOUS_PROGRESS_KEYS:
        raise ProgressEvidenceError("continuous progress schema is invalid")
    if type(value["format"]) is not int or value["format"] != CONTINUOUS_PROGRESS_FORMAT:
        raise ProgressEvidenceError("continuous progress format is invalid")
    if value["state"] not in ("running", "pass"):
        raise ProgressEvidenceError("continuous progress state is invalid")
    integer_keys = _CONTINUOUS_PROGRESS_KEYS - {"state", "transcript_sha256"}
    for key in integer_keys:
        item = value[key]
        if type(item) is not int or item < 0 or item >= 1 << 64:
            raise ProgressEvidenceError(f"continuous progress {key} is invalid")
    if (
        value["started_monotonic_ns"] == 0
        or value["updated_monotonic_ns"] < value["started_monotonic_ns"]
        or value["tcp_connections"] != 1
        or value["tcp_reconnects"] != 0
    ):
        raise ProgressEvidenceError("continuous connection evidence is invalid")
    records = value["records_completed"]
    for prefix in ("send", "receive"):
        first = value[f"first_{prefix}_sequence"]
        last = value[f"last_{prefix}_sequence"]
        expected_last = first + max(0, records - 1)
        if expected_last >= 1 << 64 or last != expected_last:
            raise ProgressEvidenceError("continuous sequence evidence is invalid")
    transcript = value["transcript_sha256"]
    if not isinstance(transcript, str) or re.fullmatch(r"[a-f0-9]{64}", transcript) is None:
        raise ProgressEvidenceError("continuous transcript digest is invalid")
    if value["state"] == "pass" and (
        records == 0 or value["sent_bytes"] == 0 or value["received_bytes"] == 0
    ):
        raise ProgressEvidenceError("continuous pass has no full-duplex evidence")
    return value


def continuous_stop_requested(path):
    """Return true only for one exact, root-private regular stop marker."""

    path = Path(path)
    _validate_progress_parent(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProgressEvidenceError("continuous stop marker is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ProgressEvidenceError("continuous stop marker identity is invalid")
        if os.name == "posix" and (
            opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ProgressEvidenceError("continuous stop marker custody is unsafe")
        if opened.st_size != len(CONTINUOUS_STOP_MARKER):
            raise ProgressEvidenceError("continuous stop marker size is invalid")
        value = os.read(descriptor, len(CONTINUOUS_STOP_MARKER) + 1)
    finally:
        os.close(descriptor)
    if value != CONTINUOUS_STOP_MARKER:
        raise ProgressEvidenceError("continuous stop marker content is invalid")
    return True


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
    # External direction totals describe application payload. Keep the digest
    # trailer bounded without reporting it as payload progress.
    digest_progress = ProgressDeadline(
        progress.phase, progress.timeout_seconds, clock=progress.clock,
    )
    send_all(conn, final_digest, digest_progress)
    progress.finish_observer()
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
    # The external reporter proves payload delivery, not protocol framing.
    # Give the trailing digest the same bounds without forwarding its bytes to
    # the reporter attached to `progress`.
    digest_progress = ProgressDeadline(
        progress.phase, progress.timeout_seconds, clock=progress.clock,
    )
    claimed = receive_exact(conn, DIGEST_SIZE, digest_progress)
    actual_digest = digest.digest()
    if not hmac.compare_digest(claimed, actual_digest):
        raise IntegrityError("streaming SHA-256 mismatch")
    progress.finish_observer()
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


def _start_writer(target, name):
    """Start a subordinate writer that cannot retain process lifetime on failure."""

    worker = threading.Thread(target=target, name=name, daemon=True)
    worker.start()
    return worker


def _run_callback_bounded(callback, phase, name):
    """Run one potentially blocking callback behind the phase deadline."""

    phase.remaining()
    results = []
    errors = []

    def target():
        try:
            results.append(callback())
        except BaseException as error:
            errors.append(error)

    worker = _start_writer(target, name)
    worker.join(timeout=phase.remaining())
    if worker.is_alive():
        raise PhaseDeadlineExceeded(
            f"{name} exceeded the whole-phase deadline"
        )
    if errors:
        raise errors[0]
    if len(results) != 1:
        raise ProgressEvidenceError(f"{name} completed without a result")
    return results[0]


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


def _run_client_round(
    conn,
    phase,
    *,
    send_id,
    send_bytes,
    receive_id,
    receive_bytes,
    progress_timeout,
    send_observer=None,
    receive_observer=None,
):
    control_progress = ProgressDeadline(phase, progress_timeout)
    header = SESSION_HEADER.pack(
        SESSION_MAGIC, send_id, send_bytes, receive_id, receive_bytes
    )
    send_all(conn, header, control_progress)

    send_progress = ProgressDeadline(
        phase, progress_timeout, observer=send_observer,
    )
    receive_progress = ProgressDeadline(
        phase, progress_timeout, observer=receive_observer,
    )
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

    worker = _start_writer(sender, "stream-transport-client-writer")
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
        send_progress.abort_observer()
        receive_progress.abort_observer()
        worker.join(timeout=1)
        raise
    _validate_ack(ack_wire, sent)
    return RoundResult(sent=sent, received=received)


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
    progress_reporter=None,
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
    if progress_reporter is not None:
        progress_reporter.bind_phase(phase)
    results = []
    for round_index in range(rounds):
        if round_index and round_delay:
            if round_delay >= phase.remaining():
                raise PhaseDeadlineExceeded("record delay exceeds the whole-phase deadline")
            time.sleep(round_delay)
        send_id = send_sequence + round_index
        receive_id = receive_sequence + round_index
        round_result = _run_client_round(
            conn,
            phase,
            send_id=send_id,
            send_bytes=send_bytes,
            receive_id=receive_id,
            receive_bytes=receive_bytes,
            progress_timeout=progress_timeout,
            receive_observer=progress_reporter,
        )
        _enforce_throughput_floors(
            round_result, min_send_mbit_s, min_receive_mbit_s
        )
        results.append(round_result)
    return results


def run_continuous_client_session(
    conn,
    *,
    duration_seconds,
    completion_grace_seconds,
    record_bytes=MIB,
    send_sequence=30_000_000_000,
    receive_sequence=40_000_000_000,
    progress_timeout=30,
    progress_file,
    progress_interval=1,
    clock=time.monotonic,
    clock_ns=time.monotonic_ns,
    stop_condition=None,
):
    """Continuously reuse one full-duplex socket for a bounded interval.

    With no stop condition, ``duration_seconds`` is the required minimum soak
    duration. With a stop condition, it is the absolute bound for receiving a
    stop request; the request is honored only after a complete full-duplex
    record and its reciprocal acknowledgements.
    """

    for name, value, upper in (
        ("duration", duration_seconds, MAX_CONTINUOUS_SECONDS),
        ("completion grace", completion_grace_seconds, 3600),
        ("progress timeout", progress_timeout, 3600),
        ("progress interval", progress_interval, 60),
    ):
        if not math.isfinite(value) or not 0 < value <= upper:
            raise ValueError(f"continuous {name} is outside the bounded range")
    if not 0 < record_bytes <= MAX_STREAM_BYTES:
        raise ValueError("continuous record size is outside the bounded range")
    if stop_condition is not None and not callable(stop_condition):
        raise ValueError("continuous stop condition is not callable")
    for name, sequence in (
        ("send", send_sequence),
        ("receive", receive_sequence),
    ):
        if not 0 <= sequence < 1 << 64:
            raise ValueError(f"continuous {name} sequence is outside uint64")

    conn.setblocking(False)
    phase = PhaseDeadline(duration_seconds + completion_grace_seconds, clock=clock)
    started_ns = clock_ns()
    reporter = ContinuousSessionReporter(
        progress_file,
        send_sequence,
        receive_sequence,
        started_monotonic_ns=started_ns,
        interval_seconds=progress_interval,
        clock_ns=clock_ns,
        phase=phase,
    )
    # The evidence interval is anchored to the published monotonic start.
    required_end = started_ns / 1_000_000_000 + duration_seconds
    round_index = 0
    while True:
        send_id = send_sequence + round_index
        receive_id = receive_sequence + round_index
        if send_id >= 1 << 64 or receive_id >= 1 << 64:
            raise ProtocolError("continuous sequence range exhausted")
        result = _run_client_round(
            conn,
            phase,
            send_id=send_id,
            send_bytes=record_bytes,
            receive_id=receive_id,
            receive_bytes=record_bytes,
            progress_timeout=progress_timeout,
            send_observer=reporter.send_observer,
            receive_observer=reporter.receive_observer,
        )
        reporter.record_complete(result)
        round_index += 1
        if stop_condition is None:
            if phase.clock() >= required_end:
                break
        else:
            if stop_condition():
                break
            if phase.clock() >= required_end:
                raise PhaseDeadlineExceeded(
                    "continuous stop marker did not arrive before its deadline"
                )
    phase.remaining()
    reporter.finish()
    return read_continuous_progress(progress_file)


def serve_connection(
    conn,
    *,
    max_stream_bytes=MAX_STREAM_BYTES,
    progress_timeout=30,
    phase_timeout=3600,
    progress_reporter=None,
    collect_results=True,
    result_observer=None,
):
    """Serve repeated full-duplex records until a clean TCP close."""

    if not 0 <= max_stream_bytes <= MAX_STREAM_BYTES:
        raise ValueError("invalid server stream limit")
    conn.setblocking(False)
    phase = PhaseDeadline(phase_timeout)
    if progress_reporter is not None:
        progress_reporter.bind_phase(phase)
    inbound_sequences = SequenceValidator()
    outbound_sequences = SequenceValidator()
    results = []
    round_count = 0
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
        if progress_reporter is not None:
            if round_count or inbound_id != progress_reporter.receive_sequence:
                raise ProtocolError("server progress reporter is not bound to this record")

        send_progress = ProgressDeadline(phase, progress_timeout)
        receive_progress = ProgressDeadline(
            phase, progress_timeout, observer=progress_reporter,
        )
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

        worker = _start_writer(sender, "stream-transport-server-writer")
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
            send_progress.abort_observer()
            receive_progress.abort_observer()
            worker.join(timeout=1)
            raise
        result = RoundResult(sent=sent, received=received)
        if result_observer is not None:
            result_observer(result)
        if collect_results:
            results.append(result)
        round_count += 1


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
    progress_reporter = None
    if (args.progress_file is None) != (args.progress_receive_sequence is None):
        raise ValueError("server progress file and receive sequence must be used together")
    if args.progress_file is not None:
        progress_reporter = ProgressReporter(
            args.progress_file,
            args.progress_receive_sequence,
            interval_seconds=args.progress_interval,
        )
    reporter_claimed = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.bind, args.port))
        listener.listen(64)
        while True:
            conn, _ = listener.accept()
            session_reporter = None
            if progress_reporter is not None:
                if reporter_claimed:
                    conn.close()
                    continue
                reporter_claimed = True
                session_reporter = progress_reporter

            def handle(accepted=conn, reporter=session_reporter):
                with accepted:
                    try:
                        rounds = serve_connection(
                            accepted,
                            max_stream_bytes=args.max_stream_bytes,
                            progress_timeout=args.progress_timeout,
                            phase_timeout=args.phase_timeout,
                            progress_reporter=reporter,
                        )
                        print(f"SESSION=pass rounds={len(rounds)}", flush=True)
                    except Exception as error:
                        print(f"SESSION=fail class={type(error).__name__}", flush=True)
                    finally:
                        if reporter is not None:
                            reporter.finish()

            threading.Thread(target=handle, daemon=True).start()


def serve_once(args):
    """Accept exactly one connection and never provide a reconnect path."""

    records = 0

    def observed(_result):
        nonlocal records
        records += 1

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.bind, args.port))
        listener.listen(1)
        listener.settimeout(args.accept_timeout)
        conn, _ = listener.accept()
    with conn:
        serve_connection(
            conn,
            max_stream_bytes=args.max_stream_bytes,
            progress_timeout=args.progress_timeout,
            phase_timeout=args.phase_timeout,
            collect_results=False,
            result_observer=observed,
        )
    if records == 0:
        raise ProtocolError("continuous server received no complete record")
    print(f"PASS connections=1 reconnects=0 records={records}", flush=True)


def serve_session_once(args):
    """Accept and verify exactly one progress-reporting full-duplex record."""

    reporter = ProgressReporter(
        args.progress_file,
        args.progress_receive_sequence,
        interval_seconds=args.progress_interval,
    )
    records = 0

    def observed(_result):
        nonlocal records
        records += 1

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.bind, args.port))
        listener.listen(1)
        listener.settimeout(args.accept_timeout)
        conn, _ = listener.accept()
    with conn:
        serve_connection(
            conn,
            max_stream_bytes=args.max_stream_bytes,
            progress_timeout=args.progress_timeout,
            phase_timeout=args.phase_timeout,
            progress_reporter=reporter,
            collect_results=False,
            result_observer=observed,
        )
    if records != 1:
        raise ProtocolError("one-session server did not verify exactly one record")
    reporter.finish()
    print("PASS connections=1 reconnects=0 records=1", flush=True)


def run_client(args):
    reporter = None
    if args.progress_file is not None:
        reporter = ProgressReporter(
            args.progress_file,
            args.receive_sequence,
            interval_seconds=args.progress_interval,
        )
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
            progress_reporter=reporter,
        )
    if reporter is not None:
        reporter.finish()
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


def run_continuous_client(args):
    phase_timeout = args.duration_seconds + args.completion_grace_seconds
    stop_condition = None
    if args.stop_file is not None:
        _validate_progress_parent(args.stop_file)
        if args.stop_file.exists() or args.stop_file.is_symlink():
            raise ProgressEvidenceError("continuous stop marker already exists")
        stop_condition = lambda: continuous_stop_requested(args.stop_file)
    with open_client(
        args.source,
        args.destination,
        args.port,
        args.progress_timeout,
        phase_timeout,
    ) as conn:
        result = run_continuous_client_session(
            conn,
            duration_seconds=args.duration_seconds,
            completion_grace_seconds=args.completion_grace_seconds,
            record_bytes=args.record_bytes,
            send_sequence=args.send_sequence,
            receive_sequence=args.receive_sequence,
            progress_timeout=args.progress_timeout,
            progress_file=args.progress_file,
            progress_interval=args.progress_interval,
            stop_condition=stop_condition,
        )
    print(
        f"PASS connections={result['tcp_connections']} "
        f"reconnects={result['tcp_reconnects']} "
        f"records={result['records_completed']} "
        f"sent_bytes={result['sent_bytes']} "
        f"received_bytes={result['received_bytes']} "
        f"transcript_sha256={result['transcript_sha256']}",
        flush=True,
    )


def wait_progress_command(args):
    value = wait_for_progress(
        args.progress_file,
        receive_sequence=args.receive_sequence,
        minimum_received_bytes=args.minimum_received_bytes,
        after_received_bytes=args.after_received_bytes,
        timeout_seconds=args.timeout_seconds,
    )
    print(f"FORMAT={value['format']}")
    print(f"MONOTONIC_NS={value['monotonic_ns']}")
    print(f"RECEIVE_SEQUENCE={value['receive_sequence']}")
    print(f"RECEIVED_BYTES={value['received_bytes']}")


def inspect_continuous_command(args):
    value = read_continuous_progress(args.progress_file)
    ordered = (
        value["state"],
        value["started_monotonic_ns"],
        value["updated_monotonic_ns"],
        value["tcp_connections"],
        value["tcp_reconnects"],
        value["records_completed"],
        value["sent_bytes"],
        value["received_bytes"],
        value["first_send_sequence"],
        value["last_send_sequence"],
        value["first_receive_sequence"],
        value["last_receive_sequence"],
        value["max_send_progress_gap_ms"],
        value["max_receive_progress_gap_ms"],
        value["transcript_sha256"],
    )
    print(" ".join(map(str, ordered)))


def signal_pid_command(args):
    signal_process_identity(
        args.pid,
        args.start_ticks,
        {"TERM": signal.SIGTERM, "KILL": getattr(signal, "SIGKILL", None)}[
            args.signal
        ],
    )


def parser():
    root = argparse.ArgumentParser()
    subcommands = root.add_subparsers(dest="command", required=True)

    server = subcommands.add_parser("serve")
    server.add_argument("--bind", required=True)
    server.add_argument("--port", type=int, default=18082)
    server.add_argument("--max-stream-bytes", type=parse_byte_count, default=MAX_STREAM_BYTES)
    server.add_argument("--progress-timeout", type=float, default=30)
    server.add_argument("--phase-timeout", type=float, default=3600)
    server.add_argument("--progress-file", type=Path)
    server.add_argument("--progress-receive-sequence", type=int)
    server.add_argument("--progress-interval", type=float, default=0.1)
    server.set_defaults(function=serve_forever)

    single_server = subcommands.add_parser("serve-once")
    single_server.add_argument("--bind", required=True)
    single_server.add_argument("--port", type=int, default=18082)
    single_server.add_argument(
        "--max-stream-bytes", type=parse_byte_count, default=MAX_STREAM_BYTES
    )
    single_server.add_argument("--progress-timeout", type=float, default=30)
    single_server.add_argument("--phase-timeout", type=float, required=True)
    single_server.add_argument("--accept-timeout", type=float, default=30)
    single_server.set_defaults(function=serve_once)

    session_server = subcommands.add_parser("serve-session-once")
    session_server.add_argument("--bind", required=True)
    session_server.add_argument("--port", type=int, default=18082)
    session_server.add_argument(
        "--max-stream-bytes", type=parse_byte_count, default=MAX_STREAM_BYTES
    )
    session_server.add_argument("--progress-timeout", type=float, default=30)
    session_server.add_argument("--phase-timeout", type=float, required=True)
    session_server.add_argument("--accept-timeout", type=float, default=30)
    session_server.add_argument("--progress-file", required=True, type=Path)
    session_server.add_argument("--progress-receive-sequence", required=True, type=int)
    session_server.add_argument("--progress-interval", type=float, default=0.1)
    session_server.set_defaults(function=serve_session_once)

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
    client.add_argument("--progress-file", type=Path)
    client.add_argument("--progress-interval", type=float, default=0.1)
    client.set_defaults(function=run_client)

    continuous = subcommands.add_parser("continuous-client")
    continuous.add_argument("--source", required=True)
    continuous.add_argument("--destination", required=True)
    continuous.add_argument("--port", type=int, default=18082)
    continuous.add_argument("--duration-seconds", type=float, required=True)
    continuous.add_argument(
        "--completion-grace-seconds", type=float, default=120
    )
    continuous.add_argument("--record-bytes", type=parse_byte_count, default=MIB)
    continuous.add_argument("--send-sequence", type=int, default=30_000_000_000)
    continuous.add_argument("--receive-sequence", type=int, default=40_000_000_000)
    continuous.add_argument("--progress-timeout", type=float, default=30)
    continuous.add_argument("--progress-file", required=True, type=Path)
    continuous.add_argument("--progress-interval", type=float, default=1)
    continuous.add_argument("--stop-file", type=Path)
    continuous.set_defaults(function=run_continuous_client)

    progress = subcommands.add_parser("wait-progress")
    progress.add_argument("--progress-file", required=True, type=Path)
    progress.add_argument("--receive-sequence", required=True, type=int)
    progress.add_argument("--minimum-received-bytes", type=int, default=1)
    progress.add_argument("--after-received-bytes", type=int)
    progress.add_argument("--timeout-seconds", type=float, default=30)
    progress.set_defaults(function=wait_progress_command)

    continuous_progress = subcommands.add_parser("inspect-continuous")
    continuous_progress.add_argument("--progress-file", required=True, type=Path)
    continuous_progress.set_defaults(function=inspect_continuous_command)
    pid_signal = subcommands.add_parser("signal-pid")
    pid_signal.add_argument("--pid", required=True, type=int)
    pid_signal.add_argument("--start-ticks", required=True, type=int)
    pid_signal.add_argument("--signal", required=True, choices=("TERM", "KILL"))
    pid_signal.set_defaults(function=signal_pid_command)
    return root


if __name__ == "__main__":
    arguments = parser().parse_args()
    arguments.function(arguments)
