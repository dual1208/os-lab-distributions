import contextlib
import hashlib
import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

import stream_transport


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class GeneratorTests(unittest.TestCase):
    def test_size_parser_supports_four_to_eight_gibibytes(self):
        self.assertEqual(stream_transport.parse_byte_count("4GiB"), 4 * stream_transport.GIB)
        self.assertEqual(stream_transport.parse_byte_count("8gib"), 8 * stream_transport.GIB)
        with self.assertRaises(ValueError):
            stream_transport.parse_byte_count("9GiB")

    def test_chunks_are_exact_length_and_sequence_unique(self):
        length = 2 * stream_transport.CHUNK_SIZE + 17
        first = list(stream_transport.payload_chunks(41, length))
        second = list(stream_transport.payload_chunks(42, length))
        self.assertEqual(sum(map(len, first)), length)
        self.assertNotEqual(first[0], first[1])
        self.assertNotEqual(first[0], second[0])
        self.assertEqual(len(first[-1]), 17)

    def test_eight_gibibyte_generator_is_lazy_and_chunk_bounded(self):
        chunks = stream_transport.payload_chunks(7, 8 * stream_transport.GIB)
        self.assertEqual(len(next(chunks)), stream_transport.CHUNK_SIZE)
        last_index = (8 * stream_transport.GIB // stream_transport.CHUNK_SIZE) - 1
        last = stream_transport.payload_chunk(
            7,
            last_index,
            stream_transport.CHUNK_SIZE,
            8 * stream_transport.GIB,
        )
        self.assertEqual(len(last), stream_transport.CHUNK_SIZE)

    def test_streaming_digest_matches_bounded_reference(self):
        length = 3 * stream_transport.CHUNK_SIZE + 101
        reference = hashlib.sha256(
            b"".join(stream_transport.payload_chunks(88, length))
        ).digest()
        self.assertEqual(stream_transport.stream_digest(88, length), reference)


class DeadlineTests(unittest.TestCase):
    def test_progress_deadline_resets_only_after_bytes(self):
        clock = FakeClock()
        phase = stream_transport.PhaseDeadline(100, clock=clock)
        progress = stream_transport.ProgressDeadline(phase, 5, clock=clock)
        clock.now += 4
        progress.advance(64)
        clock.now += 4
        self.assertGreater(progress.wait_timeout(), 0)
        clock.now += 2
        with self.assertRaises(stream_transport.ProgressDeadlineExceeded):
            progress.wait_timeout()

    def test_whole_phase_deadline_wins_even_with_recent_progress(self):
        clock = FakeClock()
        phase = stream_transport.PhaseDeadline(5, clock=clock)
        progress = stream_transport.ProgressDeadline(phase, 100, clock=clock)
        clock.now += 6
        progress.advance(1)
        with self.assertRaises(stream_transport.PhaseDeadlineExceeded):
            progress.wait_timeout()

    def test_blocked_receive_enforces_progress_deadline(self):
        receiver, idle_peer = socket.socketpair()
        try:
            receiver.setblocking(False)
            phase = stream_transport.PhaseDeadline(1)
            progress = stream_transport.ProgressDeadline(phase, 0.05)
            started = time.monotonic()
            with self.assertRaises(stream_transport.ProgressDeadlineExceeded):
                stream_transport.receive_exact(receiver, 1, progress)
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            receiver.close()
            idle_peer.close()


class ProgressEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        if os.name == "posix":
            self.root.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def test_reporter_publishes_atomic_bounded_receive_progress(self):
        path = self.root / "progress.json"
        ticks = iter((1_000_000_000, 1_200_000_000, 1_300_000_000))
        reporter = stream_transport.ProgressReporter(
            path, 77, interval_seconds=0.1, clock_ns=lambda: next(ticks),
        )
        reporter.advance(64)
        reporter.advance(128)
        reporter.finish()
        value = stream_transport.read_progress(path)
        self.assertEqual(value["format"], stream_transport.PROGRESS_FORMAT)
        self.assertEqual(value["receive_sequence"], 77)
        self.assertEqual(value["received_bytes"], 192)
        self.assertEqual(value["monotonic_ns"], 1_300_000_000)
        self.assertLessEqual(path.stat().st_size, stream_transport.MAX_PROGRESS_BYTES)
        if os.name == "posix":
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.root.glob(".progress.json.*")), [])

    def test_wait_binds_sequence_and_requires_strict_new_progress(self):
        path = self.root / "progress.json"
        reporter = stream_transport.ProgressReporter(path, 88)
        reporter.advance(100)
        current = stream_transport.wait_for_progress(
            path, receive_sequence=88, minimum_received_bytes=100,
            timeout_seconds=0.1,
        )
        self.assertEqual(current["received_bytes"], 100)
        with self.assertRaises(stream_transport.ProgressDeadlineExceeded):
            stream_transport.wait_for_progress(
                path, receive_sequence=88, after_received_bytes=100,
                timeout_seconds=0.05,
            )
        with self.assertRaises(stream_transport.ProgressEvidenceError):
            stream_transport.wait_for_progress(
                path, receive_sequence=89, timeout_seconds=0.05,
            )

    def test_both_full_duplex_receivers_publish_independent_progress(self):
        client, server = socket.socketpair()
        client_path = self.root / "b-to-a.json"
        server_path = self.root / "a-to-b.json"
        client_reporter = stream_transport.ProgressReporter(client_path, 900)
        server_reporter = stream_transport.ProgressReporter(server_path, 500)
        server_result = []
        server_error = []

        def serve():
            with server:
                try:
                    server_result.extend(stream_transport.serve_connection(
                        server, progress_timeout=2, phase_timeout=10,
                        progress_reporter=server_reporter,
                    ))
                except BaseException as error:
                    server_error.append(error)
                finally:
                    server_reporter.finish()

        worker = threading.Thread(target=serve)
        worker.start()
        with client:
            client_result = stream_transport.run_client_session(
                client, rounds=1, send_bytes=stream_transport.CHUNK_SIZE + 13,
                receive_bytes=stream_transport.CHUNK_SIZE + 29,
                send_sequence=500, receive_sequence=900,
                progress_timeout=2, phase_timeout=10,
                progress_reporter=client_reporter,
            )
        client_reporter.finish()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(server_error, [])
        self.assertEqual(len(client_result), 1)
        self.assertEqual(len(server_result), 1)
        a_to_b = stream_transport.read_progress(server_path)
        b_to_a = stream_transport.read_progress(client_path)
        self.assertEqual(a_to_b["receive_sequence"], 500)
        self.assertEqual(a_to_b["received_bytes"], stream_transport.CHUNK_SIZE + 13)
        self.assertEqual(b_to_a["receive_sequence"], 900)
        self.assertEqual(b_to_a["received_bytes"], stream_transport.CHUNK_SIZE + 29)

    def test_reader_rejects_symlink_duplicate_and_expanded_schema(self):
        target = self.root / "target.json"
        target.write_text(
            json.dumps({
                "format": 1, "monotonic_ns": 1, "receive_sequence": 1,
                "received_bytes": 1,
            }),
            encoding="utf-8",
        )
        if os.name == "posix":
            target.chmod(0o600)
        link = self.root / "link.json"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaises(stream_transport.ProgressEvidenceError):
            stream_transport.read_progress(link)
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"format":1,"format":1,"monotonic_ns":1,'
            '"receive_sequence":1,"received_bytes":1}\n',
            encoding="utf-8",
        )
        if os.name == "posix":
            duplicate.chmod(0o600)
        with self.assertRaises(stream_transport.ProgressEvidenceError):
            stream_transport.read_progress(duplicate)
        expanded = self.root / "expanded.json"
        value = json.loads(target.read_text(encoding="utf-8"))
        value["address"] = "forbidden"
        expanded.write_text(json.dumps(value), encoding="utf-8")
        if os.name == "posix":
            expanded.chmod(0o600)
        with self.assertRaises(stream_transport.ProgressEvidenceError):
            stream_transport.read_progress(expanded)

    def test_continuously_progressing_send_does_not_mask_stalled_receive(self):
        client, peer = socket.socketpair()
        client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        peer_error = []

        def drain_sender_only():
            try:
                with peer:
                    header = bytearray()
                    while len(header) < stream_transport.SESSION_HEADER.size:
                        chunk = peer.recv(
                            stream_transport.SESSION_HEADER.size - len(header)
                        )
                        if not chunk:
                            return
                        header.extend(chunk)
                    while True:
                        time.sleep(0.01)
                        if not peer.recv(4096):
                            return
            except OSError as error:
                peer_error.append(error)

        worker = threading.Thread(target=drain_sender_only)
        worker.start()
        started = time.monotonic()
        with client:
            with self.assertRaises(stream_transport.ProgressDeadlineExceeded):
                stream_transport.run_client_session(
                    client,
                    rounds=1,
                    send_bytes=16 * stream_transport.MIB,
                    receive_bytes=1,
                    progress_timeout=0.15,
                    phase_timeout=1.5,
                )
        elapsed = time.monotonic() - started
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(peer_error, [])
        self.assertLess(elapsed, 0.75)

    def test_blocked_receive_enforces_whole_phase_deadline(self):
        receiver, idle_peer = socket.socketpair()
        try:
            receiver.setblocking(False)
            phase = stream_transport.PhaseDeadline(0.05)
            progress = stream_transport.ProgressDeadline(phase, 1)
            with self.assertRaises(stream_transport.PhaseDeadlineExceeded):
                stream_transport.receive_exact(receiver, 1, progress)
        finally:
            receiver.close()
            idle_peer.close()


class IntegrityTests(unittest.TestCase):
    def test_corrupted_sequence_unique_chunk_is_rejected(self):
        receiver, sender = socket.socketpair()
        length = 1024
        try:
            receiver.setblocking(False)
            expected = bytearray(stream_transport.payload_chunk(9, 0, length, length))
            expected[11] ^= 1
            sender.sendall(expected + hashlib.sha256(expected).digest())
            phase = stream_transport.PhaseDeadline(2)
            progress = stream_transport.ProgressDeadline(phase, 1)
            with self.assertRaises(stream_transport.IntegrityError):
                stream_transport.receive_stream(receiver, 9, length, progress)
        finally:
            receiver.close()
            sender.close()

    def test_server_rejects_invalid_reciprocal_acknowledgement(self):
        client, server = socket.socketpair()
        server_result = []
        server_error = []

        def serve():
            with server:
                try:
                    server_result.extend(
                        stream_transport.serve_connection(
                            server, progress_timeout=1, phase_timeout=2
                        )
                    )
                except BaseException as error:
                    server_error.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        empty_digest = hashlib.sha256().digest()
        with client:
            client.sendall(
                stream_transport.SESSION_HEADER.pack(
                    stream_transport.SESSION_MAGIC, 10, 0, 20, 0
                )
                + empty_digest
            )
            server_digest = bytearray()
            while len(server_digest) < stream_transport.DIGEST_SIZE:
                server_digest.extend(
                    client.recv(stream_transport.DIGEST_SIZE - len(server_digest))
                )
            self.assertEqual(bytes(server_digest), empty_digest)
            client.sendall(
                stream_transport.ACK.pack(
                    stream_transport.ACK_MAGIC, 20, bytes([1]) * 32
                )
            )
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(server_result, [])
        self.assertEqual(len(server_error), 1)
        self.assertIsInstance(server_error[0], stream_transport.IntegrityError)

    def test_long_lived_sequence_validator_rejects_gap_and_duplicate(self):
        validator = stream_transport.SequenceValidator()
        validator.accept(100)
        validator.accept(101)
        with self.assertRaises(stream_transport.ProtocolError):
            validator.accept(101)
        validator = stream_transport.SequenceValidator()
        validator.accept(100)
        with self.assertRaises(stream_transport.ProtocolError):
            validator.accept(102)

    def test_full_duplex_rounds_reuse_one_connection_and_match_hashes(self):
        client, server = socket.socketpair()
        server_result = []
        server_error = []

        def serve():
            with server:
                try:
                    server_result.extend(
                        stream_transport.serve_connection(
                            server, progress_timeout=2, phase_timeout=10
                        )
                    )
                except BaseException as error:
                    server_error.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        with client:
            client_result = stream_transport.run_client_session(
                client,
                rounds=3,
                send_bytes=2 * stream_transport.CHUNK_SIZE + 13,
                receive_bytes=stream_transport.CHUNK_SIZE + 29,
                send_sequence=500,
                receive_sequence=900,
                progress_timeout=2,
                phase_timeout=10,
            )
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(server_error, [])
        self.assertEqual(len(client_result), 3)
        self.assertEqual(len(server_result), 3)
        for client_round, server_round in zip(client_result, server_result):
            self.assertEqual(client_round.sent.digest, server_round.received.digest)
            self.assertEqual(client_round.received.digest, server_round.sent.digest)
            self.assertEqual(client_round.sent.length, server_round.received.length)
            self.assertEqual(client_round.received.length, server_round.sent.length)


class OneSessionServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        if os.name == "posix":
            self.root.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def test_progress_server_accepts_one_verified_session_and_exits(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        progress = self.root / "server-progress.json"
        args = types.SimpleNamespace(
            bind="127.0.0.1",
            port=port,
            max_stream_bytes=stream_transport.MIB,
            progress_timeout=1,
            phase_timeout=3,
            accept_timeout=1,
            progress_file=progress,
            progress_receive_sequence=501,
            progress_interval=0.001,
        )
        output = io.StringIO()
        errors = []

        def serve():
            try:
                with contextlib.redirect_stdout(output):
                    stream_transport.serve_session_once(args)
            except BaseException as error:
                errors.append(error)

        server = threading.Thread(target=serve)
        server.start()
        deadline = time.monotonic() + 1
        while True:
            try:
                conn = stream_transport.open_client(
                    "127.0.0.1", "127.0.0.1", port, 1, 3,
                )
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        with conn:
            result = stream_transport.run_client_session(
                conn,
                rounds=1,
                send_bytes=stream_transport.CHUNK_SIZE + 17,
                receive_bytes=stream_transport.CHUNK_SIZE + 31,
                send_sequence=501,
                receive_sequence=601,
                progress_timeout=1,
                phase_timeout=3,
            )
        server.join(timeout=2)
        self.assertFalse(server.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(result), 1)
        self.assertEqual(
            output.getvalue(), "PASS connections=1 reconnects=0 records=1\n",
        )
        evidence = stream_transport.read_progress(progress)
        self.assertEqual(evidence["receive_sequence"], 501)
        self.assertEqual(
            evidence["received_bytes"], stream_transport.CHUNK_SIZE + 17,
        )


class WorkerLifetimeTests(unittest.TestCase):
    def test_blocked_observer_cannot_retain_failed_client_process(self):
        module_directory = str(Path(stream_transport.__file__).resolve().parent)
        source = textwrap.dedent(
            f"""
            import socket
            import sys
            import threading

            sys.path.insert(0, {module_directory!r})
            import stream_transport

            client, peer = socket.socketpair()
            entered = threading.Event()
            never = threading.Event()

            class BlockingObserver:
                def advance(self, _count):
                    entered.set()
                    never.wait()

            def peer_task():
                header = bytearray()
                while len(header) < stream_transport.SESSION_HEADER.size:
                    chunk = peer.recv(
                        stream_transport.SESSION_HEADER.size - len(header)
                    )
                    if not chunk:
                        return
                    header.extend(chunk)
                if entered.wait(2):
                    peer.close()

            threading.Thread(target=peer_task, daemon=True).start()
            try:
                stream_transport._run_client_round(
                    client,
                    stream_transport.PhaseDeadline(3),
                    send_id=11,
                    send_bytes=stream_transport.CHUNK_SIZE,
                    receive_id=12,
                    receive_bytes=1,
                    progress_timeout=1,
                    send_observer=BlockingObserver(),
                )
            except BaseException:
                client.close()
                raise SystemExit(7 if entered.is_set() else 9)
            raise SystemExit(0)
            """
        )
        started = time.monotonic()
        completed = subprocess.run(
            [sys.executable, "-B", "-c", source],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertLess(time.monotonic() - started, 4)

    def test_blocked_server_observer_fails_at_phase_deadline(self):
        module_directory = str(Path(stream_transport.__file__).resolve().parent)
        source = textwrap.dedent(
            f"""
            import hashlib
            import socket
            import sys
            import threading

            sys.path.insert(0, {module_directory!r})
            import stream_transport

            server, peer = socket.socketpair()
            entered = threading.Event()
            never = threading.Event()

            class BlockingReporter:
                receive_sequence = 501

                def bind_phase(self, _phase):
                    return None

                def advance(self, _count):
                    entered.set()
                    never.wait()

            def peer_task():
                payload = stream_transport.payload_chunk(501, 0, 1, 1)
                peer.sendall(
                    stream_transport.SESSION_HEADER.pack(
                        stream_transport.SESSION_MAGIC, 501, 1, 601, 1,
                    )
                    + payload
                    + hashlib.sha256(payload).digest()
                )

            threading.Thread(target=peer_task, daemon=True).start()
            try:
                with server:
                    stream_transport.serve_connection(
                        server,
                        progress_timeout=0.1,
                        phase_timeout=0.25,
                        progress_reporter=BlockingReporter(),
                        collect_results=False,
                    )
            except stream_transport.PhaseDeadlineExceeded:
                raise SystemExit(7 if entered.is_set() else 9)
            raise SystemExit(0)
            """
        )
        started = time.monotonic()
        completed = subprocess.run(
            [sys.executable, "-B", "-c", source],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertLess(time.monotonic() - started, 2)
        self.assertNotIn("PASS", completed.stdout)

    def test_blocked_final_publication_fails_before_pass(self):
        module_directory = str(Path(stream_transport.__file__).resolve().parent)
        source = textwrap.dedent(
            f"""
            import os
            import sys
            import tempfile
            import threading

            sys.path.insert(0, {module_directory!r})
            import stream_transport

            entered = threading.Event()
            never = threading.Event()
            with tempfile.TemporaryDirectory() as directory:
                if os.name == "posix":
                    os.chmod(directory, 0o700)
                reporter = stream_transport.ProgressReporter(
                    os.path.join(directory, "progress.json"), 501,
                )
                reporter.bind_phase(stream_transport.PhaseDeadline(0.25))

                def blocked_publish(*_args):
                    entered.set()
                    never.wait()

                reporter._publish = blocked_publish
                try:
                    reporter.finish()
                except stream_transport.PhaseDeadlineExceeded:
                    raise SystemExit(7 if entered.is_set() else 9)
            raise SystemExit(0)
            """
        )
        started = time.monotonic()
        completed = subprocess.run(
            [sys.executable, "-B", "-c", source],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertLess(time.monotonic() - started, 2)
        self.assertNotIn("PASS", completed.stdout)


class ProcessIdentitySignalTests(unittest.TestCase):
    def test_proc_stat_parser_uses_the_final_command_delimiter(self):
        fields = [b"S"] + [b"1"] * 18 + [b"4242", b"0"]
        value = b"123 (name with ) delimiter) " + b" ".join(fields) + b"\n"
        self.assertEqual(stream_transport._parse_proc_start_ticks(value), 4242)
        with self.assertRaises(stream_transport.ProcessIdentityError):
            stream_transport._parse_proc_start_ticks(b"123 malformed\n")
        with self.assertRaises(stream_transport.ProcessIdentityError):
            stream_transport._parse_proc_start_ticks(
                b"x" * (stream_transport.MAX_PROC_STAT_BYTES + 1)
            )

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "Linux pidfd signaling is unavailable",
    )
    def test_pidfd_signal_rejects_mismatch_then_terminates_exact_process(self):
        child = subprocess.Popen(
            [sys.executable, "-B", "-c", "import time; time.sleep(30)"],
        )
        try:
            ticks = stream_transport.process_start_ticks(child.pid)
            with self.assertRaises(stream_transport.ProcessIdentityError):
                stream_transport.signal_process_identity(
                    child.pid, ticks + 1, signal.SIGTERM,
                )
            self.assertIsNone(child.poll())
            self.assertTrue(
                stream_transport.signal_process_identity(
                    child.pid, ticks, signal.SIGTERM,
                )
            )
            child.wait(timeout=5)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    def test_signal_identity_rejects_self_and_unapproved_signal(self):
        with self.assertRaises(stream_transport.ProcessIdentityError):
            stream_transport.signal_process_identity(
                os.getpid(), 1, signal.SIGTERM,
            )
        with self.assertRaises(stream_transport.ProcessIdentityError):
            stream_transport.signal_process_identity(1, 1, signal.SIGINT)

    def test_pidfd_signal_is_bracketed_by_matching_proc_identities(self):
        identity = (11, 22)
        with (
            mock.patch.object(stream_transport.os, "name", "posix"),
            mock.patch.object(stream_transport.os, "getpid", return_value=999),
            mock.patch.object(
                stream_transport, "_open_proc_process", side_effect=[10, 30],
            ) as opened,
            mock.patch.object(
                stream_transport, "_proc_identity",
                side_effect=[(identity, 4242), (identity, 4242)],
            ),
            mock.patch.object(
                stream_transport.os, "pidfd_open", return_value=20, create=True,
            ) as pidfd_open,
            mock.patch.object(
                stream_transport.signal, "pidfd_send_signal", create=True,
            ) as pidfd_signal,
            mock.patch.object(stream_transport.os, "close") as closed,
        ):
            self.assertTrue(
                stream_transport.signal_process_identity(123, 4242, signal.SIGTERM)
            )
        self.assertEqual(opened.call_count, 2)
        pidfd_open.assert_called_once_with(123, 0)
        pidfd_signal.assert_called_once_with(20, signal.SIGTERM, None, 0)
        self.assertCountEqual(
            [call.args[0] for call in closed.call_args_list], [10, 20, 30]
        )

    def test_pidfd_signal_rejects_identity_change_after_open(self):
        with (
            mock.patch.object(stream_transport.os, "name", "posix"),
            mock.patch.object(stream_transport.os, "getpid", return_value=999),
            mock.patch.object(
                stream_transport, "_open_proc_process", side_effect=[10, 30],
            ),
            mock.patch.object(
                stream_transport, "_proc_identity",
                side_effect=[((11, 22), 4242), ((11, 23), 4242)],
            ),
            mock.patch.object(
                stream_transport.os, "pidfd_open", return_value=20, create=True,
            ),
            mock.patch.object(
                stream_transport.signal, "pidfd_send_signal", create=True,
            ) as pidfd_signal,
            mock.patch.object(stream_transport.os, "close"),
            self.assertRaisesRegex(
                stream_transport.ProcessIdentityError, "changed around pidfd open",
            ),
        ):
            stream_transport.signal_process_identity(123, 4242, signal.SIGTERM)
        pidfd_signal.assert_not_called()

    def test_pidfd_signal_treats_a_disappearing_matching_target_as_done(self):
        with (
            mock.patch.object(stream_transport.os, "name", "posix"),
            mock.patch.object(stream_transport.os, "getpid", return_value=999),
            mock.patch.object(stream_transport, "_open_proc_process", return_value=10),
            mock.patch.object(
                stream_transport, "_proc_identity", side_effect=FileNotFoundError,
            ),
            mock.patch.object(
                stream_transport.os, "pidfd_open", create=True,
            ) as pidfd_open,
            mock.patch.object(
                stream_transport.signal, "pidfd_send_signal", create=True,
            ) as pidfd_signal,
            mock.patch.object(stream_transport.os, "close"),
        ):
            self.assertFalse(
                stream_transport.signal_process_identity(123, 4242, signal.SIGTERM)
            )
        pidfd_open.assert_not_called()
        pidfd_signal.assert_not_called()


class ContinuousSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        if os.name == "posix":
            self.root.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def test_one_socket_carries_contiguous_full_duplex_records_for_duration(self):
        client, server = socket.socketpair()
        progress = self.root / "continuous.json"
        server_records = []
        server_error = []

        def serve():
            with server:
                try:
                    stream_transport.serve_connection(
                        server,
                        progress_timeout=1,
                        phase_timeout=3,
                        collect_results=False,
                        result_observer=server_records.append,
                    )
                except BaseException as error:
                    server_error.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        with client:
            result = stream_transport.run_continuous_client_session(
                client,
                duration_seconds=0.05,
                completion_grace_seconds=1,
                record_bytes=4096,
                send_sequence=70_000,
                receive_sequence=80_000,
                progress_timeout=1,
                progress_file=progress,
                progress_interval=0.001,
            )
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(server_error, [])
        self.assertEqual(result["state"], "pass")
        self.assertEqual(result["tcp_connections"], 1)
        self.assertEqual(result["tcp_reconnects"], 0)
        self.assertGreater(result["records_completed"], 0)
        self.assertEqual(result["records_completed"], len(server_records))
        self.assertEqual(
            result["sent_bytes"], result["records_completed"] * 4096
        )
        self.assertEqual(
            result["received_bytes"], result["records_completed"] * 4096
        )
        self.assertEqual(
            result["last_send_sequence"],
            result["first_send_sequence"] + result["records_completed"] - 1,
        )
        self.assertEqual(
            result["last_receive_sequence"],
            result["first_receive_sequence"] + result["records_completed"] - 1,
        )
        self.assertGreaterEqual(
            result["updated_monotonic_ns"] - result["started_monotonic_ns"],
            50_000_000,
        )
        self.assertRegex(result["transcript_sha256"], r"^[a-f0-9]{64}$")

    def test_external_stop_is_honored_only_after_a_full_duplex_record_boundary(self):
        client, server = socket.socketpair()
        progress = self.root / "continuous.json"
        server_records = []
        server_error = []
        checks = []

        def serve():
            with server:
                try:
                    stream_transport.serve_connection(
                        server,
                        progress_timeout=1,
                        phase_timeout=3,
                        collect_results=False,
                        result_observer=server_records.append,
                    )
                except BaseException as error:
                    server_error.append(error)

        def stop_after_second_record():
            checks.append(True)
            return len(checks) == 2

        worker = threading.Thread(target=serve)
        worker.start()
        with client:
            result = stream_transport.run_continuous_client_session(
                client,
                duration_seconds=1,
                completion_grace_seconds=1,
                record_bytes=4096,
                send_sequence=90_000,
                receive_sequence=100_000,
                progress_timeout=1,
                progress_file=progress,
                progress_interval=0.001,
                stop_condition=stop_after_second_record,
            )
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(server_error, [])
        self.assertEqual(result["state"], "pass")
        self.assertEqual(result["records_completed"], 2)
        self.assertEqual(len(server_records), 2)
        self.assertEqual(result["sent_bytes"], 2 * 4096)
        self.assertEqual(result["received_bytes"], 2 * 4096)

    def test_missing_external_stop_fails_at_its_absolute_bound(self):
        client, server = socket.socketpair()
        progress = self.root / "continuous.json"
        server_error = []

        def serve():
            with server:
                try:
                    stream_transport.serve_connection(
                        server,
                        progress_timeout=1,
                        phase_timeout=2,
                        collect_results=False,
                    )
                except BaseException as error:
                    server_error.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        started = time.monotonic()
        with client:
            with self.assertRaises(stream_transport.PhaseDeadlineExceeded):
                stream_transport.run_continuous_client_session(
                    client,
                    duration_seconds=0.01,
                    completion_grace_seconds=1,
                    record_bytes=1024,
                    progress_timeout=1,
                    progress_file=progress,
                    progress_interval=0.001,
                    stop_condition=lambda: False,
                )
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(server_error, [])
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(
            stream_transport.read_continuous_progress(progress)["state"],
            "running",
        )

    def test_stop_marker_reader_rejects_noncanonical_or_unsafe_evidence(self):
        marker = self.root / "stop.marker"
        self.assertFalse(stream_transport.continuous_stop_requested(marker))
        marker.write_bytes(stream_transport.CONTINUOUS_STOP_MARKER)
        if os.name == "posix":
            marker.chmod(0o600)
        self.assertTrue(stream_transport.continuous_stop_requested(marker))

        marker.write_bytes(stream_transport.CONTINUOUS_STOP_MARKER + b"EXTRA")
        if os.name == "posix":
            marker.chmod(0o600)
        with self.assertRaises(stream_transport.ProgressEvidenceError):
            stream_transport.continuous_stop_requested(marker)

        marker.write_bytes(stream_transport.CONTINUOUS_STOP_MARKER)
        if os.name == "posix":
            marker.chmod(0o644)
            with self.assertRaises(stream_transport.ProgressEvidenceError):
                stream_transport.continuous_stop_requested(marker)

    def test_stop_marker_reader_rejects_a_symlink_substitution(self):
        target = self.root / "target.marker"
        target.write_bytes(stream_transport.CONTINUOUS_STOP_MARKER)
        if os.name == "posix":
            target.chmod(0o600)
        marker = self.root / "stop.marker"
        try:
            marker.symlink_to(target)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaises(stream_transport.ProgressEvidenceError):
            stream_transport.continuous_stop_requested(marker)

    def test_continuous_reader_rejects_expanded_or_false_connection_evidence(self):
        client, server = socket.socketpair()
        progress = self.root / "continuous.json"

        def serve():
            with server:
                stream_transport.serve_connection(
                    server,
                    progress_timeout=1,
                    phase_timeout=2,
                    collect_results=False,
                )

        worker = threading.Thread(target=serve)
        worker.start()
        with client:
            stream_transport.run_continuous_client_session(
                client,
                duration_seconds=0.01,
                completion_grace_seconds=1,
                record_bytes=1024,
                progress_timeout=1,
                progress_file=progress,
                progress_interval=0.001,
            )
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        value = json.loads(progress.read_text(encoding="utf-8"))
        for key, replacement in (
            ("tcp_connections", 2),
            ("tcp_reconnects", 1),
            ("last_send_sequence", value["last_send_sequence"] + 1),
            ("last_receive_sequence", value["last_receive_sequence"] + 1),
            ("transcript_sha256", "not-a-canonical-digest"),
        ):
            mutated = dict(value)
            mutated[key] = replacement
            progress.write_text(json.dumps(mutated), encoding="utf-8")
            if os.name == "posix":
                progress.chmod(0o600)
            with self.subTest(key=key):
                with self.assertRaises(stream_transport.ProgressEvidenceError):
                    stream_transport.read_continuous_progress(progress)
        expanded = dict(value)
        expanded["peer_address"] = "forbidden"
        progress.write_text(json.dumps(expanded), encoding="utf-8")
        if os.name == "posix":
            progress.chmod(0o600)
        with self.assertRaises(stream_transport.ProgressEvidenceError):
            stream_transport.read_continuous_progress(progress)


class ThroughputFloorTests(unittest.TestCase):
    def test_round_below_either_throughput_floor_fails(self):
        digest = bytes(32)
        result = stream_transport.RoundResult(
            sent=stream_transport.TransferResult(1, 125_000, digest, 1.0),
            received=stream_transport.TransferResult(2, 250_000, digest, 1.0),
        )
        stream_transport._enforce_throughput_floors(result, 1.0, 2.0)
        with self.assertRaises(stream_transport.ThroughputFloorError):
            stream_transport._enforce_throughput_floors(result, 1.001, 0)
        with self.assertRaises(stream_transport.ThroughputFloorError):
            stream_transport._enforce_throughput_floors(result, 0, 2.001)


if __name__ == "__main__":
    unittest.main()
