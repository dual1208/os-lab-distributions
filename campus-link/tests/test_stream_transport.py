import hashlib
import socket
import threading
import time
import unittest

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


