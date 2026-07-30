import hashlib
import math
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

import a11_b22


class ProtocolTests(unittest.TestCase):
    def test_payload_is_deterministic_and_exact_length(self):
        payload = b"".join(a11_b22.payload_chunks(42, 100_003))
        self.assertEqual(len(payload), 100_003)
        self.assertEqual(hashlib.sha256(payload).digest(), a11_b22.digest_for(42, len(payload)))

    def test_payload_is_unique_by_sequence_and_chunk_position(self):
        length = 2 * a11_b22.CHUNK_SIZE + 17
        first = list(a11_b22.payload_chunks(41, length))
        second = list(a11_b22.payload_chunks(42, length))
        self.assertNotEqual(first[0], first[1])
        self.assertNotEqual(first[0], second[0])
        self.assertEqual(len(first[-1]), 17)

    def test_exchange_detects_no_corruption(self):
        client, server = socket.socketpair()
        thread = threading.Thread(target=a11_b22.handle_tcp, args=(server,))
        thread.start()
        with client:
            a11_b22.exchange(client, 7, 1_000_003, half_close=True)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())

    def test_health_classifies_transport_and_integrity_failures(self):
        args = SimpleNamespace(source="source", destination="destination", tcp_port=1)
        with mock.patch.object(a11_b22, "one_flow", side_effect=OSError("unavailable")):
            with self.assertRaises(SystemExit) as transport:
                a11_b22.health(args)
        self.assertEqual(transport.exception.code, 75)

        with mock.patch.object(a11_b22, "one_flow", side_effect=AssertionError("corrupt")):
            with self.assertRaises(SystemExit) as integrity:
                a11_b22.health(args)
        self.assertEqual(integrity.exception.code, 76)

        with mock.patch.object(a11_b22, "one_flow") as flow:
            a11_b22.health(args)
        flow.assert_called_once_with("source", "destination", 1, 9_000_000)

    def test_server_reports_digest_corruption_as_integrity_failure(self):
        client, server = socket.socketpair()
        thread = threading.Thread(target=a11_b22.handle_tcp, args=(server,))
        thread.start()
        with client:
            client.sendall(a11_b22.HEADER.pack(17, 3) + b"bad" + bytes(a11_b22.DIGEST_SIZE))
            response = a11_b22.recv_exact(client, a11_b22.HEADER.size + a11_b22.DIGEST_SIZE)
        sequence, status = a11_b22.HEADER.unpack(response[: a11_b22.HEADER.size])
        self.assertEqual(sequence, 17)
        self.assertEqual(status, a11_b22.STATUS_DIGEST_MISMATCH)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())

    def test_server_rejects_wrong_sequence_payload_with_matching_digest(self):
        client, server = socket.socketpair()
        thread = threading.Thread(target=a11_b22.handle_tcp, args=(server,))
        thread.start()
        wrong = b"".join(a11_b22.payload_chunks(18, 1024))
        with client:
            client.sendall(
                a11_b22.HEADER.pack(17, len(wrong))
                + wrong
                + hashlib.sha256(wrong).digest()
            )
            response = a11_b22.recv_exact(
                client, a11_b22.HEADER.size + a11_b22.DIGEST_SIZE
            )
        sequence, status = a11_b22.HEADER.unpack(response[: a11_b22.HEADER.size])
        self.assertEqual(sequence, 17)
        self.assertEqual(status, a11_b22.STATUS_DIGEST_MISMATCH)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())

    def test_udp_echo_requires_source_digest_and_in_range_sequence(self):
        port = 18081
        destination = "192.0.2.10"
        sequence = 7
        wire = (
            sequence.to_bytes(8, "big")
            + a11_b22.digest_for(sequence, 64)
        )
        self.assertEqual(
            a11_b22.valid_udp_echo(
                wire, (destination, port), destination, port, 10
            ),
            sequence,
        )
        self.assertIsNone(
            a11_b22.valid_udp_echo(
                wire, ("192.0.2.11", port), destination, port, 10
            )
        )
        corrupted = wire[:-1] + bytes([wire[-1] ^ 1])
        self.assertIsNone(
            a11_b22.valid_udp_echo(
                corrupted, (destination, port), destination, port, 10
            )
        )
        self.assertIsNone(
            a11_b22.valid_udp_echo(
                wire, (destination, port), destination, port, sequence
            )
        )

    def test_client_rejects_unbounded_or_nonfinite_probe_options_before_io(self):
        base = dict(
            source="source",
            destination="destination",
            tcp_port=1,
            udp_port=1,
            records=1,
            record_bytes=1,
            pipeline_window=1,
            concurrency=1,
            bulk_bytes=1,
            udp_packets=1,
            udp_interval_ms=1,
            udp_wait_seconds=1,
            min_udp_ratio=1,
        )
        for key, value in (
            ("records", a11_b22.MAX_RECORDS + 1),
            ("concurrency", a11_b22.MAX_CONCURRENCY + 1),
            ("pipeline_window", a11_b22.MAX_PIPELINE_WINDOW + 1),
            ("udp_packets", a11_b22.MAX_UDP_PACKETS + 1),
            ("udp_interval_ms", math.nan),
            ("min_udp_ratio", math.inf),
        ):
            values = dict(base)
            values[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    a11_b22.client(SimpleNamespace(**values))


if __name__ == "__main__":
    unittest.main()
