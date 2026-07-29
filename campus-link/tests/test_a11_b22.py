import hashlib
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


if __name__ == "__main__":
    unittest.main()
