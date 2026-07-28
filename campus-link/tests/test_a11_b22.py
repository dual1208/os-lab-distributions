import hashlib
import socket
import threading
import unittest

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


if __name__ == "__main__":
    unittest.main()
