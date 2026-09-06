"""Unit tests for LumiNet Core Python SDK."""

import unittest
from luminet import LumiCore, EvasionSocket


class TestLumiCoreSDK(unittest.TestCase):
    def setUp(self):
        self.core = LumiCore()

    def test_version_retrieval(self):
        v = self.core.version()
        self.assertIsInstance(v, int)
        self.assertGreaterEqual(v, 3)

    def test_scan_ports_contract(self):
        # Scan localhost loopback
        results = self.core.scan_ports("127.0.0.1", [80, 443], timeout_ms=500)
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertIn("port", r)
            self.assertIn("open", r)

    def test_detect_sni_contract(self):
        res = self.core.detect_sni("example.com", timeout_ms=500)
        self.assertIsInstance(res, dict)
        self.assertIn("domain", res)

    def test_evasion_socket_structure(self):
        sock = EvasionSocket(desync_offset=3, desync_delay_ms=10)
        self.assertEqual(sock.desync_offset, 3)
        self.assertEqual(sock.desync_delay_ms, 10)
        sock.close()


if __name__ == "__main__":
    unittest.main()
