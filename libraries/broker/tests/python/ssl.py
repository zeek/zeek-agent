import unittest
import multiprocessing
import sys
import time
import os.path

import broker

def data_path(file):
    base = os.path.realpath(__file__)
    return os.path.join(os.path.join(os.path.dirname(base), "certs"), file)

class TestSSL(unittest.TestCase):
    def check_ping(self, ep1, s1, ep2, s2):
        ep2.publish("/test", ["ping"])
        (t, d) = s1.get()
        self.assertEqual(t, "/test")
        self.assertEqual(d[0], "ping")

        ep1.publish(t, ["pong"])
        (t, d) = s2.get()
        self.assertEqual(t, "/test")
        self.assertEqual(d[0], "pong")

    def test_ssl_auth_success_ca(self):
        cfg = broker.Configuration(broker.BrokerOptions())
        cfg.openssl_certificate = data_path("cert.1.pem")
        cfg.openssl_key = data_path("key.1.pem")
        cfg.openssl_cafile = data_path("ca.pem")

        ep1 = broker.Endpoint(cfg)
        ep2 = broker.Endpoint(cfg)
        s1 = ep1.make_subscriber("/test")
        s2 = ep2.make_subscriber("/test")
        port = ep1.listen("127.0.0.1", 0)
        r = ep2.peer("127.0.0.1", port, 0)
        self.assertEqual(r, True)

        self.check_ping(ep1, s1, ep2, s2)

        ep1.shutdown()
        ep2.shutdown()

    def test_ssl_auth_success_ca_pw(self):
        cfg = broker.Configuration(broker.BrokerOptions())
        cfg.openssl_certificate = data_path("cert.1.pem")
        cfg.openssl_key = data_path("key.1.enc.pem")
        cfg.openssl_cafile = data_path("ca.pem")
        cfg.openssl_passphrase = "12345"

        ep1 = broker.Endpoint(cfg)
        ep2 = broker.Endpoint(cfg)
        s1 = ep1.make_subscriber("/test")
        s2 = ep2.make_subscriber("/test")
        port = ep1.listen("127.0.0.1", 0)
        r = ep2.peer("127.0.0.1", port, 0)
        self.assertEqual(r, True)

        self.check_ping(ep1, s1, ep2, s2)

        ep1.shutdown()
        ep2.shutdown()

    def test_ssl_auth_success_self_signed(self):
        cfg = broker.Configuration(broker.BrokerOptions())
        cfg.openssl_certificate = data_path("cert.self-signed.pem")
        cfg.openssl_key = data_path("key.self-signed.pem")
        cfg.openssl_cafile = data_path("cert.self-signed.pem")

        ep1 = broker.Endpoint(cfg)
        ep2 = broker.Endpoint(cfg)
        s1 = ep1.make_subscriber("/test")
        s2 = ep2.make_subscriber("/test")
        port = ep1.listen("127.0.0.1", 0)
        r = ep2.peer("127.0.0.1", port, 0)
        self.assertEqual(r, True)

        self.check_ping(ep1, s1, ep2, s2)

        ep1.shutdown()
        ep2.shutdown()

    def test_ssl_auth_failure_self_signed(self):
        cfg1 = broker.Configuration(broker.BrokerOptions())
        cfg1.openssl_certificate = data_path("cert.1.pem")
        cfg1.openssl_key = data_path("key.1.pem")
        cfg1.openssl_cafile = data_path("ca.pem")

        cfg2 = broker.Configuration(broker.BrokerOptions())
        cfg2.openssl_certificate = data_path("cert.self-signed.pem")
        cfg2.openssl_key = data_path("key.self-signed.pem")
        cfg2.openssl_cafile = data_path("cert.self-signed.pem")

        ep1 = broker.Endpoint(cfg1)
        ep2 = broker.Endpoint(cfg2)
        port = ep1.listen("127.0.0.1", 0)
        r = ep2.peer("127.0.0.1", port, 0)
        self.assertEqual(r, False)

        ep1 = broker.Endpoint(cfg2)
        ep2 = broker.Endpoint(cfg1)
        port = ep1.listen("127.0.0.1", 0)
        r = ep2.peer("127.0.0.1", port, 0)
        self.assertEqual(r, False)

        ep1.shutdown()
        ep2.shutdown()

    def test_ssl_auth_failure_no_auth(self):
        cfg1 = broker.Configuration(broker.BrokerOptions())
        cfg1.openssl_certificate = data_path("cert.1.pem")
        cfg1.openssl_key = data_path("key.1.pem")
        cfg1.openssl_cafile = data_path("ca.pem")

        cfg2 = broker.Configuration(broker.BrokerOptions())

        ep1 = broker.Endpoint(cfg1)
        ep2 = broker.Endpoint(cfg2)
        port = ep1.listen("127.0.0.1", 0)
        r = ep2.peer("127.0.0.1", port, 0)
        self.assertEqual(r, False)

        ep1 = broker.Endpoint(cfg2)
        ep2 = broker.Endpoint(cfg1)
        port = ep1.listen("127.0.0.1", 0)
        r = ep2.peer("127.0.0.1", port, 0)
        self.assertEqual(r, False)

    def test_ssl_auth_failure_no_ssl(self):
        cfg1 = broker.Configuration(broker.BrokerOptions())
        cfg1.openssl_certificate = data_path("cert.1.pem")
        cfg1.openssl_key = data_path("key.1.pem")
        cfg1.openssl_cafile = data_path("ca.pem")

        cfg2 = broker.Configuration(broker.BrokerOptions())

        ep1 = broker.Endpoint(cfg1)
        ep2 = broker.Endpoint(cfg2)
        port = ep1.listen("127.0.0.1", 0)
        r = ep2.peer("127.0.0.1", port, 0)
        self.assertEqual(r, False)

        ep1 = broker.Endpoint(cfg2)
        ep2 = broker.Endpoint(cfg1)
        port = ep1.listen("127.0.0.1", 0)
        r = ep2.peer("127.0.0.1", port, 0)
        self.assertEqual(r, False)

    def XXXtest_ssl_auth_failure_ca_pw(self):
        cfg = broker.Configuration(broker.BrokerOptions())
        cfg.openssl_certificate = data_path("cert.1.pem")
        cfg.openssl_key = data_path("key.1.enc.pem")
        cfg.openssl_cafile = data_path("ca.pem")
        cfg.openssl_passphrase = "WRONG PASSWORD"

        ep1 = broker.Endpoint(cfg)
        ep2 = broker.Endpoint(cfg)
        port = ep1.listen("127.0.0.1", 0)

        # TODO: This correctly generates an exception in CAF, for which I
        # don't know where to catch it.
        r = ep2.peer("127.0.0.1", port, 0)
        self.assertEqual(r, False)

        ep1.shutdown()
        ep2.shutdown()

if __name__ == '__main__':
    unittest.main(verbosity=3)
