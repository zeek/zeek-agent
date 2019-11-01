
# This is needed in order to use the "ipaddress" module on Python 2.7.
from __future__ import unicode_literals

import unittest
import multiprocessing
import sys
import time
import ipaddress

import broker

class TestCommunication(unittest.TestCase):
    def test_ping(self):
        # --peer-start
        ep1 = broker.Endpoint()
        ep2 = broker.Endpoint()

        s1 = ep1.make_subscriber("/test")
        s2 = ep2.make_subscriber("/test")

        port = ep1.listen("127.0.0.1", 0)
        ep2.peer("127.0.0.1", port, 1.0)

        # --peer-end

        # --ping-start
        ep2.publish("/test", ["ping"])
        (t, d) = s1.get()
        # t == "/test", d == ["ping"]
        # --ping-end
        self.assertEqual(t, "/test")
        self.assertEqual(d[0], "ping")

        ep1.publish(t, ["pong"])
        (t, d) = s2.get()
        self.assertEqual(t, "/test")
        self.assertEqual(d[0], "pong")

        ep1.shutdown()
        ep2.shutdown()

    def test_messages(self):
        ep1 = broker.Endpoint()
        ep2 = broker.Endpoint()
        s1 = ep1.make_subscriber("/test")
        port = ep1.listen("127.0.0.1", 0)
        ep2.peer("127.0.0.1", port, 1.0)

        msg0 = ("/test/1", ())
        ep2.publish(*msg0)

        # --messages-start
        msg1 = ("/test/2", (1, 2, 3))
        msg2 = ("/test/3", (42, "foo", {"a": "A", "b": ipaddress.IPv4Address('1.2.3.4')}))
        ep2.publish_batch(msg1, msg2)
        # --messages-end

        msgs = s1.get(3)
        self.assertFalse(s1.available())

        self.assertEqual(msgs[0], msg0)
        self.assertEqual(msgs[1], msg1)
        self.assertEqual(msgs[2], msg2)

        ep1.shutdown()
        ep2.shutdown()

    def test_publisher(self):
        ep1 = broker.Endpoint()
        ep2 = broker.Endpoint()
        s1 = ep1.make_subscriber("/test")
        p2 = ep2.make_publisher("/test")
        port = ep1.listen("127.0.0.1", 0)
        ep2.peer("127.0.0.1", port, 1.0)

        p2.publish([1, 2, 3])
        p2.publish_batch(["a", "b", "c"], [True, False])

        msgs = s1.get(3)
        self.assertFalse(s1.available())

        self.assertEqual(msgs[0], ("/test", (1, 2, 3)))
        self.assertEqual(msgs[1], ("/test", ("a", "b", "c")))
        self.assertEqual(msgs[2], ("/test", (True, False)))

        ep1.shutdown()
        ep2.shutdown()

    def test_status_subscriber(self):
        # --status-start
        ep1 = broker.Endpoint()
        ep2 = broker.Endpoint()
        es1 = ep1.make_status_subscriber(True)
        es2 = ep2.make_status_subscriber(True)
        port = ep1.listen("127.0.0.1", 0)
        ep2.peer("127.0.0.1", port, 1.0)
        st1 = es1.get()
        st2 = es2.get()
        # st1.code() == broker.SC.PeerAdded, st2.code() == broker.SC.PeerAdded
        # --status-end

        self.assertEqual(st1.code(), broker.SC.PeerAdded)
        self.assertEqual(st1.context().network.get().address, "127.0.0.1")
        self.assertEqual(st2.code(), broker.SC.PeerAdded)
        self.assertEqual(st2.context().network.get().address, "127.0.0.1")

        ep1.shutdown()
        ep2.shutdown()

    def test_status_subscriber_error(self):
        # --error-start
        ep1 = broker.Endpoint()
        es1 = ep1.make_status_subscriber()
        r = ep1.peer("127.0.0.1", 1947, 0.0) # Try unavailable port, no retry
        self.assertEqual(r, False) # Not shown in docs.
        st1 = es1.get()
        # s1.code() == broker.EC.PeerUnavailable
        # --error-end
        self.assertEqual(st1.code(), broker.EC.PeerUnavailable)

        # Async version.
        ep1.peer_nosync("127.0.0.1", 1947, 1.0)
        st1 = es1.get()
        self.assertEqual(st1.code(), broker.EC.PeerUnavailable)

        st1 = es1.get()
        self.assertEqual(st1.code(), broker.EC.PeerUnavailable)

        ep1.shutdown()

    def test_idle_endpoint(self):
        ep1 = broker.Endpoint()
        es1 = ep1.make_status_subscriber()
        s1 = ep1.make_subscriber("/test")
        ep1.shutdown()

if __name__ == '__main__':
    unittest.main(verbosity=3)
