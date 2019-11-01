
import unittest
import multiprocessing
import sys
import time

import broker

def setup_peers(opts1=None, opts2=None, opts3=None, opts4=None, create_s1=True, create_s2=True, create_s3=True, create_s4=True):
    def cfg(opts):
        return broker.Configuration(opts) if opts else broker.Configuration(broker.BrokerOptions())
    ep1 = broker.Endpoint(cfg(opts1))
    ep2 = broker.Endpoint(cfg(opts2))
    ep3 = broker.Endpoint(cfg(opts3))
    ep4 = broker.Endpoint(cfg(opts4))

    s1 = ep1.make_subscriber("/test/") if create_s1 else None
    s2 = ep2.make_subscriber("/test/") if create_s2 else None
    s3 = ep3.make_subscriber("/test/") if create_s3 else None
    s4 = ep4.make_subscriber("/test/") if create_s4 else None

    p2 = ep2.listen("127.0.0.1", 0)
    p3 = ep3.listen("127.0.0.1", 0)
    p4 = ep4.listen("127.0.0.1", 0)

    # ep1 <-> ep2 <-> ep3 <-> ep4
    ep1.peer("127.0.0.1", p2, 1.0)
    ep2.peer("127.0.0.1", p3, 1.0)
    ep3.peer("127.0.0.1", p4, 1.0)

    return ((ep1, ep2, ep3, ep4), (s1, s2, s3, s4))

class TestCommunication(unittest.TestCase):
    def test_two_hops(self):
        # Two hops that are subscribed, so they'll forward.
        ((ep1, ep2, ep3, ep4), (s1, s2, s3, s4)) = setup_peers()

        ep1.publish("/test/foo", "Foo!")
        ep4.publish("/test/bar", "Bar!")

        x = s4.get()
        self.assertEqual(x, ('/test/foo', 'Foo!'))
        x = s1.get()
        self.assertEqual(x, ('/test/bar', 'Bar!'))

    def test_two_hops_with_forward(self):
        # Two hops that are not subscribed, but configured to forward.
        ((ep1, ep2, ep3, ep4), (s1, s2, s3, s4)) = setup_peers(create_s2=False, create_s3=False)

        ep2.forward("/test/");
        ep3.forward("/test/");
        time.sleep(1) # give time to take effect.

        ep1.publish("/test/foo", "Foo!")
        ep4.publish("/test/bar", "Bar!")

        x = s4.get()
        self.assertEqual(x, ('/test/foo', 'Foo!'))
        x = s1.get()
        self.assertEqual(x, ('/test/bar', 'Bar!'))

    def test_two_hops_forwarding_disabled(self):
        # Two hops that are subscribed, so they would forward but we disable.
        no_forward = broker.BrokerOptions()
        no_forward.forward = False

        ((ep1, ep2, ep3, ep4), (s1, s2, s3, s4)) = setup_peers(opts2=no_forward)

        ep1.publish("/test/foo", "Foo!") # Shouldn't arrive
        x = s4.get(1.0)
        self.assertEqual(x, None)

    def test_two_hops_without_forward(self):
        # Two hops that are not subscribed, and hence don't forward.
        ((ep1, ep2, ep3, ep4), (s1, s2, s3, s4)) = setup_peers(create_s2=False, create_s3=False)

        ep1.publish("/test/foo", "Foo!")
        x = s4.get(1.0)
        self.assertEqual(x, None)

    def test_two_hops_ttl(self):
        ttl1 = broker.BrokerOptions()
        ttl1.ttl = 2
        ((ep1, ep2, ep3, ep4), (s1, s2, s3, s4)) = setup_peers(opts1=ttl1)

        ep1.publish("/test/foo", "Foo!")

        x = s2.get(1.0)
        self.assertEqual(x, ('/test/foo', 'Foo!'))
        x = s3.get(1.0)
        self.assertEqual(x, ('/test/foo', 'Foo!'))
        x = s4.get(1.0)
        self.assertEqual(x, None) # Doesn't get here anymore.

if __name__ == '__main__':
    #TestCommunication().test_two_hops()
    unittest.main(verbosity=3)
