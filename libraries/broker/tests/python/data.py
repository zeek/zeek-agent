#
# Testing the data conversion back and forth between broker.Data and Python.
# Note that the user will rarely see broker.Data instances directly. We make
# sure that the transparent conversion works as expected.
#

# This is needed in order to use the "ipaddress" module on Python 2.7.
from __future__ import unicode_literals

import datetime
import time
import math
import ipaddress
import sys
import unittest

import broker

# Check the Python version
py2 = (sys.version_info.major < 3)


class TestDataConstruction(unittest.TestCase):

    # Given a Python value 'p' and expected broker type 't', convert 'p' to
    # the corresponding broker type and verify that it has the correct type
    # and the expected string representation 's' (note this is not necessarily
    # the same as str(p)).
    def check_to_broker(self, p, s, t):
        assert not isinstance(p, broker.Data)
        b = broker.Data(p)
        #print("[to_broker] ({} / {}) -> ({} / {}) (expected: {} / {})".format(p, type(p), str(b), b.get_type(), s, t))

        if s is not None:
            self.assertEqual(str(b), s)

        self.assertEqual(b.get_type(), t)
        return b

    # Given a broker value 'b' and a Python value 'p', convert 'b' to the
    # corresponding python type, then verify that the type and value match
    # the original python value 'p'.
    def check_to_py(self, b, p):
        b2p = broker.Data.to_py(b)
        #print("[to_py] data({} / {}) -> ({} / {})".format(str(b), b.get_type(), b2p, type(b2p)))

        if py2:
            # Python 2.7 compatibility: convert objects of type 'int' to 'long'
            # to match the type returned by broker.Data.to_py(b)
            if isinstance(p, int) and not isinstance(p, bool):
                p = long(p)

            # Python 2.7 compatibility: convert objects of type 'str' to
            # 'unicode' to match the type returned by broker.Data.to_py(b)
            if isinstance(p, str):
                p = unicode(p)

        self.assertIsInstance(b2p, type(p))

        if isinstance(p, datetime.datetime):
            # Some pythons may have rounding issues converting datetime to
            # timestamp and back again.  https://bugs.python.org/issue23517

            if p.tzinfo:
                # Our test cases were explicit in using UTC
                self.assertEqual(b2p.tzinfo, p.tzinfo)

                self.assertEqual(b2p.year, p.year)
                self.assertEqual(b2p.month, p.month)
                self.assertEqual(b2p.day, p.day)
                self.assertEqual(b2p.hour, p.hour)
                self.assertEqual(b2p.minute, p.minute)
                self.assertEqual(b2p.second, p.second)

                us_equal = (b2p.microsecond == p.microsecond or
                            b2p.microsecond == p.microsecond - 1 or
                            b2p.microsecond == p.microsecond + 1)
                self.assertTrue(us_equal)
            else:
                # 'b2p' is in UTC and 'p' is assumed to be local time
                self.assertEqual(b2p.tzinfo, broker.utc)

                b2p_us = b2p.microsecond

                b2p_ts  = (b2p - datetime.datetime(1970, 1, 1, tzinfo=broker.utc)).total_seconds()
                b2p_ts = math.trunc(b2p_ts)

                p_us = p.microsecond

                p_ts = time.mktime(p.timetuple())

                self.assertEqual(b2p_ts, p_ts)

                us_equal = (b2p_us == p_us or
                            b2p_us == p_us - 1 or
                            b2p_us == p_us + 1)
                self.assertTrue(us_equal)

        else:
            self.assertEqual(b2p, p)

    def check_to_broker_and_back(self, p, s, t):
        b = self.check_to_broker(p, s, t)
        self.check_to_py(b, p)
        return b

    def test_bool(self):
        self.check_to_broker_and_back(True, 'T', broker.Data.Type.Boolean)
        self.check_to_broker_and_back(False, 'F', broker.Data.Type.Boolean)

    def test_integer(self):
        self.check_to_broker_and_back(42, '42', broker.Data.Type.Integer)

        self.check_to_broker_and_back(-42, '-42', broker.Data.Type.Integer)

        # Test a value that is beyond range of unsigned 32-bit integer (on
        # 32-bit python 2.x systems, this will be type 'long')
        self.check_to_broker_and_back(5123123123, '5123123123', broker.Data.Type.Integer)

        if py2:
            # Explicitly pass a 'long' value (this is not relevant for python 3)
            self.check_to_broker_and_back(long(5), '5', broker.Data.Type.Integer)

    def test_count(self):
        self.check_to_broker_and_back(broker.Count(42), '42', broker.Data.Type.Count)

        # Test a value that is beyond range of unsigned 32-bit integer (on
        # 32-bit python 2.x systems, this will be type 'long')
        self.check_to_broker_and_back(broker.Count(5123123123), '5123123123', broker.Data.Type.Count)

        if py2:
            # Explicitly pass a 'long' value (this is not relevant for python 3)
            self.check_to_broker_and_back(broker.Count(long(5)), '5', broker.Data.Type.Count)

    def test_count_overflow(self):
        with self.assertRaises(Exception) as context:
            # I've seen this raise either OverflowError or SystemError
            # depending on Python version is seems.
            self.check_to_broker(broker.Count(-1), '-1', broker.Data.Type.Count)

    def test_real(self):
        self.check_to_broker_and_back(1e18, '1000000000000000000.000000', broker.Data.Type.Real)
        self.check_to_broker_and_back(4.2, '4.200000', broker.Data.Type.Real)
        self.check_to_broker_and_back(-4.2, '-4.200000', broker.Data.Type.Real)

    def test_timespan(self):
        to_us = lambda x: x.microseconds + (x.seconds + x.days * 24 * 3600) * 10**6
        to_ns = lambda x: to_us(x) * 10**3

        # Setup timespan values
        neg1ms = datetime.timedelta(microseconds = -1000)
        neg1ms_ns = -1000 * 10**3
        self.assertEqual(neg1ms_ns, to_ns(neg1ms))

        neg42sec = datetime.timedelta(milliseconds = -42 * 10**3)
        neg42sec_ns = (-42 * 10**6) * 10**3
        self.assertEqual(neg42sec_ns, to_ns(neg42sec))

        pos1ms2us = datetime.timedelta(milliseconds = 1, microseconds = 2)
        pos1ms2us_ns = (1000 + 2) * 10**3
        self.assertEqual(pos1ms2us_ns, to_ns(pos1ms2us))

        pos1day2s3us = datetime.timedelta(days = 1, seconds = 2, microseconds = 3)
        pos1day2s3us_ns = (3 + (2 + 24 * 3600) * 10**6) * 10**3
        self.assertEqual(pos1day2s3us_ns, to_ns(pos1day2s3us))

        # Verify Timespan only
        self.assertEqual(broker.Timespan(neg1ms_ns), broker.Timespan(to_ns(neg1ms)))
        self.assertEqual(broker.Timespan(neg42sec_ns), broker.Timespan(to_ns(neg42sec)))
        self.assertEqual(broker.Timespan(pos1ms2us_ns), broker.Timespan(to_ns(pos1ms2us)))
        self.assertEqual(broker.Timespan(pos1day2s3us_ns), broker.Timespan(to_ns(pos1day2s3us)))

        # Verify Data
        self.check_to_broker_and_back(neg1ms, '-1000000ns', broker.Data.Type.Timespan)
        self.check_to_broker_and_back(neg42sec, '-42000000000ns', broker.Data.Type.Timespan)
        self.check_to_broker_and_back(pos1ms2us, '1002000ns', broker.Data.Type.Timespan)
        self.check_to_broker_and_back(pos1day2s3us, '86402000003000ns', broker.Data.Type.Timespan)

    def test_timestamp(self):
        self.check_to_broker(broker.now(), None, broker.Data.Type.Timestamp)

        today = datetime.datetime.now(broker.utc)
        self.check_to_broker_and_back(today, None, broker.Data.Type.Timestamp)

        if not py2:
            today = datetime.datetime.now(datetime.timezone.utc)
            self.check_to_broker_and_back(today, None, broker.Data.Type.Timestamp)

        today = datetime.datetime.now()
        self.check_to_broker_and_back(today, None, broker.Data.Type.Timestamp)

        past = datetime.datetime(1970, 1, 31, tzinfo=broker.utc)
        self.check_to_broker_and_back(past, None, broker.Data.Type.Timestamp)

        # Test a time value with number of seconds since Jan. 1 1970 beyond
        # the range of a signed 32-bit integer (the "year 2038 problem").
        future = datetime.datetime(2040, 1, 31, tzinfo=broker.utc)
        try:
            self.check_to_broker_and_back(future, None, broker.Data.Type.Timestamp)
        except OverflowError:
            # This test fails on some 32-bit systems (such as Debian 9 i386),
            # but for now we just ignore this failure.
            pass

    def test_string(self):
        self.check_to_broker_and_back('', '', broker.Data.Type.String)
        self.check_to_broker_and_back('foo', 'foo', broker.Data.Type.String)
        self.check_to_broker_and_back('\ttab', '\ttab', broker.Data.Type.String)
        self.check_to_broker_and_back('new\n', 'new\n', broker.Data.Type.String)

        if py2:
            # These test cases are not relevant for Python 3

            # Explicitly pass a 'unicode' value (this is relevant in case
            # unicode_literals isn't imported)
            self.check_to_broker_and_back(u'foo2', 'foo2', broker.Data.Type.String)

            # Explicitly pass a 'str' value (this is relevant in case
            # unicode_literals is imported)
            self.check_to_broker_and_back(str('foo3'), 'foo3', broker.Data.Type.String)

    def test_address_v4(self):
        addr = ipaddress.IPv4Address('0.0.0.0')
        self.check_to_broker_and_back(addr, '0.0.0.0', broker.Data.Type.Address)

        addr = ipaddress.IPv4Address('1.2.3.4')
        self.check_to_broker_and_back(addr, '1.2.3.4', broker.Data.Type.Address)

        addr = ipaddress.IPv4Address('255.255.255.255')
        self.check_to_broker_and_back(addr, '255.255.255.255', broker.Data.Type.Address)

    def test_address_v6(self):
        addr = ipaddress.IPv6Address('::')
        self.check_to_broker_and_back(addr, '::', broker.Data.Type.Address)

        addr = ipaddress.IPv6Address('::1')
        self.check_to_broker_and_back(addr, '::1', broker.Data.Type.Address)

        addr = ipaddress.IPv6Address('1:2:3:4:5:6:7:8')
        self.check_to_broker_and_back(addr, '1:2:3:4:5:6:7:8', broker.Data.Type.Address)

        addr = ipaddress.IPv6Address('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
        self.check_to_broker_and_back(addr, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', broker.Data.Type.Address)

    def test_subnet_v4(self):
        sn = ipaddress.IPv4Network('1.2.3.4/32')
        self.check_to_broker_and_back(sn, '1.2.3.4/32', broker.Data.Type.Subnet)

        sn = ipaddress.IPv4Network('10.0.0.0/8')
        self.check_to_broker_and_back(sn, '10.0.0.0/8', broker.Data.Type.Subnet)

        sn = ipaddress.IPv4Network('0.0.0.0/0')
        self.check_to_broker_and_back(sn, '0.0.0.0/0', broker.Data.Type.Subnet)

    def test_subnet_v6(self):
        sn = ipaddress.IPv6Network('::1/128')
        self.check_to_broker_and_back(sn, '::1/128', broker.Data.Type.Subnet)

        sn = ipaddress.IPv6Network('fc00::/7')
        self.check_to_broker_and_back(sn, 'fc00::/7', broker.Data.Type.Subnet)

        sn = ipaddress.IPv6Network('::/0')
        self.check_to_broker_and_back(sn, '::/0', broker.Data.Type.Subnet)

    def test_port(self):
        self.check_to_broker_and_back(broker.Port(65535, broker.Port.TCP), "65535/tcp", broker.Data.Type.Port)
        self.check_to_broker_and_back(broker.Port(53, broker.Port.UDP), "53/udp", broker.Data.Type.Port)
        self.check_to_broker_and_back(broker.Port(8, broker.Port.ICMP), "8/icmp", broker.Data.Type.Port)
        self.check_to_broker_and_back(broker.Port(0, broker.Port.Unknown), "0/?", broker.Data.Type.Port)

    def test_set(self):
        # Test an empty set
        self.check_to_broker_and_back(set(), '{}', broker.Data.Type.Set)

        # Test a simple set
        p = set([1, 2, 3])
        d = self.check_to_broker_and_back(p, '{1, 2, 3}', broker.Data.Type.Set)

        for (i, x) in enumerate(d.as_set()):
            self.check_to_broker(x, str(i + 1), broker.Data.Type.Integer)
            self.check_to_py(x, i + 1)

        # Test a set that contains various data types
        d = broker.Data(set(['foo', ipaddress.IPv6Address('::1'), None]))
        for (i, x) in enumerate(d.as_set()):
            if i == 1:
                self.check_to_broker(x, 'foo', broker.Data.Type.String)
                self.check_to_py(x, 'foo')
            elif i == 2:
                self.check_to_broker(x, '::1', broker.Data.Type.Address)
                self.check_to_py(x, ipaddress.IPv6Address('::1'))

        # Test some of our own methods on wrapped sets.
        d = broker.Data(set([1, 2, 3])).as_set()
        self.assertEqual(str(d), "Set{1, 2, 3}")
        d.remove(broker.Data(2))
        self.assertEqual(str(d), "Set{1, 3}")
        d.clear()
        self.assertEqual(str(d), "Set{}")

    def test_table(self):
        # Test an empty table
        self.check_to_broker_and_back({}, '{}', broker.Data.Type.Table)

        # Test a simple table
        p = {"a": 1, "b": 2, "c": 3}
        d = self.check_to_broker_and_back(p, '{a -> 1, b -> 2, c -> 3}', broker.Data.Type.Table)

        for (i, (k, v)) in enumerate(d.as_table().items()):
            self.check_to_broker(k, ["a", "b", "c"][i], broker.Data.Type.String)
            self.check_to_py(k, ["a", "b", "c"][i])
            self.check_to_broker(v, str(i + 1), broker.Data.Type.Integer)
            self.check_to_py(v, i + 1)

        # Test a table that contains different data types
        p = {True: 42, broker.Port(22, broker.Port.TCP): False, (1,2,3): [4,5,6]}
        d = self.check_to_broker(p, '{T -> 42, 22/tcp -> F, (1, 2, 3) -> (4, 5, 6)}', broker.Data.Type.Table)

        t = d.as_table()

        self.check_to_broker(t[broker.Data(True)], "42", broker.Data.Type.Integer)
        self.check_to_py(t[broker.Data(True)], 42)

        self.check_to_broker(t[broker.Data(broker.Port(22, broker.Port.TCP))], "F", broker.Data.Type.Boolean)
        self.check_to_py(t[broker.Data(broker.Port(22, broker.Port.TCP))], False)

        self.check_to_broker(t[broker.Data((1, 2, 3))], "(4, 5, 6)", broker.Data.Type.Vector)
        self.check_to_py(t[broker.Data([1, 2, 3])], (4, 5, 6))

    def test_vector(self):
        # Test an empty vector
        self.check_to_broker_and_back((), '()', broker.Data.Type.Vector)

        # Test a simple vector
        d = self.check_to_broker((1, 2, 3), '(1, 2, 3)', broker.Data.Type.Vector)
        # Either a list or a tuple are mapped to a Broker vector.
        d = self.check_to_broker([1, 2, 3], '(1, 2, 3)', broker.Data.Type.Vector)

        for (i, x) in enumerate(d.as_vector()):
            self.check_to_broker(x, str(i + 1), broker.Data.Type.Integer)
            self.check_to_py(x, i + 1)

        # Test a vector that contains various data types
        d = broker.Data(['foo', [[True]], ipaddress.IPv6Address('::1'), None])
        v = d.as_vector()
        self.check_to_broker(v[0], 'foo', broker.Data.Type.String)
        self.check_to_py(v[0], 'foo')

        v1 = v[1].as_vector()
        self.check_to_broker(v1, '((T))', broker.Data.Type.Vector)
        self.check_to_py(v[1], ((True,),))
        self.check_to_broker(v1[0], '(T)', broker.Data.Type.Vector)
        self.check_to_py(v1[0], (True,))

        self.check_to_broker(v[2], '::1', broker.Data.Type.Address)
        self.check_to_py(v[2], ipaddress.IPv6Address("::1"))

        self.check_to_broker(v[3], 'nil', broker.Data.Type.Nil)

if __name__ == '__main__':
    unittest.main(verbosity=3)
