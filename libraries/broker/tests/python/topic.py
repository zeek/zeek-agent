
import unittest

import broker

class TestTopic(unittest.TestCase):
    def test_string(self):
        t = broker.Topic("/a/b/c")
        self.assertEqual(str(t), "/a/b/c")
        self.assertEqual(t.string(), "/a/b/c")

    def test_append(self):
        t1 = broker.Topic("/a/")
        t2 = broker.Topic("/b/c")
        t3 = t1 / t2
        t2 /= t1

        self.assertEqual(t3.string(), "/a/b/c")
        self.assertEqual(t2.string(), "/b/c/a")

if __name__ == '__main__':
  unittest.main(verbosity=3)
