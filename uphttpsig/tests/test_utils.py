#!/usr/bin/env python
import os
import sys
import unittest
from uphttpsig.utils import get_fingerprint

from uphttpsig.tests.keys import RSA_PUBLIC_KEY

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestUtils(unittest.TestCase):

    def test_get_fingerprint(self):
        key = RSA_PUBLIC_KEY.decode("ascii")
        fingerprint = get_fingerprint(key)
        self.assertRegex(fingerprint, r"^([0-9a-f]{2}:){15}[0-9a-f]{2}$")
