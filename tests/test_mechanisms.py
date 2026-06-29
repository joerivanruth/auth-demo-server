import subprocess
import sys
from unittest import TestCase

from util import (
    running_demoserver,
    needs_kerberos,
)


class MechanismTests(TestCase):
    """
    Tests for the various mechanisms
    """
    @needs_kerberos
    def test_gssapi(self):
        self.run_mechanism_test('GSSAPI')

    def run_mechanism_test(self, mechname):
        with running_demoserver() as url:
            cmd = [sys.executable, 'democlient.py', '-v', url, '-m', mechname]
            subprocess.check_call(cmd)

    @needs_kerberos
    def test_naive_gssapi(self):
        self.run_mechanism_test('NAIVE_GSSAPI')

    def test_scram_sha_256(self):
        self.run_mechanism_test('SCRAM-SHA-256')

    def test_ripemd160(self):
        self.run_mechanism_test('RIPEMD160')

    def test_sha256(self):
        self.run_mechanism_test('SHA256')

    def test_naive_digest(self):
        self.run_mechanism_test('NAIVE_DIGEST')

    def test_plain(self):
        self.run_mechanism_test('PLAIN')
