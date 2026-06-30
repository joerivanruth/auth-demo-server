import subprocess
import sys
from unittest import TestCase
from urllib.parse import urlencode

import urllib

from util import (
    running_demoserver,
    needs_kerberos,
    needs_alt_client,
    ALT_CLIENT_KEYTAB,
    ALT_CLIENT_PRINCIPAL,
)


class MechanismTests(TestCase):
    """
    Tests for the various mechanisms
    """

    def run_mechanism_test(self, mechname, *, urlparams=None, server_args=[], client_args=[]):
        with running_demoserver(extra_args=server_args) as url:
            if urlparams:
                url += '&' + urlencode(urlparams, quote_via=urllib.parse.quote)
            cmd = [sys.executable, 'democlient.py', '-v', url, *client_args]
            if mechname:
                cmd += ['-m', mechname]
            subprocess.check_call(cmd)

    @needs_kerberos
    def test_gssapi(self):
        self.run_mechanism_test('GSSAPI')

    @needs_kerberos
    def test_gssapi_urlparam(self):
        self.run_mechanism_test(None, urlparams=dict(_authmechanism='GSSAPI'))

    @needs_kerberos
    @needs_alt_client
    def test_gssapi_client_keytab(self):
        urlparams = dict(
            _authmechanism='GSSAPI',
            user='altuser',
            _keytab=ALT_CLIENT_KEYTAB,
            _principal=ALT_CLIENT_PRINCIPAL,
        )
        server_args = ['-c', f'altuser=principal:{ALT_CLIENT_PRINCIPAL}']
        client_args = ['--assert-happy', f'Authenticated {ALT_CLIENT_PRINCIPAL} -> ']
        self.run_mechanism_test(
            None, urlparams=urlparams, server_args=server_args, client_args=client_args
        )

    def test_scram_sha_256(self):
        self.run_mechanism_test('SCRAM-SHA-256')

    def test_ripemd160(self):
        self.run_mechanism_test('RIPEMD160')

    def test_sha256(self):
        self.run_mechanism_test('SHA256')

    def test_plain(self):
        self.run_mechanism_test('PLAIN')
