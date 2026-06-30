from contextlib import contextmanager
import importlib
import os
import socket
import subprocess
import sys
import time
from typing import Tuple
import urllib.parse

import pytest

# Use environment variale to force force tests to run even if dependency is not detected
# For use in CI
FORCE_TESTS: set[str] = set(item for item in os.getenv('FORCE_TESTS', '').split(',') if item)
if 'all' in FORCE_TESTS:
    FORCE_TESTS |= {'most', 'kerberos', 'altuser'}
if 'most' in FORCE_TESTS:
    FORCE_TESTS |= {'mclient', 'jdbc', 'pty'}

# class name of JdbcClient, we'll look for it on the classpath
JDBCCLIENT = 'org.monetdb.client.JdbcClient'

# Allow to set path to mclient using env var
MCLIENT = os.getenv('MCLIENT', 'mclient')

# Kerberos tests need a keytab to be available.
# Optionally, the server principal can also be set.
KEYTAB = os.getenv('TEST_KEYTAB', None)
SERVER_PRINCIPAL = os.getenv('TEST_SERVER_PRINCIPAL', None)
ALT_CLIENT_KEYTAB = os.getenv('ALT_CLIENT_KEYTAB', None)
ALT_CLIENT_PRINCIPAL = os.getenv('ALT_CLIENT_PRINCIPAL', None)

# Password entries to use in demoserver. If set must include
# monetdb=plain:monetdb and for Kerberos also
# monetdb=principal:USERNAME@REALM.
TEST_USERS = [cred for cred in os.getenv('TEST_USERS', '').split(',') if cred] or None

HAVE_PTY_MODULE = 'pymonetdb' in FORCE_TESTS
try:
    HAVE_PTY_MODULE or importlib.import_module('pty')
    HAVE_PTY_MODULE = True
except ModuleNotFoundError:
    pass

HAVE_MCLIENT = 'mclient' in FORCE_TESTS
try:
    HAVE_MCLIENT or subprocess.check_output([MCLIENT, '--version'])
    HAVE_MCLIENT = True
except (FileNotFoundError, subprocess.CalledProcessError):
    pass

HAVE_JDBCCLIENT = 'jdbc' in FORCE_TESTS
try:
    HAVE_JDBCCLIENT or subprocess.check_output(['java', JDBCCLIENT, '--version'])
    HAVE_JDBCCLIENT = True
except subprocess.CalledProcessError:
    pass


needs_pty_module = pytest.mark.skipif(not HAVE_PTY_MODULE, reason='needs pty module')
needs_mclient = pytest.mark.skipif(not HAVE_MCLIENT, reason='needs mclient')
needs_jdbcclient = pytest.mark.skipif(not HAVE_JDBCCLIENT, reason='needs jdbcclient')

if not KEYTAB:
    no_kerberos_reason = '$TEST_KEYTAB not set'
elif not os.path.isfile(KEYTAB):
    no_kerberos_reason = f'keytab not found: {KEYTAB}'
else:
    gssapi = None
    try:
        gssapi = importlib.import_module('gssapi')
    except ModuleNotFoundError:
        no_kerberos_reason = 'gssapi module not present'
    if gssapi:
        try:
            # check for valid TGT
            gssapi.Credentials(usage='initiate')
            no_kerberos_reason = ''
        except gssapi.raw.GSSError as e:
            no_kerberos_reason = str(e)
HAVE_KERBEROS = not no_kerberos_reason or 'kerberos' in FORCE_TESTS
needs_kerberos = pytest.mark.skipif(not HAVE_KERBEROS, reason=no_kerberos_reason)

HAVE_ALT_CLIENT = 'altuser' in FORCE_TESTS or (ALT_CLIENT_PRINCIPAL and ALT_CLIENT_KEYTAB)
needs_alt_client = pytest.mark.skipif(
    not HAVE_ALT_CLIENT, reason='$ALT_CLIENT_PRINCIPAL or $ALT_CLIENT_KEYTAB not set'
)


def pick_listenaddr() -> Tuple[str, int]:
    """Pick a free port number to listen on."""
    host = '127.0.0.1'
    fam = socket.AF_INET  # must match host
    with socket.create_server(address=(host, 0), family=fam) as sock:
        return sock.getsockname()


@contextmanager
def running_demoserver(*, extra_args=[]):
    """Context manager that starts and later kills a demoserver and returns its monetdb url"""

    listen_host = 'localhost'
    # Pick an address for the demo server to listen on
    with socket.create_server(address=(listen_host, 0), family=socket.AF_INET) as sock:
        ignored, listen_port = sock.getsockname()
    listen_address = f'{listen_host}:{listen_port}'
    urlparams = dict(user='monetdb', password='monetdb')
    if HAVE_KERBEROS:
        assert KEYTAB
        krb5_args = ['-k', KEYTAB]
        if SERVER_PRINCIPAL:
            krb5_args += ['-P', SERVER_PRINCIPAL]
            urlparams['server_principal'] = SERVER_PRINCIPAL
        if TEST_USERS:
            for cred in TEST_USERS:
                krb5_args += ['-c', cred]
    else:
        krb5_args = []
    url = f'monetdb://{listen_host}:{listen_port}/demo?' + urllib.parse.urlencode(
        urlparams, quote_via=urllib.parse.quote
    )
    # Start the demoserver
    proc = subprocess.Popen(
        [sys.executable, 'demoserver.py', '-v', listen_address, *krb5_args, *extra_args],
        shell=False,
        stdin=subprocess.DEVNULL,
    )
    # Wait for it to start, then yield the url.
    # Always kill it afterward.
    try:
        sleep_interval = 0.1
        deadline = time.time() + 2.0
        while True:
            now = time.time()
            if now > deadline:
                raise Exception('demo server failed to start accepting connections')
            try:
                with socket.create_connection((listen_host, listen_port)):
                    break
            except OSError:
                time.sleep(sleep_interval)
        yield url
    finally:
        proc.kill()
