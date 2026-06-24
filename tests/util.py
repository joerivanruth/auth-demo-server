from contextlib import contextmanager
import importlib
import os
import socket
import subprocess
import sys
import time
from typing import Tuple

import pytest

# Use environment variale to force force tests to run even if dependency is not detected
# For use in CI
FORCE_TESTS: set[str] = set(item for item in os.getenv('FORCE_TESTS', '').split(',') if item)
if 'all' in FORCE_TESTS:
    FORCE_TESTS |= {'most', 'kerberos'}
if 'most' in FORCE_TESTS:
    FORCE_TESTS |= {'mclient', 'jdbc', 'pty'}

# class name of JdbcClient, we'll look for it on the classpath
JDBCCLIENT = 'org.monetdb.client.JdbcClient'

# Allow to set path to mclient using env var
MCLIENT = os.getenv('MCLIENT', 'mclient')

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


def pick_listenaddr() -> Tuple[str, int]:
    """Pick a free port number to listen on."""
    host = '127.0.0.1'
    fam = socket.AF_INET  # must match host
    with socket.create_server(address=(host, 0), family=fam) as sock:
        return sock.getsockname()


@contextmanager
def running_demoserver():
    """Context manager that starts and later kills a demoserver and returns its monetdb url"""

    listen_host = 'localhost'
    # Pick an address for the demo server to listen on
    with socket.create_server(address=(listen_host, 0), family=socket.AF_INET) as sock:
        listen_port = sock.getsockname()[1]
    listen_address = f'{listen_host}:{listen_port}'
    url = f'monetdb://{listen_host}:{listen_port}/demo?user=monetdb&password=monetdb'
    # Start the demoserver
    proc = subprocess.Popen(
        [sys.executable, 'demoserver.py', '-v', listen_address],
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
