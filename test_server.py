from contextlib import contextmanager
import functools
import importlib
import os
import pty
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Tuple
from unittest import SkipTest, TestCase

import pytest

# This module contains tests that verify that demoserver can impersonate
# mserver5 well enough for mclient, pymonetdb and monetdb-jdbc to be able to
# connect.
#
# They only work if mclient, pymonetdb and monetdb-jdbc are present on the PATH,
# PYTHONPATH and CLASSPATH, respectively. By default, the tests are skipped if
# the client is not found. In CI we want the tests to fail rather than silently
# get skipped. This can be achieved by setting the environment variable
# FORCE_CLIENTS to a comma separated list of the keywords 'mclient', 'pymonetdb',
# 'jdbc' or 'all'.

FORCE_CLIENTS = set(client for client in os.getenv('FORCE_CLIENTS', '').split(',') if client)
if 'all' in FORCE_CLIENTS:
    FORCE_CLIENTS |= {'pymonetdb', 'mclient', 'jdbc'}

MCLIENT = os.getenv('MCLIENT', 'mclient')


@functools.cache
def find_pymonetdb_or_skip():
    try:
        importlib.import_module('pymonetdb')
    except ModuleNotFoundError:
        if 'pymonetdb' not in FORCE_CLIENTS:
            raise SkipTest('pymonetdb not available')


@functools.cache
def find_mclient_or_skip() -> str:
    try:
        subprocess.check_output([MCLIENT, '--version'])
        return MCLIENT
    except (FileNotFoundError, subprocess.CalledProcessError):
        if 'mclient' not in FORCE_CLIENTS:
            raise SkipTest('mclient not available')
        else:
            return MCLIENT


@functools.cache
def find_jdbcclient_or_skip():
    jdbcclient = 'org.monetdb.client.JdbcClient'
    try:
        subprocess.check_output(['java', '-version'])
    except FileNotFoundError:
        if 'jdbc' not in FORCE_CLIENTS:
            raise SkipTest('java not available')
    try:
        subprocess.check_output(['java', jdbcclient, '--version'])
    except subprocess.CalledProcessError:
        if 'jdbc' not in FORCE_CLIENTS:
            raise SkipTest('monetdb-jdbc not on the class path')
    return jdbcclient


@functools.cache
def find_pty_or_skip():
    try:
        importlib.import_module('pty')
    except ModuleNotFoundError:
        raise SkipTest('pty only available on Unix')


def pick_listenaddr() -> Tuple[str, int]:
    """Pick a free port number to listen on."""
    host = '127.0.0.1'
    fam = socket.AF_INET  # must match host
    with socket.create_server(address=(host, 0), family=fam) as sock:
        return sock.getsockname()


@contextmanager
def running_demoserver():
    """Context manager that starts and later kills a demoserver and returns its monetdb url"""

    # Pick an address for the demo server to listen on
    with socket.create_server(address=('127.0.0.1', 0), family=socket.AF_INET) as sock:
        listen_host, listen_port = sock.getsockname()
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


class DemoServerTests(TestCase):
    def test_pymonetdb(self):
        """Demoserver should be able to accept connections from pymonetdb"""

        find_pymonetdb_or_skip()
        import pymonetdb

        with running_demoserver() as url:
            with pymonetdb.connect(url, connect_timeout=5):
                pass

    def test_mclient(self):
        """Demoserver should be able to accept connections from mclient"""

        mclient_exe = find_mclient_or_skip()
        with running_demoserver() as url:
            cmd = [mclient_exe, '-d', url + '&connect_timeout=3']
            mclient = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            mclient.communicate()
            retcode = mclient.wait(timeout=3)
            self.assertEqual(0, retcode, 'mclient should have exited with status 0')

    def test_mclient_interactive(self):
        """Demoserver should be able to accept connections from interactive mclient, which runs some more querie

        To test this we run mclient in a pseudo tty
        """

        mclient_exe = find_mclient_or_skip()
        find_pty_or_skip()

        with running_demoserver() as url:
            cmd = [mclient_exe, '-d', url + '&connect_timeout=3']

            pid, master_fd = pty.fork()
            if pid == 0:
                # We're the child process, we must become mclient
                os.execlp(cmd[0], *cmd[1:])
            else:
                # We're the master process.
                # Spawn a thread that copies the child's output to our stderr.
                # Do not give it any input.
                try:
                    threading.Thread(target=self.copy_output, args=[master_fd]).start()
                    time.sleep(0.5)
                    os.write(master_fd, b'\\quit\n')
                    ignored, encoded_exit_status = os.waitpid(pid, 0)
                    retcode = os.waitstatus_to_exitcode(encoded_exit_status)
                    self.assertEqual(0, retcode, 'mclient should have exited with status 0')
                finally:
                    if pid:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def copy_output(self, master_fd):
        stderr = sys.stderr.fileno()
        try:
            while True:
                data = os.read(master_fd, 1024)
                if not data:
                    break
                while data:
                    nwritten = os.write(stderr, data)
                    data = data[nwritten:]
        except OSError:
            return

    def test_jdbc(self):
        """Demoserver should be able to accept connections from mclient"""

        jdbcclient = find_jdbcclient_or_skip()

        with running_demoserver() as url:
            cmd = ['java', jdbcclient, '-d', 'jdbc:' + url + '&connect_timeout=3']
            mclient = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            mclient.communicate()
            retcode = mclient.wait(timeout=3)
            self.assertEqual(0, retcode, 'jdbcclient should have exited with status 0')


@pytest.mark.parametrize('mech', ['RIPEMD160', 'SHA256', 'PLAIN', 'NAIVE_DIGEST'])
def test_democlient(mech: str):
    with running_demoserver() as url:
        cmd = [sys.executable, 'democlient.py', '-v', url, '-m', mech]
        subprocess.check_call(cmd)
