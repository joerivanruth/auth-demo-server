import os
import pty
import signal
import subprocess
import sys
import threading
import time
from unittest import TestCase

from util import (
    JDBCCLIENT,
    MCLIENT,
    running_demoserver,
    needs_mclient,
    needs_jdbcclient,
    needs_pty_module,
)


class DemoServerTests(TestCase):
    """
    Tests that verify that demoserver can impersonate mserver5 well enough to
    fool mclient, pymonetdb and monetdb-jdbc
    """

    def test_pymonetdb(self):
        """Demoserver should be able to accept connections from pymonetdb"""

        import pymonetdb

        with running_demoserver() as url:
            with pymonetdb.connect(url, connect_timeout=5):
                pass

    @needs_mclient
    def test_mclient(self):
        """Demoserver should be able to accept connections from mclient"""

        with running_demoserver() as url:
            cmd = [MCLIENT, '-d', url + '&connect_timeout=3']
            mclient = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            mclient.communicate()
            retcode = mclient.wait(timeout=3)
            self.assertEqual(0, retcode, 'mclient should have exited with status 0')

    @needs_mclient
    @needs_pty_module
    def test_mclient_interactive(self):
        """
        Demoserver should be able to accept connections from interactive mclient, which runs some more queries

        To test this we run mclient in a pseudo tty
        """

        with running_demoserver() as url:
            cmd = [MCLIENT, '-d', url + '&connect_timeout=3']

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

    @needs_jdbcclient
    def test_jdbc(self):
        """Demoserver should be able to accept connections from mclient"""

        with running_demoserver() as url:
            cmd = ['java', JDBCCLIENT, '-d', 'jdbc:' + url + '&connect_timeout=3']
            mclient = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            mclient.communicate()
            retcode = mclient.wait(timeout=3)
            self.assertEqual(0, retcode, 'jdbcclient should have exited with status 0')

    def test_democlient(self):
        """Demoserver should be able to accept connections from democlient"""
        with running_demoserver() as url:
            cmd = [sys.executable, 'democlient.py', '-v', url, '-m', 'RIPEMD160']
            subprocess.check_call(cmd)
