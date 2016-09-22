#    Copyright 2015-2016 Mirantis, Inc
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections
import itertools
import logging
import os
import socket
import subprocess
import threading
import time

import paramiko

from mcv_consoler import exceptions
from mcv_consoler.common import config

LOG = logging.getLogger(__name__)

ProcOutput = collections.namedtuple(
    'ProcOutput', 'stdout, stderr, rcode')


class SSHClient(object):
    connected = False

    def __init__(self, host, username,
                 password=None,
                 rsa_key=None,
                 port=None,
                 timeout=config.DEFAULT_SSH_TIMEOUT):

        self.timeout = timeout
        self.creds = Credentials(
            host, username, password=password, auth_key=rsa_key, port=port)

        self.client = paramiko.client.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self, exc=False, quiet=False):
        self.connected = False

        args = self.creds.paramiko_connect_args()
        args['timeout'] = self.timeout
        try:
            self.client.connect(**args)
        except (
                paramiko.AuthenticationException,
                paramiko.SSHException,
                socket.error) as e:

            if exc:
                raise exceptions.AccessError(e.message)

            if not quiet:
                LOG.error('SSH connect {}: {}'.format(self.identity, e))
                LOG.debug('Error details', exc_info=True)
            return False

        self.connected = True
        return self.connected

    def exec_cmd(self, cmd, stdin=None, exc=False, hide_stdout=False):
        if not self.connected:
            raise exceptions.RemoteError(
                'SSH {} is not connected'.format(self.identity))

        LOG.debug('{} Running SSH command: {}'.format(
            self.creds.identity, cmd))
        inp, out, err = self.client.exec_command(cmd)

        if stdin:
            inp.write(stdin)
        inp.channel.shutdown(2)

        args = (out.read(), err.read(), inp.channel.recv_exit_status())
        results = ProcOutput(*args)

        msg = '{identity} Results: ' \
              '\n\t rcode: {rcode}'
        if not hide_stdout:
            msg += '\n\t stdout: {stdout}' \
                   '\n\t stderr: {stderr}'
        LOG.debug(msg.format(rcode=results.rcode,
                             stdout=results.stdout.strip(),
                             stderr=results.stderr.strip(),
                             identity=self.creds.identity))

        if results.rcode and exc:
            raise exceptions.RemoteError(
                'Command {!r} failed on {}'.format(
                    cmd, self.creds.identity), results)

        return results

    def close(self):
        if self.connected:
            self.client.close()
            self.connected = False

    @property
    def identity(self):
        return self.creds.identity


class Credentials(object):
    show_password = False

    def __init__(self, remote, login, password=None, auth_key=None, port=None):
        self.remote = remote
        self.login = login
        self.password = password
        self.auth_key = auth_key
        self.port = port

    def paramiko_connect_args(self):
        args = {
            'hostname': self.remote,
            'username': self.login}
        if self.password:
            args['password'] = self.password
        if self.auth_key:
            args['pkey'] = paramiko.RSAKey.from_private_key_file(self.auth_key)
        if self.port:
            args['port'] = self.port

        return args

    @property
    def host_with_login(self):
        return '@'.join((self.login, self.remote))

    @property
    def identity(self):
        auth = []
        if self.password:
            if not self.show_password:
                pwd = '*' * 5
            else:
                pwd = self.password
            auth.append(pwd)

        if self.auth_key:
            auth.append('{private-key}')
        auth = '/'.join(auth)
        if auth:
            auth = ':' + auth

        host = self.remote
        if self.port:
            host += ':{}'.format(self.port)

        return '{login}{auth}@{host}'.format(
            login=self.login, auth=auth, host=host)


class LocalPortForwarder(object):
    is_closed = False

    _busy_ports = set()
    _lock = threading.Lock()

    def __init__(
            self, remote, remote_port, via,
            local='localhost',
            min_port=config.SSH_LOCAL_PORT_FORWARDING_MIN,
            max_port=config.SSH_LOCAL_PORT_FORWARDING_MAX):
        self.remote = remote
        self.remote_port = remote_port
        self.via = via
        self.local = local
        self.port = self._lookup_free_port(min_port, max_port)

        cmd = []
        if self.via.password:
            cmd += ['sshpass', '-p', self.via.password]
        cmd += [
            'ssh', '-qnN',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'StrictHostKeyChecking=no',
            '-L', '{}:{}:{}:{}'.format(
                self.local, self.port, self.remote, self.remote_port)]
        if self.via.auth_key:
            cmd += [
                '-i', self.via.auth_key]
        cmd.append(self.via.host_with_login)

        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=open(os.devnull, 'w'), stderr=subprocess.STDOUT,
                close_fds=True)
        except OSError as e:
            raise exceptions.PortForwardingError(
                'Unable to execute {!r}: {}'.format(cmd, e))

        try:
            self._wait_for_connect()
        except Exception:
            self._release_port(self.port)
            self.proc.terminate()
            raise

    def close(self):
        if self.is_closed:
            return

        self.is_closed = True

        self.proc.terminate()
        self.proc.wait()
        self._release_port(self.port)

    @classmethod
    def _lookup_free_port(cls, min_port, max_port):
        if all((min_port, max_port)):
            seq = range(min_port, max_port)
        elif min_port:
            seq = itertools.count(min_port)
        else:
            raise ValueError('You must define at least min_port')

        cls._lock.acquire()
        try:
            for port in seq:
                if port in cls._busy_ports:
                    continue
                break
            else:
                raise exceptions.PortForwardingError(
                    'There is no free ports (min={}, max={})'.format(
                        min_port, max_port))

            cls._busy_ports.add(port)
        finally:
            cls._lock.release()

        return port

    @classmethod
    def _release_port(cls, port):
        cls._lock.acquire()
        try:
            cls._busy_ports.remove(port)
        finally:
            cls._lock.release()

    def _wait_for_connect(self, tout=10):
        now = time.time()
        etime = now + tout

        while now < etime and self.proc.poll() is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((self.local, self.port))
            except socket.error:
                time.sleep(int(now + 1) - now)
                now = time.time()
                continue
            finally:
                s.close()

            break
        else:
            raise exceptions.PortForwardingError(
                'SSH forwarded port {}:{} is unaccesibble (ssh process '
                'status: {})'.format(self.local, self.port, self.proc.poll()))


def save_private_key(dest, payload):
    umask = os.umask(0177)
    try:
        with open(dest, 'wt') as fp:
            fp.write(payload)

        # If file exist on time when we made "open()" call, it will be not
        # recreated and will keep it's old permission bits. We should make
        # chmod call to be sure that file get correct permission in all
        # cases.
        os.chmod(dest, 0600)
    except IOError as e:
        raise exceptions.FrameworkError(
            'Fail to store RSA key', e)
    finally:
        os.umask(umask)
