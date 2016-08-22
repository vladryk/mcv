#    Copyright 2015 Mirantis, Inc
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
import os
import socket

import paramiko

from mcv_consoler import exceptions
from mcv_consoler.common.config import DEFAULT_SSH_TIMEOUT
from mcv_consoler.log import LOG


LOG = LOG.getLogger(__name__)

ProcOutput = collections.namedtuple(
    'ProcOutput', 'stdout, stderr, rcode')


class SSHClient(object):
    connected = False
    show_password = False

    def __init__(self, host, username,
                 password=None,
                 rsa_key=None,
                 timeout=DEFAULT_SSH_TIMEOUT):

        self.client = paramiko.client.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.connect_args = {
            'hostname': host,
            'username': username,
            'timeout': timeout}
        if password:
            self.connect_args['password'] = password
        if rsa_key:
            self.connect_args['pkey'] = rsa_key

    def connect(self):
        self.connected = False
        try:
            self.client.connect(**self.connect_args)
        except (
                paramiko.AuthenticationException,
                paramiko.SSHException,
                socket.error) as e:
            LOG.error('SSH connect {}: {}'.format(self.identity, e))
            LOG.debug('Error details', exc_info=True)
            return False

        self.connected = True
        return self.connected

    def exec_cmd(self, cmd, stdin=None, exc=False):
        if not self.connected:
            raise exceptions.RemoteError(
                'SSH {} is not connected'.format(self.identity))

        LOG.debug('{} Running SSH command: {}'.format(self.identity, cmd))
        inp, out, err = self.client.exec_command(cmd)

        if stdin:
            inp.write(stdin)
        inp.channel.shutdown(2)

        args = (out.read(), err.read(), inp.channel.recv_exit_status())
        results = ProcOutput(*args)

        LOG.debug('{identity} Results:\n'
                  '\trcode: {0.rcode}\n'
                  '\tstdout: {0.stdout}\n'
                  '\tstderr: {0.stderr}'.format(
            results, identity=self.identity))

        if results.rcode and exc:
            raise exceptions.RemoteError(
                'Command {!r} failed on {}'.format(
                    cmd, self.identity), results)

        return results

    def close(self):
        if self.connected:
            self.client.close()
            self.connected = False

    @property
    def identity(self):
        auth = []
        try:
            pwd = self.connect_args['password']
            if not self.show_password:
                pwd = '*' * 5
            auth.append(pwd)
        except KeyError:
            pass
        if 'pkey' in self.connect_args:
            auth.append('{private-key}')
        auth = '/'.join(auth)
        if auth:
            auth = ':' + auth

        return '{login}{auth}@{host}'.format(
            login=self.connect_args['username'],
            auth=auth, host=self.connect_args['hostname'])


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


def get_rsa_obj(rsa_path):
    try:
        # re-save file, so it got correct permissions and ownership
        with open(rsa_path) as f:
            payload = f.read()
        save_private_key(rsa_path, payload)
    except IOError as e:
        raise exceptions.FrameworkError(str(e))
    return paramiko.RSAKey.from_private_key_file(rsa_path)


