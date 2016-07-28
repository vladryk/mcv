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

import socket
import traceback

from mcv_consoler.common.config import DEFAULT_SSH_TIMEOUT

from mcv_consoler.logger import LOG

from paramiko import AuthenticationException
from paramiko import AutoAddPolicy
from paramiko import SSHException
from paramiko import client


LOG = LOG.getLogger(__name__)


class SSHClient(object):

    def __init__(self, host, username,
                 password=None,
                 rsa_key=None,
                 timeout=DEFAULT_SSH_TIMEOUT):

        self.client = client.SSHClient()
        self.client.set_missing_host_key_policy(AutoAddPolicy())

        self.host = host
        self.username = username
        self.password = password
        self.rsa_key = rsa_key
        self.timeout = timeout
        self.connected = False

    def connect(self):
        self.connected = False
        try:
            kwargs = {'hostname': self.host,
                      'username': self.username,
                      'timeout': self.timeout}
            if self.password:
                kwargs['password'] = self.password
            if self.rsa_key:
                kwargs['pkey'] = self.rsa_key

            self.client.connect(**kwargs)
        except AuthenticationException:
            LOG.error('Cannot connect to {host}: Invalid credentials!'.format(
                host=self.host))
            LOG.debug(traceback.format_exc())
            return False
        except SSHException as e:
            LOG.error('Cannot connect to {host}: SSH error occurred!'.format(
                host=self.host))
            LOG.debug(traceback.format_exc())
            return False
        except socket.error as e:
            LOG.error('Cannot connect to {host}: Socket error occurred!'.format(
                host=self.host))
            LOG.debug(str(e))
            LOG.debug(traceback.format_exc())
            return False

        self.connected = True
        return self.connected

    def exec_cmd(self, cmd):
        if not self.connected:
            LOG.debug('Client is not connected to SSH. Command will not be run!')
            return ('', '')

        LOG.debug('Running SSH command: {cmd}'.format(cmd=cmd))
        sout, serr = self.client.exec_command(cmd)[1:]
        out = sout.read()
        err = serr.read()
        LOG.debug('Results:\n\tStdout: {sout}\n\tStderr: {serr}'.format(
            sout=out, serr=err))
        return out, err

    def close(self):
        if self.connected:
            self.client.close()
            self.connected = False
