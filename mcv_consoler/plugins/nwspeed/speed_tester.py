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

import logging
import re
import socket

from operator import truediv
from oslo_config import cfg

from mcv_consoler.common import config as app_conf
from mcv_consoler.common import ssh
from mcv_consoler import exceptions

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


# Issue with 'netcat': whenever it is failed to do something - it always
# returns exit code '1'. Error details are are written to stderr.
# To determine a particular error 'port is busy' - we need to parse that
# error message
RE_PORT_IN_USE = r'.*[Aa]ddress already in use.*'

NETCAT_SEND_BYTES = 'LC_ALL=C ' \
                    'dd if=/dev/zero bs=1M count={count} | ' \
                    'nc -w {timeout} {destination} {port}'

NETCAT_LISTEN = 'nc -v -l -p {port} > /dev/null'


class Node2NodeSpeed(object):

    # FIXME(ogrytsenko): remove hardcoded value when this patch
    # https://review.openstack.org/#/c/339787/9/oslo_config/types.py
    # became available in 'oslo_config' (probably oslo.config==3.18.0)
    MAX_VNC_PORT = 6100

    def __init__(self, ctx, computes, nodes):
        self.ctx = ctx
        self.computes = computes
        self.nodes = nodes
        self.ssh_conns = dict()
        # Port for testing speed between nodes
        self.test_port = CONF.nwspeed.test_port
        # Data size for testing in megabytes
        self.data_size = CONF.nwspeed.data_size

    @property
    def port_range(self):
        return (p for p in xrange(self.test_port, self.MAX_VNC_PORT))

    def init_ssh_conns(self):
        all_test_nodes = set(self.computes) | set(self.nodes)
        if not all_test_nodes:
            return
        work_dir = self.ctx.work_dir_global
        rsa_path = work_dir.resource(work_dir.RES_OS_SSH_KEY)
        login = app_conf.OS_NODE_SSH_USER
        for node in all_test_nodes:
            conn = self._ssh_connect(login, node.ip, rsa_path)
            self.ssh_conns[node.fqdn] = conn

    @staticmethod
    def _ssh_connect(username, ip, auth_key):
        agent = ssh.SSHClient(ip, username, rsa_key=auth_key)
        try:
            agent.connect()
        except exceptions.AccessError:
            LOG.error("Can't access node %s via SSH", ip)
        if agent.connected:
            return agent

    def measure_speed(self, node, attempts):
        res = dict()
        for target in self.nodes:
            if target is node:
                continue
            node_res = list()
            for _ in xrange(attempts):
                attempt = self._measure_speed_between_nodes(node, target)
                node_res.append(attempt)
            res[target.fqdn] = node_res
        return res

    def _measure_speed_between_nodes(self, node1, node2):

        ctrl_c = chr(3)  # Ctrl+C pressed
        ssh_node1 = self.ssh_conns[node1.fqdn]
        ssh_node2 = self.ssh_conns[node2.fqdn]

        # FIXME(ogrytsenko): this is a temporary work-around which will work
        # fine in most cases. But the main issue is still not resolved -
        # we create and remember active SSH connection to each node. While
        # tests running, some node may go to
        # 'active -> error -> discovering -> active' state several times.
        # Currently we do not handle such cases
        # FIXME(ogrytsenko): issue #2 - fuel's 'node status' is quite
        # far away from the the reality. Never trust this parameter
        err_msg = 'No SSH connection to node: %s'
        if ssh_node1 is None:
            return LOG.error(err_msg, node1.fqdn)
        if ssh_node2 is None:
            return LOG.error(err_msg, node2.fqdn)

        msg_running = 'SSH %s. Running command: %s'
        msg_output = 'SSH %s. Output: %s'
        pretty_output = lambda text: '\n' + text.strip('\n') if text else text

        output = None
        for port in self.port_range:
            sin = None
            server_running = False

            cmd1 = NETCAT_SEND_BYTES.format(
                destination=node2.fqdn, port=port, count=self.data_size,
                timeout=app_conf.DEFAULT_SSH_TIMEOUT)
            cmd2 = NETCAT_LISTEN.format(port=port)

            try:
                # start netcat server on node2
                LOG.debug(msg_running, node2.fqdn, cmd2)
                sin, _, serr = ssh_node2.client.exec_command(cmd2)

                # safely read one line. Check if this is a an error message.
                # Repeat test with new port, if required
                line = serr.readline(size=1024)
                LOG.debug(msg_output, node2.fqdn, pretty_output(line))
                if re.match(RE_PORT_IN_USE, line, re.M):
                    continue
                server_running = True

                # run speed measure from node1 to node2
                LOG.debug(msg_running, node1.fqdn, cmd1)
                _, _, dd_serr = ssh_node1.client.exec_command(cmd1)
                output = dd_serr.read()
                LOG.debug(msg_output, node1.fqdn, pretty_output(output))
            except ssh.paramiko.SSHException as e:
                LOG.debug('Error: %s', e.message, exc_info=True)
                break
            finally:
                try:
                    # terminate netcat server
                    server_running and sin.write(ctrl_c)
                except (socket.error, AttributeError):
                    # channel was already closed or 'sin' is None.
                    # Both cases are expected and should be treated as
                    # a correct behaviour
                    pass
            break

        if output is None:
            return
        try:
            speed_mb = self._parse_speed(output)
        except (exceptions.ParseError, ValueError) as e:
            LOG.debug('Error: %s', e.message, exc_info=True)
            speed_mb = None
        return speed_mb

    @staticmethod
    def _units_to_mb(speed, unit):
        sp = float(speed)
        u = unit.lower().strip()
        if u[:1] == 'b':
            return truediv(sp, 1024 * 1024)
        if u[:2] == 'kb':
            return truediv(sp, 1024)
        if u[:2] == 'mb':
            return sp
        if u[:2] == 'gb':
            return sp * 1024
        raise ValueError('could not convert \'%s %s\' to MB/s' % (sp, unit))

    def _parse_speed(self, text):
        expr = r'^\d+\s+bytes\s+\([^)]+\) copied,\s+' \
               r'(?P<time>[.0-9]+)\s+' \
               r'(?P<time_units>\S+),\s+' \
               r'(?P<speed>[.0-9]+)\s+(?P<speed_units>.*)$'
        res = re.search(expr, text, re.M)
        if res is None:
            raise exceptions.ParseError("Can't get speed form %s" % text)
        speed, unit = res.group('speed', 'speed_units')
        speed_mbs = self._units_to_mb(speed, unit)
        return speed_mbs

    def cleanup(self):
        ssh_close = lambda c: c.close()
        return map(ssh_close, self.ssh_conns.values())
