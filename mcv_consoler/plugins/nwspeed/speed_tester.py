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
from operator import truediv

from oslo_config import cfg

import mcv_consoler.common.config as app_conf
from mcv_consoler import exceptions
from mcv_consoler.common import ssh

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class Node2NodeSpeed(object):

    def __init__(self, ctx, nodes):
        self.ctx = ctx
        self.nodes = nodes
        self.ssh_conns = dict()
        # Port for testing speed between nodes
        self.test_port = CONF.nwspeed.test_port
        # Data size for testing in megabytes
        self.data_size = CONF.nwspeed.data_size

    def init_ssh_conns(self):
        if not self.nodes:
            return
        work_dir = self.ctx.work_dir_global
        rsa_path = work_dir.resource(work_dir.RES_OS_SSH_KEY)
        login = app_conf.OS_NODE_SSH_USER
        for node in self.nodes:
            conn = self._ssh_connect(login, node.ip, rsa_path)
            self.ssh_conns[node.fqdn] = conn

    @staticmethod
    def _ssh_connect(username, ip, auth_key):
        connect = ssh.SSHClient(ip, username, rsa_key=auth_key)
        if connect.connect():
            return connect
        raise exceptions.AccessError("Can't access node {} via SSH".format(ip))

    def measure_speed(self, node, attempts):
        res = dict()
        for target in self.nodes:
            if target is node:
                continue
            node_res = self._do_measure(node, target, attempts)
            res[target.fqdn] = node_res
        return res

    def _do_measure(self, node1, node2, attempts=3):
        cmd_listen = 'nc -l -k -p {port} > /dev/null'
        cmd_send = 'LC_ALL=C ' \
                   'dd if=/dev/zero bs=1M count={count} | ' \
                   'nc {fqdn} {port}'
        ctrl_c = chr(3)  # Ctrl+C pressed

        ssh_node1 = self.ssh_conns[node1.fqdn]
        ssh_node2 = self.ssh_conns[node2.fqdn]

        LOG.debug('Starting netcat server on node %s', node2.fqdn)
        cmd = cmd_listen.format(port=self.test_port)
        LOG.debug('%s Running SSH command: %s', ssh_node2.identity, cmd)
        sin, _, _ = ssh_node2.client.exec_command(cmd, get_pty=True)

        cmd = cmd_send.format(count=self.data_size, fqdn=node2.fqdn,
                              port=self.test_port)
        res = list()
        try:
            for _ in xrange(attempts):
                out = ssh_node1.exec_cmd(cmd)
                speed_mb = self._parse_speed(out.stderr)
                res.append(speed_mb)
        finally:
            # terminate netcat server
            sin.write(ctrl_c)
        return res

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
