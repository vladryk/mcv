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

import os
import time

import mcv_consoler.common.config as app_conf
from mcv_consoler.log import LOG
from mcv_consoler import exceptions
from mcv_consoler.utils import GET
from mcv_consoler.common import ssh

LOG = LOG.getLogger(__name__)


class Node2NodeSpeed(object):
    def __init__(self, config, nodes):
        self.config = config
        self.nodes = nodes
        self.ssh_conns = dict()
        # Port for testing speed between nodes
        self.test_port = GET(self.config, 'test_port', 'nwspeed', 5903)
        # Data size for testing in megabytes
        self.data_size = GET(self.config, 'data_size', 'nwspeed', 100)
        rsa_file = GET(self.config, 'ssh_key', 'auth')
        self.rsa_obj = ssh.get_rsa_obj(rsa_file)

    def init_ssh_conns(self):
        if not self.nodes:
            return
        root = app_conf.RMT_CONTROLLER_USER
        for node in self.nodes:
            conn = self._ssh_connect(root, node.ip, self.rsa_obj)
            self.ssh_conns[node.fqdn] = conn

    @staticmethod
    def _ssh_connect(username, ip, rsa_obj):
        connect = ssh.SSHClient(ip, username, rsa_key=rsa_obj)
        if connect.connect():
            return connect
        raise exceptions.AccessError("Can't access node {} via SSH".format(ip))

    def measure_speed(self, node):
        res = dict()
        for target in self.nodes:
            if target is node:
                continue
            node_res = self._do_measure(node, target)
            res[target.fqdn] = node_res
        return res

    def _do_measure(self, from_node, to_node, attempts=3):
        nc_listen = 'nc -l -k -p {port} > /dev/null'
        nc_send = 'dd if=/dev/zero bs=1M count={count} | ' \
                  'nc {fqdn} {port}'
        ctrl_c = chr(3)  # Ctrl+C pressed

        res = list()
        from_ssh = self.ssh_conns[from_node.fqdn]
        to_ssh = self.ssh_conns[to_node.fqdn]

        LOG.debug('Starting netcat server on node %s', to_node.fqdn)
        cmd = nc_listen.format(port=self.test_port)
        LOG.debug('%s Running SSH command: %s', to_ssh.identity, cmd)
        sin, _, _ = to_ssh.client.exec_command(cmd, get_pty=True)

        cmd = nc_send.format(count=self.data_size, fqdn=to_node.fqdn,
                             port=self.test_port)
        try:
            for _ in xrange(attempts):
                start = time.time()
                from_ssh.exec_cmd(cmd)
                total_time = round(time.time() - start, 2)
                res.append(total_time)
        finally:
            # terminate netcat server
            sin.write(ctrl_c)
        return res

    def generate_report(self, node, spd_res):
        path = os.path.join(os.path.dirname(__file__), 'speed_template.html')
        with open(path) as f:
            template = f.read()
        html_res = ''
        avg_spds = []

        for test_node, spd in spd_res.iteritems():
            html_res += (
                '<tr><td align="center">Network speed to node '
                '{}:</td><tr>\n').format(test_node)

            # Calculate speed from time
            spd = [float(self.data_size) / i for i in spd]

            for i in range(len(spd)):
                html_res += ('<tr><td>{} attempt:</td><td align="right">Speed '
                             '{} MB/s</td><tr>\n').format(i + 1,
                                                          round(spd[i], 2))

            avg_spd = round(sum(spd) / float(len(spd)), 2)
            html_res += (
                '<tr><td align="center">Average speed: {} '
                'MB/s</td><tr>\n').format(avg_spd)
            avg_spds.append(avg_spd)

        total_avg_spd = round(sum(avg_spds) / float(len(avg_spds)), 2)
        LOG.info("Node %s average network speed: %s MB/s \n" % (
            node.fqdn, total_avg_spd))
        return template.format(node_name=node.fqdn,
                               attempts=html_res,
                               avg=total_avg_spd), total_avg_spd

    def cleanup(self):
        ssh_close = lambda c: c.close()
        return map(ssh_close, self.ssh_conns.values())
