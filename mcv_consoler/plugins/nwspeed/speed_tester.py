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
import paramiko
import subprocess
import time

from mcv_consoler.common import clients as Clients
from mcv_consoler.logger import LOG
from mcv_consoler.utils import GET

LOG = LOG.getLogger(__name__)


class Node2NodeSpeed(object):
    def __init__(self, access_data, *args, **kwargs):
        self.nova = Clients.get_nova_client(access_data)
        self.config = kwargs.get('config')
        self.node_name = ""
        self.test_nodes = []
        self.ssh_conns = {}
        self.port_n = 45535
        self.port_pool = range(45536, 45600)
        # Port for testing speed between nodes
        self.test_port = GET(self.config, 'test_port', 'nwspeed',
                                        5903)
        # Data size for testing in megabytes
        self.data_size = GET(self.config, 'data_size', 'nwspeed',
                                        100)

    def generate_report(self, spd_res):
        path = os.path.join(os.path.dirname(__file__), 'speed_template.html')
        temp = open(path, 'r')
        template = temp.read()
        temp.close()
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
            self.node_name, total_avg_spd))
        return template.format(node_name=self.node_name,
                               attempts=html_res,
                               avg=total_avg_spd), total_avg_spd

    def prepare_tunnels(self):
        controller_ip = GET(self.config, 'controller_ip', 'auth')
        ssh_key = GET(self.config, 'ssh_key', 'auth')
        # Creating tunnel for current node
        subprocess.call(
            'ssh -i %s -4 -f -N -L %s:%s:22 root@%s &' % (ssh_key,
                                                          self.port_n,
                                                          self.node_name,
                                                          controller_ip),
            shell=True)
        self.set_ssh_connection('localhost', self.port_n, self.node_name)
        # Creating tunnels for test nodes
        for i, test_node in enumerate(self.test_nodes):
            subprocess.call(
                'ssh -i %s -4 -f -N -L %s:%s:22 root@%s' % (ssh_key,
                                                            self.port_pool[i],
                                                            test_node,
                                                            controller_ip),
                shell=True)
            self.set_ssh_connection('localhost', self.port_pool[i], test_node)

    def set_ssh_connection(self, ip, prt, node_name):
        hostname = ip
        port = prt
        username = 'root'
        ssh_key = GET(self.config, 'ssh_key', 'auth')
        rsa_key = paramiko.RSAKey.from_private_key_file(ssh_key)
        # TODO (raliev): There is a problem if controller host key not exist
        # TODO (raliev): in known_hosts file. Need to use AutoAdd Policy,
        # TODO (raliev): but it's unavailable in Transport class.

        conn = False
        for i in range(0, 20):
            try:
                self.ssh_conns[node_name] = paramiko.Transport((hostname, port))
                self.ssh_conns[node_name].connect(username=username,
                                                  pkey=rsa_key)
                conn = True
                break
            except paramiko.SSHException:
                LOG.debug('Waiting for establishing SSH connection')
            time.sleep(1)
        if conn:
            LOG.debug('SSH connection to node %s '
                      'successfully established' % node_name)
        else:
            raise RuntimeError("Can't connect to node %s" % node_name)

    def run_ssh_cmd(self, cmd, ssh_conn, nocheck=False):
        command = 'sudo ' + cmd
        buff_size = 4096
        stdout_data = []
        stderr_data = []
        session = ssh_conn.open_channel(kind='session')
        session.exec_command(command)
        if nocheck:
            return
        while True:
            if session.recv_ready():
                stdout_data.append(session.recv(buff_size))
            if session.recv_stderr_ready():
                stderr_data.append(session.recv_stderr(buff_size))
            if session.exit_status_ready():
                break

        status = session.recv_exit_status()
        while session.recv_ready():
            stdout_data.append(session.recv(buff_size))
        while session.recv_stderr_ready():
            stderr_data.append(session.recv_stderr(buff_size))

        out = ''.join(stdout_data)
        err = ''.join(stderr_data)
        session.close()

        if status != 0:
            LOG.info('Command "%s" finished with exit code %d' % (cmd, status))
        else:
            LOG.debug('Command "%s" finished with exit code %d' % (cmd,
                                                                  status))
        LOG.debug('Stdout: %s' % out)
        LOG.debug('Stderr: %s' % err)
        return {'ret': status, 'out': out, 'err': err}

    def get_node_list(self):
        # Preparing node list for testing against current node
        self.test_nodes = list(
            {host.host_name for host in self.nova.hosts.list()})
        self.test_nodes.remove(self.node_name)

    def measure_nw_speed(self, ip):
        # Starting nc server
        self.run_ssh_cmd('nc -vvlnp %s > /dev/null' % self.test_port,
                         self.ssh_conns[ip],
                         nocheck=True)
        time.sleep(1)
        start_time = time.time()
        # Starting nc client
        ret = self.run_ssh_cmd('dd if=/dev/zero bs=1M count=%s '
                               'conv=notrunc,fsync | nc -vv %s %s' % (
                                   self.data_size, ip, self.test_port),
                               self.ssh_conns[self.node_name])['ret']
        return time.time() - start_time if ret == 0 else -1

    def measure_speed(self, node_name):
        self.node_name = node_name
        self.get_node_list()
        self.prepare_tunnels()
        LOG.info('Start measuring HW network speed on node %s' % node_name)
        res = {}
        for test_node in self.test_nodes:
            spd = []
            for i in range(0, 3):
                speed = self.measure_nw_speed(test_node)
                if speed != -1:
                    spd.append(speed)
            res[test_node] = spd

        time.sleep(3)
        self.cleanup()
        return self.generate_report(res)

    def cleanup(self):
        # Killing all ssh tunneling processes
        LOG.debug("Killing ssh tunnelling processes")
        n_pid = subprocess.check_output(
            "lsof -i :%s | tail -n +2 | awk "
            "'{if ($10==\"(LISTEN)\") print $2}'" % self.port_n, shell=True,
            stderr=subprocess.STDOUT)
        if 1 < int(n_pid) < 32768:
            LOG.debug("Killing process %s" % n_pid)
            subprocess.call('kill %s > /dev/null 2>&1' % n_pid, shell=True)
        for i in range(0, len(self.test_nodes)):
            pid = subprocess.check_output(
                "lsof -i :%s | tail -n +2 | awk "
                "'{if ($10==\"(LISTEN)\") print $2}'" % self.port_pool[i],
                shell=True, stderr=subprocess.STDOUT)
            if 1 < int(pid) < 32768:
                LOG.debug("Killing process %s" % pid)
                subprocess.call('kill %s > /dev/null 2>&1' % pid, shell=True)
