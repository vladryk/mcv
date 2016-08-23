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
import functools
import json
import math
import time

import paramiko

from mcv_consoler.common import clients
from mcv_consoler.common import config as app_conf
from mcv_consoler.common import ssh
from mcv_consoler import exceptions
from mcv_consoler.logger import LOG
from mcv_consoler.plugins.speed import config
from mcv_consoler import utils


LOG = LOG.getLogger(__name__)


class BaseStorageSpeed(object):

    def __init__(self, access_data, *args, **kwargs):
        self.access_data = access_data
        self.config = kwargs.get('config')
        self.work_dir = kwargs['work_dir']

        protocol = 'https' if self.access_data['insecure'] else 'http'

        self.glance_url = "{protocol}://{endpoint}:9292/v2".format(
            protocol=protocol,
            endpoint=self.access_data['public_endpoint_ip'])

        self.timeout = 0
        self.test_vm = None

        self.cinderclient = clients.get_cinder_client(self.access_data)
        self.novaclient = clients.get_nova_client(self.access_data)
        self.glance = clients.get_glance_client(self.access_data)

    def cleanup(self, vm_uuid):
        pass

    def get_test_vm(self, node_id):
        vm = self.novaclient.servers.find(id=node_id)
        floating_ip = [ip['addr'] for ip in vm.addresses.values()[0] if
                       ip['OS-EXT-IPS:type'] == 'floating'][0]
        return vm, floating_ip

    def set_ssh_connection(self, hostname):
        port = 22
        pkey = paramiko.RSAKey.from_private_key_file(
            config.tool_vm_keypair_path(self.work_dir))
        for i in range(0, 100):
            try:
                self.client = paramiko.Transport((hostname, port))
                self.client.connect(username=config.tool_vm_login, pkey=pkey)
                break
            except paramiko.SSHException as e:
                LOG.debug('Waiting for test VM became available (%s)', e)
            time.sleep(10)
        else:
            raise RuntimeError("Can't connect to test vm")

        LOG.debug('SSH connection to test VM successfully established')

    def run_ssh_cmd(self, cmd):
        command = 'sudo ' + cmd
        buff_size = 4096
        stdout_data = []
        stderr_data = []
        session = self.client.open_channel(kind='session')
        session.exec_command(command)
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
            LOG.debug('Command "%s" finished with exit code %d' % (cmd,
                                                                  status))
        else:
            LOG.debug('Command "%s" finished with exit code %d' % (cmd,
                                                                   status))
        LOG.debug('Stdout: %s' % out)
        LOG.debug('Stderr: %s' % err)
        return {'ret': status, 'out': out, 'err': err}

    def prepare_size(self, str_size):
        size = str_size.lower().strip()
        if size.endswith('g'):
            size = float(size[:-1]) * 1024
        elif size.endswith('gb'):
            size = float(size[:-2]) * 1024
        elif size.endswith('m'):
            size = float(size[:-1])
        elif size.endswith('mb'):
            size = float(size[:-2])
        else:
            size = 1024
        return int(round(size))


def block_measure_dec(measure):
    def wrapper(self, m_type='default'):
        if m_type == 'thr':
            bs = str(self.max_thr) + 'M'
            count = self.thr_count
        elif m_type == 'iop':
            bs = '4K'
            count = int(self.size * 256)
        else:
            bs = '1M'
            count = int(self.size)
        self.drop_cache()
        start_time = time.time()
        ret = measure(self, bs, count)
        return time.time() - start_time if not ret else 0
    return wrapper


class BlockStorageSpeed(BaseStorageSpeed):

    def __init__(self, access_data, *args, **kwargs):
        super(BlockStorageSpeed, self).__init__(access_data, *args, **kwargs)
        self.size_str = kwargs.get('volume_size')
        self.size = 0
        self.device = None
        self.vol = None
        self.max_thr = 1
        self.thr_size = 0
        self.thr_count = 0
        self.image_name = '/mnt/testvolume/testimage.ss.img'

    def create_test_volume(self, node_id):
        LOG.debug('Creating test volume')
        self.test_vm, test_vm_ip = self.get_test_vm(node_id)
        self.set_ssh_connection(test_vm_ip)
        self.vol = self.cinderclient.volumes.create(
            int(math.ceil((self.size + 100.0) / 1024.0)))

        if not self.test_vm:
            LOG.error('Creation of test vm failed')
            raise RuntimeError
        for i in range(0, 20):
            vol = self.cinderclient.volumes.get(self.vol.id)
            if vol.status == 'available':
                break
            time.sleep(3)

        attach = self.novaclient.volumes.create_server_volume(
            self.test_vm.id,
            self.vol.id,
            device='/dev/vdb')

        LOG.debug('Result of creating volume: %s' % str(attach))

        path = '/dev/vdb'
        cmd = "test -e %s && echo 1" % path
        for i in range(0, 20):
            res = self.run_ssh_cmd(cmd)['out']
            if res:
                self.device = path
                break

            time.sleep(3)

        # NOTE: cirros or cinder work strange and sometimes attach volume
        # not to specified device, so additional check for it
        if not self.device:
            cmd = "test -e %s && echo 1" % '/dev/vdc'
            res = self.run_ssh_cmd(cmd)['out']
            if res:
                self.device = '/dev/vdc'

        if not self.device:
            LOG.error("Failed to attach test volume")
            self.cleanup(node_id)
            raise RuntimeError

        LOG.debug('Mounting volume to test VM')
        res = self.run_ssh_cmd('/usr/sbin/mkfs.ext4 %s' % self.device)
        res = self.run_ssh_cmd('mkdir -p /mnt/testvolume')
        res = self.run_ssh_cmd('mount %s /mnt/testvolume' % self.device)

        LOG.debug('Volume successfully created')

    def generate_report(self, storage, compute_name, r_res, w_res, r_res_thr,
                        w_res_thr, r_res_iop, w_res_iop):
        # Default
        r_res = [float(self.size) / i for i in r_res]
        r_average = round(sum(r_res) / float(len(r_res)), 2)
        read = ''
        resulting_list = []
        for i in range(len(r_res)):
            resulting_list.append(
                dict(node=compute_name, attempt=i+1,
                     action='read', result=r_res[i],
                     type='general', size=self.size))
        resulting_list.append(
                dict(node=compute_name, attempt='general average',
                     action='read', result=r_average,
                     type='general', size=self.size))
        w_res = [float(self.size) / i for i in w_res]
        w_average = round(sum(w_res) / float(len(w_res)), 2)
        write = ''
        for i in range(len(w_res)):
            resulting_list.append(
                dict(node=compute_name, attempt=i+1,
                     action='write', result=w_res[i],
                     type='general', size=self.size))
        resulting_list.append(
                dict(node=compute_name, attempt='general average',
                     action='read', result=w_average,
                     type='general', size=self.size))
        # Throughput
        r_res_thr = [float(self.thr_size) / i for i in r_res_thr]
        r_average_thr = round(sum(r_res_thr) / float(len(r_res_thr)), 2)
        read_thr = ''
        for i in range(len(r_res_thr)):
            resulting_list.append(
                dict(node=compute_name, attempt=i+1,
                     action='read', result=r_res_thr[i],
                     type='throughput', size=self.thr_size))
        resulting_list.append(
                dict(node=compute_name, attempt='average throughput',
                     action='read', result=r_average_thr,
                     type='throughput', size=self.thr_size))
        w_res_thr = [float(self.thr_size) / i for i in w_res_thr]
        w_average_thr = round(sum(w_res_thr) / float(len(w_res_thr)), 2)
        write_thr = ''
        for i in range(len(w_res_thr)):
            resulting_list.append(
                dict(node=compute_name, attempt=i+1,
                     action='write', result=w_res_thr[i],
                     type='throughput', size=self.thr_size))
        resulting_list.append(
                dict(node=compute_name, attempt='average throughput',
                     action='write', result=r_average_thr,
                     type='throughput', size=self.thr_size))
        # IOPs
        r_res_iop = [float(self.size) / i for i in r_res_iop]
        r_average_iop = round(sum(r_res_iop) / float(len(r_res_iop)), 2)
        read_iop = ''
        for i in range(len(r_res_iop)):
            resulting_list.append(
                dict(node=compute_name, attempt=i+1,
                     action='read', result=r_res_iop[i],
                     type='IOPs', size='4Kb'))
        resulting_list.append(
                dict(node=compute_name, attempt='average IOPs',
                     action='read', result=r_average_iop,
                     type='IOPs', size='4Kb'))
        w_res_iop = [float(self.size) / i for i in w_res_iop]
        w_average_iop = round(sum(w_res_iop) / float(len(w_res_iop)), 2)
        write_iop = ''
        for i in range(len(w_res_iop)):
            resulting_list.append(
                dict(node=compute_name, attempt=i+1,
                     action='write', result=w_res_iop[i],
                     type='IOPs', size='4Kb'))
        resulting_list.append(
                dict(node=compute_name, attempt='average IOPs',
                     action='write', result=w_average_iop,
                     type='IOPs', size='4Kb'))
        # Average
        r_res_all = r_res + r_res_thr + r_res_iop
        w_res_all = w_res + w_res_thr + w_res_iop
        r_av_all = round(sum(r_res_all) / len(r_res_all), 2)
        w_av_all = round(sum(w_res_all) / len(w_res_all), 2)
        resulting_list.append(
                dict(node=compute_name, attempt='average',
                     action='write', result=w_av_all,
                     type='All', size='All'))
        resulting_list.append(
                dict(node=compute_name, attempt='average',
                     action='read', result=r_av_all,
                     type='All', size='All'))

        return resulting_list, r_av_all, w_av_all

    def drop_cache(self):
        self.run_ssh_cmd('sync; sudo /sbin/sysctl -w vm.drop_caches=3')

    def get_max_throughput(self):
        max_mem = int(
            self.run_ssh_cmd("free -m | awk 'FNR == 3 {print $4}'")['out']) - 1
        if max_mem < self.size:
            self.max_thr = max_mem
            self.thr_count = int(math.ceil(float(self.size) /
                                           float(self.max_thr)))
            self.thr_size = int(self.max_thr * self.thr_count)
        else:
            self.max_thr = self.size
            self.thr_count = 1
            self.thr_size = int(self.max_thr * self.thr_count)
        if self.max_thr < 0 or self.thr_count < 0:
            self.max_thr = abs(self.max_thr)
            self.thr_count = abs(self.thr_count)

    def remove_file(self):
        LOG.debug('Removing file')
        self.run_ssh_cmd('rm /mnt/testvolume/testimage.ss.img')

    @block_measure_dec
    def measure_write(self, bs, count):
        LOG.info(
            "Measuring write speed: block size {0}, "
            "count {1}".format(bs, count))
        return self.run_ssh_cmd('dd if=/dev/zero of=%s bs=%s count=%d '
                                'conv=notrunc,fsync' % (
                                    self.image_name, bs, count))['ret']

    @block_measure_dec
    def measure_read(self, bs, count):
        LOG.info(
            "Measuring  read speed: block size {0}, "
            "count {1}".format(bs, count))
        return self.run_ssh_cmd('dd if=%s of=/dev/null bs=%s count=%d' % (
            self.image_name, bs, count))['ret']

    def measure_speed(self, node_id):
        self.size = self.prepare_size(self.size_str)
        self.create_test_volume(node_id)
        self.drop_cache()
        self.get_max_throughput()
        compute_name = getattr(self.test_vm, 'OS-EXT-SRV-ATTR:host')
        r_res = []
        w_res = []
        r_res_thr = []
        w_res_thr = []
        r_res_iop = []
        w_res_iop = []
        LOG.info('Starting measuring block storage r/w speed')

        self.attempts = utils.GET(
            self.config, 'attempts', 'speed',
            app_conf.SPEED_STORAGE_ATTEMPTS_DEFAULT)
        try:
            self.attempts = int(self.attempts)
        except ValueError:
            LOG.error(
                "Expected 'attempts' to be a number, "
                "but got {} value instead!".format(
                    self.attempts))
            LOG.debug("Default value {} is used for 'attempts'".format(
                app_conf.SPEED_STORAGE_ATTEMPTS_DEFAULT))
            self.attempts = app_conf.SPEED_STORAGE_ATTEMPTS_DEFAULT

        for _ in range(0, self.attempts):
            w_res.append(self.measure_write())
            r_res.append(self.measure_read())
            self.remove_file()

            w_res_thr.append(self.measure_write(m_type='thr'))
            r_res_thr.append(self.measure_read(m_type='thr'))
            self.remove_file()

            w_res_iop.append(self.measure_write(m_type='iop'))
            r_res_iop.append(self.measure_read(m_type='iop'))
            self.remove_file()
        self.cleanup(node_id)
        return self.generate_report('Block', compute_name, r_res, w_res,
                                    r_res_thr, w_res_thr, r_res_iop, w_res_iop)

    def cleanup(self, node_id):
        LOG.debug('Start cleanup resources')
        vm, ip = self.get_test_vm(node_id)

        try:
            cmds = ['umount /mnt/testvolume', 'rm -rf /mnt/testvolume']
            for cmd in cmds:
                LOG.debug('Executing command: %s' % cmd)
                res = self.run_ssh_cmd(cmd)
                LOG.debug('RESULT: %s' % str(res))
        except OSError:
            LOG.error('Unmounting volume failed')

        self.client.close()
        self.novaclient.volumes.delete_server_volume(vm.id, self.vol.id)
        LOG.debug('Waiting for volume became available')
        for i in range(0, 60):
            vol = self.cinderclient.volumes.get(self.vol.id)
            if vol.status == 'available':
                break
            time.sleep(1)
        try:
            self.cinderclient.volumes.delete(self.vol)
        except Exception:
            LOG.error('Deleting test volume failed')
        LOG.debug('Cleanup finished')


class ObjectStorageSpeed(BaseStorageSpeed):
    def __init__(self, access_data, *args, **kwargs):
        super(ObjectStorageSpeed, self).__init__(access_data, *args, **kwargs)
        self.size = self.prepare_size(kwargs['image_size'])
        self.iterations = kwargs['iterations']

        self.fuel = clients.FuelClientProxy(self.access_data)
        cluster = utils.GET(self.config, 'cluster_id', 'fuel', convert=int)
        self.nodes = self.fuel.node.get_all(environment_id=cluster)

    def measure_speed(self, node_id):
        LOG.info('Running measuring object storage r/w speed...')

        node = self._get_node_by_instance(node_id)

        measures = []
        for _ in range(self.iterations):
            measures.append(GlanceToComputeSpeedMetric(self, node).measures)

        return self.generate_report(node['fqdn'], measures)

    def generate_report(self, node_name, measures):
        record = functools.partial(dict, node=node_name, size=self.size)
        results_read, results_write = [], []

        for idx, value in enumerate(measures):
            results_read.append(record(
                action='read', attempt=idx + 1,
                speed=float(self.size) / value.download.value.total_seconds()))
            results_write.append(record(
                action='write', attempt=idx + 1,
                speed=float(self.size) / value.upload.value.total_seconds()))

        average_read = sum(x['speed'] for x in results_read) / len(measures)
        average_write = sum(x['speed'] for x in results_write) / len(measures)

        results = results_read + results_write
        results.append(
            record(action='read', attempt='average', speed=average_read))
        results.append(
            record(action='write', attempt='average', speed=average_write))

        LOG.info("Compute %s average IO with glance API results:" % node_name)
        LOG.info("Read %.3f MB/s", average_read)
        LOG.info("Write %.3f MB/s", average_write)

        return results, average_read, average_write

    def _get_node_by_instance(self, idnr):
        instance = self.novaclient.servers.get(idnr)
        hostname = getattr(instance, 'OS-EXT-SRV-ATTR:hypervisor_hostname')
        for node in self.nodes:
            if node['fqdn'] != hostname:
                continue
            break
        else:
            raise exceptions.FrameworkError(
                'Unable to locate compute node, that host VM {}'.format(idnr))
        return node

    @staticmethod
    def get_node_address(node, network='fuelweb_admin'):
        for net in node['network_data']:
            if net['name'] != network:
                continue
            break
        else:
            raise exceptions.FrameworkError(
                'Unable to network {} in node {}'.format(
                    network, node['fqdn']))
        try:
            addr = net['ip']
        except:
            raise exceptions.FrameworkError(
                'There is no IP address on node {} in network {}'.format(
                    node['fqdn'], network))
        return addr.split('/')[0]


class _MetricAbstract(object):
    def __init__(self, context):
        self.context = context


class GlanceToComputeSpeedMetric(_MetricAbstract):
    def __init__(self, context, node):
        super(GlanceToComputeSpeedMetric, self).__init__(context)
        self.node = node

        time_track = utils.TimeTrack()
        connect = self._open_ssh_connect(node)
        token = utils.TokenFactory(self.context.access_data, connect)

        glance_image_idnr = self._new_glace_image_request(connect, token)

        try:
            with time_track.record('upload'):
                self._push_glance_image_payload(
                    connect, token, glance_image_idnr)
            with time_track.record('download'):
                self._fetch_glance_image_payload(
                    connect, token, glance_image_idnr)
        finally:
            try:
                self._delete_glance_image(connect, token, glance_image_idnr)
            except exceptions.AccessError as e:
                LOG.error('Unable to complete cleanup: %s', e)
                LOG.debug('Error details', exc_info=True)

        self.measures = _GlanceSpeedResults(
            time_track.query('upload'),
            time_track.query('download'))

    def _open_ssh_connect(self, node):
        addr = self.context.get_node_address(node)
        pkey = paramiko.RSAKey.from_private_key_file(
            app_conf.DEFAULT_RSA_KEY_PATH)
        connect = ssh.SSHClient(
            addr, config.compute_login, rsa_key=pkey)

        if not connect.connect():
            raise exceptions.AccessError(
                'Can\'t access node {} via SSH {}'.format(
                    node['fqdn'], connect.identity))

        return connect

    def _new_glace_image_request(self, connect, token):
        payload = {
            'name': 'speedtest',
            'container_format': 'bare',
            'disk_format': "raw"}
        payload = json.dumps(payload)

        cmd = (
            'curl -X POST --insecure --silent '
            '--header "Content-type: application/json" '
            '--header "X-Auth-Token: {token}" '
            '--data \'{payload}\' '
            '{url_base}/images'
        ).format(
            token=token, payload=payload, url_base=self.context.glance_url)

        try:
            proc = connect.exec_cmd(cmd, exc=True)
            payload = json.loads(proc.stdout)
            idnr = payload['id']
        except (KeyError, ValueError, TypeError, exceptions.RemoteError) as e:
            raise exceptions.AccessError(
                'Image create request to glance have failed: {}'.format(e))
        return idnr

    def _push_glance_image_payload(self, connect, token, idnr):
        cmd = (
            'dd if=/dev/zero bs=32k count={count} | '
            'curl -X PUT --insecure --silent '
            '--header "X-Auth-Token: {token}" '
            '--header "Content-Type: application/octet-stream" '
            '--upload-file - '
            '{url_base}/images/{idnr}/file'
        ).format(
            count=int(self.context.size * 32), token=token,
            url_base=self.context.glance_url, idnr=idnr)

        try:
            connect.exec_cmd(cmd, exc=True)
        except exceptions.RemoteError as e:
            raise exceptions.AccessError(
                'Image create request to glance have failed: {}'.format(e))

    def _fetch_glance_image_payload(self, connect, token, idnr):
        cmd = (
            'curl -X GET --insecure --silent '
            '--header "X-Auth-Token: {token}" '
            '--output /dev/null '
            '{url_base}/images/{idnr}/file'
        ).format(
            token=token, url_base=self.context.glance_url, idnr=idnr)

        try:
            connect.exec_cmd(cmd, exc=True)
        except exceptions.RemoteError as e:
            raise exceptions.AccessError(
                'Image create request to glance have failed: {}'.format(e))

    def _delete_glance_image(self, connect, token, idnr):
        cmd = (
            'curl -X DELETE --insecure --silent '
            '--header "X-Auth-Token: {token}" '
            '{url_base}/images/{idnr}'
        ).format(token=token, url_base=self.context.glance_url, idnr=idnr)
        try:
            connect.exec_cmd(cmd, exc=True)
        except exceptions.RemoteError as e:
            raise exceptions.AccessError(
                'Image create request to glance have failed: {}'.format(e))


_GlanceSpeedResults = collections.namedtuple(
    '_GlanceSpeedresults', 'upload, download')
