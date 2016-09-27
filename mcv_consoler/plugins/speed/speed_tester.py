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
import functools
import json
import logging
import math
import time

from oslo_config import cfg

from mcv_consoler.common import clients
from mcv_consoler.common import config as app_conf
from mcv_consoler.common import ssh
from mcv_consoler import exceptions
from mcv_consoler.plugins.speed import config
from mcv_consoler import utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class BaseStorageSpeed(object):
    ssh_connect = None

    def __init__(self, ctx, **kwargs):
        self.ctx = ctx
        self.access_data = self.ctx.access_data
        self.iterations = kwargs['iterations']

        protocol = 'https' if self.access_data['insecure'] else 'http'

        self.glance_url = "{protocol}://{endpoint}:9292/v2".format(
            protocol=protocol,
            endpoint=self.access_data['public_endpoint_ip'])

        self.timeout = 0

        self.cinderclient = clients.get_cinder_client(self.access_data)
        self.novaclient = clients.get_nova_client(self.access_data)
        self.glance = clients.get_glance_client(self.access_data)

    def cleanup(self, vm_uuid):
        pass

    @staticmethod
    def get_vm_external_addr(vm):
        floating_ip = [ip['addr'] for ip in vm.addresses.values()[0] if
                       ip['OS-EXT-IPS:type'] == 'floating'][0]
        return floating_ip

    def set_ssh_connection(self, hostname):
        work_dir = self.ctx.work_dir
        self.ssh_connect = ssh.SSHClient(
            hostname, config.tool_vm_login,
            rsa_key=work_dir.resource(work_dir.RES_TOOL_VM_SSH_KEY),
            timeout=config.tool_vm_connect_tout)

        now = time.time()
        timeout = now + config.tool_vm_connect_tout
        attempt = 0
        while now < timeout:
            attempt += 1
            LOG.debug('Make SSH connect on "tool" VM (try #%d)', attempt)
            if self.ssh_connect.connect(quiet=True):
                break
            time.sleep(4)
            now = time.time()
        else:
            raise RuntimeError("Can't connect to test vm")

        LOG.debug('SSH connection to test VM successfully established')

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
        return int(size)


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


# TODO(dbogun): rewrite to match "style" of ObjectStorageSpeed
class BlockStorageSpeed(BaseStorageSpeed):
    # FIXME(dbogun): should we use config option?
    image_name = '/mnt/testvolume/testimage.ss.img'

    _measure_kinds = ('general', 'throughput', 'IOPs')

    def __init__(self, ctx, **kwargs):
        super(BlockStorageSpeed, self).__init__(ctx, **kwargs)
        self.size = self.prepare_size(kwargs['volume_size'])
        self.device = None
        self.vol = None
        self.max_thr = 1
        self.thr_size = 0
        self.thr_count = 0

    def create_test_volume(self, target_vm):
        LOG.debug('Creating test volume')

        # We can to write up to self.size * 2, because of logic in
        # "threshold" test
        self.vol = self.cinderclient.volumes.create(
            int(math.ceil((self.size * 2) / 1024.0)))

        for i in range(0, 20):
            vol = self.cinderclient.volumes.get(self.vol.id)
            if vol.status == 'available':
                break
            time.sleep(3)

        mount_path_start = self.ssh_connect.exec_cmd(
            'lsblk -din --output=NAME', exc=True).stdout

        attach = self.novaclient.volumes.create_server_volume(
            target_vm.id,
            self.vol.id)

        LOG.debug('Result of creating volume: %s' % str(attach))

        mount_path_end = ''
        for i in range(0, 20):
            LOG.debug('Try to find new block device')
            mount_path_end = self.ssh_connect.exec_cmd(
                'lsblk -din --output=NAME', exc=True).stdout
            if mount_path_end == mount_path_start:
                time.sleep(3)
                continue
            LOG.debug('Founded new block device /dev/{}'.format(
                mount_path_end))
            break

        if mount_path_end == mount_path_start:
            raise exceptions.MountError(
                "Can't mount server volume {} to {}".format(
                    self.vol.id, target_vm.id)
            )

        mounted_path = list(
            set(mount_path_end.split('\n')
                ) - set(mount_path_start.split('\n')))[0]

        LOG.debug('Server volume was attached to {}'.format(mounted_path))

        self.device = '/dev/' + mounted_path

        LOG.debug('Mounting volume to test VM')
        self.ssh_connect.exec_cmd(
            'sudo mkfs -t ext4 {}'.format(self.device), exc=True)
        self.ssh_connect.exec_cmd('sudo mkdir -p /mnt/testvolume', exc=True)
        self.ssh_connect.exec_cmd(
            'sudo mount {} /mnt/testvolume'.format(self.device), exc=True)

        LOG.debug('Volume successfully created')

    def drop_cache(self):
        self.ssh_connect.exec_cmd(
            'sync; sudo /sbin/sysctl -w vm.drop_caches=3', exc=True)

    def get_max_throughput(self):
        proc = self.ssh_connect.exec_cmd(
            'free --mega | awk "\\$1 == \\"Mem:\\" {print \\$4, \\$6}"',
            exc=True)

        mem_free, mem_cache = map(int, proc.stdout.rstrip().split())
        mem_free += mem_cache - int(mem_cache / 5)

        block_size = mem_free
        block_size = min(block_size, self.size)
        block_size = max(block_size, 1)

        block_count = float(self.size) / block_size
        block_count = math.ceil(block_count)
        block_count = int(block_count)

        self.thr_count, self.thr_size = block_count, block_size

    def remove_file(self):
        LOG.debug('Removing file')
        self.ssh_connect.exec_cmd(
            'sudo rm {}'.format(self.image_name), exc=True)

    @block_measure_dec
    def measure_write(self, bs, count):
        LOG.info(
            "Measuring write speed: block size {0}, "
            "count {1}".format(bs, count))
        return self.ssh_connect.exec_cmd(
            'sudo dd if=/dev/zero of={} bs={} count={} '
            'conv=notrunc,fsync'.format(
                self.image_name, bs, count), exc=True).rcode

    @block_measure_dec
    def measure_read(self, bs, count):
        LOG.info(
            "Measuring read speed: block size {0}, "
            "count {1}".format(bs, count))
        return self.ssh_connect.exec_cmd(
            'sudo dd if={} of=/dev/null bs={} count={}'.format(
                self.image_name, bs, count)).rcode

    def measure_speed(self, vm):
        vm_addr = self.get_vm_external_addr(vm)
        self.set_ssh_connection(vm_addr)

        self.create_test_volume(vm)
        self.drop_cache()
        self.get_max_throughput()

        compute_host = getattr(vm, 'OS-EXT-SRV-ATTR:host')

        LOG.info('Starting measuring block storage r/w speed')

        results = {}
        for _ in range(0, self.iterations):
            for kind, report in zip(
                    (None, 'thr', 'iop'),
                    self._measure_kinds):
                args = {}
                if kind is not None:
                    args['m_type'] = kind

                storage = results.setdefault(report, [])
                storage.append(_BlockDeviceSpeedResults(
                    self.measure_write(**args),
                    self.measure_read(**args)))
                self.remove_file()

        return self.generate_report(compute_host, results)

    def cleanup(self, vm):
        LOG.debug('Start cleanup resources')

        for cmd in [
                'sudo umount /mnt/testvolume',
                'sudo rm -rf /mnt/testvolume']:
            self.ssh_connect.exec_cmd(cmd, exc=True)

        self.ssh_connect.close()
        self.novaclient.volumes.delete_server_volume(vm.id, self.vol.id)
        LOG.debug('Waiting for volume became available')
        for i in range(0, 60):
            vol = self.cinderclient.volumes.get(self.vol.id)
            if vol.status == 'available':
                break
            time.sleep(1)
        self.cinderclient.volumes.delete(self.vol)
        LOG.debug('Cleanup finished')

    def generate_report(self, node, measures):
        results = []
        # FIXME(dbogun): clear what must be stored into "size" field
        # FIXME(dbogun): avoid this magic constants
        size_map = dict(zip(
            measures,
            ('1Mb', '{}Mb'.format(self.max_thr), '4Kb')))

        for kind in measures:
            results += self._prepare_report_payload(
                node, kind, measures[kind], size_map[kind])

        average = {
            'read': 0,
            'write': 0}
        counts = {x: 0 for x in average}
        for row in results:
            if row.pop('calculated', False):
                continue
            average[row['action']] += row['result']
            counts[row['action']] += 1

        record = functools.partial(
            dict, node=node, type='All', size='All', attempt='average')

        for kind in average:
            average[kind] /= counts[kind]
            results.append(record(action=kind, result=average[kind]))

        return results, average['read'], average['write']

    def _prepare_report_payload(self, node, measure_kind, raw, size):
        payload = [[], []]
        average = [[0], [0]]
        action_labels = ('write', 'read')
        record = functools.partial(
            dict, node=node, type=measure_kind, size=size)

        for attempt, measure in enumerate(raw):
            for value, storage, avg, action in zip(
                    measure, payload, average, action_labels):
                if value:
                    value = self.size / float(value)
                else:
                    value = 0.0
                storage.append(record(
                    result=measure.read, attempt=attempt + 1, action=action))
                avg[0] += value

        for idx, avg in enumerate(average):
            average[idx] = record(
                calculated=True,
                result=avg[0] / len(raw),
                attempt='{} average'.format(measure_kind),
                action=action_labels[idx])

        results = []
        for storage, avg in zip(payload, average):
            results += storage
            results.append(avg)

        return results


class ObjectStorageSpeed(BaseStorageSpeed):
    def __init__(self, ctx, **kwargs):
        super(ObjectStorageSpeed, self).__init__(ctx, **kwargs)
        self.size = self.prepare_size(kwargs['image_size'])

        nodes = self.ctx.access.fuel.node.get_all(
            environment_id=CONF.fuel.cluster_id)
        self.nodes = self.ctx.access.fuel.filter_nodes_by_status(nodes)

    def measure_speed(self, vm):
        LOG.info('Running measuring object storage r/w speed...')

        node = self._get_node_by_instance(vm.id)

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


class _MetricAbstract(object):
    def __init__(self, manager):
        self.manager = manager


class GlanceToComputeSpeedMetric(_MetricAbstract):
    def __init__(self, manager, node):
        super(GlanceToComputeSpeedMetric, self).__init__(manager)
        self.node = node

        time_track = utils.TimeTrack()
        connect = self._open_ssh_connect(node)
        token = utils.TokenFactory(self.manager.access_data, connect)

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
        fuel = self.manager.ctx.access.fuel
        work_dir = self.manager.ctx.work_dir

        connect = ssh.SSHClient(
            fuel.get_node_address(node), app_conf.OS_NODE_SSH_USER,
            rsa_key=work_dir.resource(work_dir.RES_OS_SSH_KEY))

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
            token=token, payload=payload, url_base=self.manager.glance_url)

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
            count=int(self.manager.size * 32), token=token,
            url_base=self.manager.glance_url, idnr=idnr)

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
            token=token, url_base=self.manager.glance_url, idnr=idnr)

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
        ).format(token=token, url_base=self.manager.glance_url, idnr=idnr)
        try:
            connect.exec_cmd(cmd, exc=True)
        except exceptions.RemoteError as e:
            raise exceptions.AccessError(
                'Image create request to glance have failed: {}'.format(e))


_BlockDeviceSpeedResults = collections.namedtuple(
    '_BlockDeviceSpeedResults', 'write, read')
_GlanceSpeedResults = collections.namedtuple(
    '_GlanceSpeedresults', 'upload, download')
