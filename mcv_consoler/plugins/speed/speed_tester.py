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

import json
import math
import os
import paramiko
import time

from mcv_consoler.common import clients as Clients
from mcv_consoler.logger import LOG

LOG = LOG.getLogger(__name__)


class BaseStorageSpeed(object):

    def __init__(self, access_data, *args, **kwargs):
        self.config = kwargs.get('config')
        self.access_data = access_data
        protocol = 'https' if self.access_data['insecure'] else 'http'
        self.glance_url = "{protocol}://{endpoint}:9292/v2".format(
                              protocol=protocol,
                              endpoint=self.access_data['ips']['endpoint'])
        self.timeout = 0
        self.test_vm = None
        self.init_clients()

    def init_clients(self):
        LOG.debug("Trying to obtain authenticated OS clients")
        self.cinderclient = Clients.get_cinder_client(self.access_data)
        self.novaclient = Clients.get_nova_client(self.access_data)
        LOG.debug('Authentication ends well')

    def generate_report(self, storage, compute_name, r_res, w_res):
        path = os.path.join(os.path.dirname(__file__), 'speed_template.html')
        temp = open(path, 'r')
        template = temp.read()
        temp.close()
        r_res = [float(self.size) / i for i in r_res]
        r_average = round(sum(r_res) / float(len(r_res)), 2)
        read = ''
        for i in range(len(r_res)):
            read += ('<tr><td>{} attempt:</td><td align="right">Speed '
                     '{} MB/s</td><tr>\n').format(i + 1, round(r_res[i], 2))
        w_res = [float(self.size) / i for i in w_res]
        w_average = round(sum(w_res) / float(len(w_res)), 2)
        write = ''
        for i in range(len(w_res)):
            write += ('<tr><td>{} attempt:</td><td align="right">Speed '
                      '{} MB/s</td><tr>\n').format(i + 1, round(w_res[i], 2))

        LOG.info("Compute %s average results:" % compute_name)
        LOG.info("Read %s MB/s" % r_average)
        LOG.info("Write %s MB/s\n" % w_average)
        return template.format(read=read,
                               storage=storage,
                               compute=compute_name,
                               write=write,
                               r_average=r_average,
                               w_average=w_average), r_average, w_average

    def get_test_vm(self, node_id):
        vm = self.novaclient.servers.find(id=node_id)
        floating_ip = [ip['addr'] for ip in vm.addresses.values()[0] if
                       ip['OS-EXT-IPS:type'] == 'floating'][0]
        return vm, floating_ip

    def set_ssh_connection(self, ip):
        hostname = ip
        port = 22
        username = 'cirros'
        password = 'cubswin:)'

        conn = False
        for i in range(0, 20):
            try:
                self.client = paramiko.Transport((hostname, port))
                self.client.connect(username=username, password=password)
                conn = True
                break
            except paramiko.SSHException:
                LOG.info('Waiting for test VM became available')
            time.sleep(10)
        if conn:
            LOG.info('SSH connection to test VM successfully established')
        else:
            raise RuntimeError("Can't connect to test vm")

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
            LOG.info('Command "%s" finished with exit code %d' % (cmd, status))
        else:
            LOG.debug('Command "%s" finished with exit code %d' % (cmd, status))
        LOG.debug('Stdout: %s' % out)
        LOG.debug('Stderr: %s' % err)
        return {'ret': status, 'out': out, 'err': err}

    def prepare_size(self, str_size):
        size = ''.join(i for i in str_size if i.isdigit())
        if str_size.endswith('G') or str_size.endswith('Gb'):
            size = int(size) * 1024
        elif str_size.endswith('M') or str_size.endswith('Mb'):
            size = int(size)
        else:
            size = 1024
        return size


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

        attach = self.novaclient.volumes.create_server_volume(self.test_vm.id,
                                                              self.vol.id,
                                                              device='/dev/vdb')
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
        path = os.path.join(os.path.dirname(__file__),
                            'block_speed_template.html')
        temp = open(path, 'r')
        template = temp.read()
        temp.close()

        # Default
        r_res = [float(self.size) / i for i in r_res]
        r_average = round(sum(r_res) / float(len(r_res)), 2)
        read = ''
        for i in range(len(r_res)):
            read += ('<tr><td>{} attempt:</td><td align="right">Speed {} '
                     'MB/s</td><tr>\n').format(i+1, round(r_res[i], 2))
        w_res = [float(self.size) / i for i in w_res]
        w_average = round(sum(w_res) / float(len(w_res)), 2)
        write = ''
        for i in range(len(w_res)):
            write += ('<tr><td>{} attempt:</td><td align="right">Speed {} '
                      'MB/s</td><tr>\n').format(i+1, round(w_res[i], 2))

        # Throughput
        r_res_thr = [float(self.thr_size) / i for i in r_res_thr]
        r_average_thr = round(sum(r_res_thr) / float(len(r_res_thr)), 2)
        read_thr = ''
        for i in range(len(r_res_thr)):
            read_thr += ('<tr><td>{} attempt:</td><td align="right">Speed {}'
                         ' MB/s</td><tr>\n').format(i+1,
                                                    round(r_res_thr[i], 2))
        w_res_thr = [float(self.thr_size) / i for i in w_res_thr]
        w_average_thr = round(sum(w_res_thr) / float(len(w_res_thr)), 2)
        write_thr = ''
        for i in range(len(w_res_thr)):
            write_thr += ('<tr><td>{} attempt:</td><td align="right">Speed {} '
                          'MB/s</td><tr>\n').format(i+1,
                                                    round(w_res_thr[i], 2))

        # IOPs
        r_res_iop = [float(self.size) / i for i in r_res_iop]
        r_average_iop = round(sum(r_res_iop) / float(len(r_res_iop)), 2)
        read_iop = ''
        for i in range(len(r_res_iop)):
            read_iop += ('<tr><td>{} attempt:</td><td align="right">Speed {}'
                         ' MB/s</td><tr>\n').format(i+1,
                                                    round(r_res_iop[i], 2))
        w_res_iop = [float(self.size) / i for i in w_res_iop]
        w_average_iop = round(sum(w_res_iop) / float(len(w_res_iop)), 2)
        write_iop = ''
        for i in range(len(w_res_iop)):
            write_iop += ('<tr><td>{} attempt:</td><td align="right">Speed {}'
                          ' MB/s</td><tr>\n').format(i+1,
                                                     round(w_res_iop[i], 2))

        # Average
        r_res_all = r_res + r_res_thr + r_res_iop
        w_res_all = w_res + w_res_thr + w_res_iop
        r_av_all = round(sum(r_res_all) / len(r_res_all), 2)
        w_av_all = round(sum(w_res_all) / len(w_res_all), 2)

        LOG.info("Compute %s average results:" % compute_name)
        LOG.info("Read %s MB/s" % r_av_all)
        LOG.info("Write %s MB/s\n" % w_av_all)

        return template.format(read=read,
                               storage=storage,
                               compute=compute_name,
                               write=write,
                               r_average=r_average,
                               w_average=w_average,
                               read_thr=read_thr,
                               write_thr=write_thr,
                               r_average_thr=r_average_thr,
                               w_average_thr=w_average_thr,
                               read_iop=read_iop,
                               write_iop=write_iop,
                               r_average_iop=r_average_iop,
                               w_average_iop=w_average_iop,
                               r_av_all=r_av_all,
                               w_av_all=w_av_all), r_av_all, w_av_all

    def drop_cache(self):
        self.run_ssh_cmd('sync; sudo /sbin/sysctl -w vm.drop_caches=3')

    def get_max_throughput(self):
        max_mem = int(
            self.run_ssh_cmd("free -m | awk 'FNR == 3 {print $4}'")['out']) - 1
        if max_mem < self.size:
            self.max_thr = max_mem
            self.thr_count = int(math.ceil(float(self.size) / float(self.max_thr)))
            self.thr_size = int(self.max_thr * self.thr_count)
        else:
            self.max_thr = self.size
            self.thr_count = 1
            self.thr_size = int(self.max_thr * self.thr_count)

    def remove_file(self):
        LOG.debug('Removing file')
        self.run_ssh_cmd('rm /mnt/testvolume/testimage.ss.img')

    @block_measure_dec
    def measure_write(self, bs, count):
        LOG.info('Measuring write speed')
        return self.run_ssh_cmd('dd if=/dev/zero of=%s bs=%s count=%d '
                                'conv=notrunc,fsync' % (
                                    self.image_name, bs, count))['ret']

    @block_measure_dec
    def measure_read(self, bs, count):
        LOG.info('Measuring read speed')
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
        for i in range(0, 3):
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


def object_measure_dec(measure):
    def wrapper(self, image_id=None, token=None):
        if image_id is None:
            return 0
        if token is None:
            token = self.get_token()
        else:
            token = self.get_token() if self.is_expired() else token
        start_time = time.time()
        measure(self, image_id, token)
        return time.time() - start_time
    return wrapper


class ObjectStorageSpeed(BaseStorageSpeed):

    def __init__(self, access_data, *args, **kwargs):
        super(ObjectStorageSpeed, self).__init__(access_data, *args, **kwargs)
        self.size_str = kwargs.get('image_size')
        self.size = 0
        self.start_time = 0

    def is_expired(self):
        if time.time() - self.start_time > 3600:
            return True
        else:
            return False

    def separate_out(self, out):
        res = out.split('---')
        try:
            data = res[0]
            code = int(res[1])
            LOG.debug("Http code - %d, data - %s" % (code, data))
            return code, data
        except KeyError:
            LOG.error('Parsing out failed')
            raise RuntimeError

    def get_token(self):
        self.start_time = time.time()

        cmd = ('curl -k -s -w "---%%{http_code}" '
               '-d \'{"auth":{"tenantName": "%s", '
               '"passwordCredentials": {"username": "%s", '
               '"password": "%s"}}}\' -H "Content-type: application/json" '
               '%s/tokens') % (
            self.access_data['tenant_name'],
            self.access_data['username'],
            self.access_data['password'],
            self.access_data['auth_url'])

        res = self.run_ssh_cmd(cmd)
        out = res['out']
        ret = res['ret']
        if not out:
            LOG.warning('Token has not received, retrying')
            return self.get_token()
        code, data = self.separate_out(out)
        if ret or code != 200:
            LOG.error('Get token error, exit code - %s, '
                      'http code - %s' % (ret, code))
            raise RuntimeError
        else:
            try:
                token_id = json.loads(data)['access']['token']['id']
                return token_id
            except KeyError:
                LOG.error('Invalid token data received')
                raise RuntimeError

    def create_image(self, token):
        cmd = ('curl -k -s -w "---%%{http_code}" '
               '-X POST -H \'X-Auth-Token: %s\' '
               '-H \'Content-Type: application/json\' '
               '-d \'{"name": "speedtest", "container_format": "bare", '
               '"disk_format": "raw"}\' '
               '%s/images') % (
            token,
            self.glance_url)

        res = self.run_ssh_cmd(cmd)
        out = res['out']
        ret = res['ret']
        if not out:
            LOG.warning('Creating failed, retrying')
            return self.create_image(token)
        code, data = self.separate_out(out)
        if ret or code != 201:
            LOG.error('Create image error, exit code - %s, '
                      'http code - %s' % (ret, code))
            raise RuntimeError
        else:
            try:
                image_id = json.loads(data)['id']
                return image_id
            except KeyError:
                LOG.error('Invalid image data received')
                raise RuntimeError

    @object_measure_dec
    def upload_image(self, image_id, token):
        LOG.info('Uploading image')

        cmd = ('dd if=/dev/zero bs=32k count=%d | '
               'curl -k -s -w "---%%{http_code}" -X PUT -H '
               '\'X-Auth-Token: %s\' '
               '-H \'Content-Type: application/octet-stream\' '
               '-T - %s/images/%s/file') % (
            int(self.size * 32),
            token,
            self.glance_url,
            image_id)

        res = self.run_ssh_cmd(cmd)
        out = res['out']
        ret = res['ret']
        code = self.separate_out(out)[0]
        if ret or code != 204:
            LOG.error('Upload image error, exit code - %s, '
                      'http code - %s' % (ret, code))
            raise RuntimeError

    @object_measure_dec
    def download_image(self, image_id, token):
        LOG.info('Downloading image')

        cmd = ('curl -k -s -w "---%%{http_code}" '
               '-X GET -H \'X-Auth-Token: %s\' '
               '%s/images/%s/file -o /dev/null') % (
            token,
            self.glance_url,
            image_id)
        res = self.run_ssh_cmd(cmd)
        out = res['out']
        ret = res['ret']
        code = self.separate_out(out)[0]
        if ret or code != 200:
            LOG.error('Download image error, exit code - %s, '
                      'http code - %s' % (ret, code))
            raise RuntimeError

    def delete_image(self, image_id, token):
        cmd = ('curl -k -s -w "---%%{http_code}" '
               '-X DELETE -H \'X-Auth-Token: %s\' '
               '%s/images/%s') % (
            token,
            self.glance_url,
            image_id)
        res = self.run_ssh_cmd(cmd)
        out = res['out']
        ret = res['ret']
        code = self.separate_out(out)[0]
        if ret or code != 204:
            LOG.error('Delete image error, exit code - %s, '
                      'http code - %s' % (ret, code))
            raise RuntimeError

    def measure_speed(self, node_id):
        self.size = self.prepare_size(self.size_str)
        self.test_vm, test_vm_ip = self.get_test_vm(node_id)
        self.set_ssh_connection(test_vm_ip)
        compute_name = getattr(self.test_vm, 'OS-EXT-SRV-ATTR:host')
        r_res = []
        w_res = []
        LOG.info('Start measuring object storage r/w speed')
        token = self.get_token()
        for i in range(0, 3):
            image_id = self.create_image(
                self.get_token() if self.is_expired() else token)
            w_res.append(self.upload_image(image_id=image_id, token=token))
            r_res.append(self.download_image(image_id=image_id, token=token))
            self.delete_image(image_id,
                              self.get_token() if self.is_expired() else token)
            time.sleep(1)
        self.cleanup(node_id)
        return self.generate_report('Object', compute_name, r_res, w_res)

    def cleanup(self, node_id):
        images = self.novaclient.images.findall(name='speedtest')
        [image.delete() for image in images]
