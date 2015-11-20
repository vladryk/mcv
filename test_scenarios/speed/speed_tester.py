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
import logging
import subprocess
import time
import os

import cinderclient.client as cinder
import glanceclient as glance
from keystoneclient.v2_0 import client as keystone_v2
import novaclient.client as nova

LOG = logging



class BaseStorageSpeed(object):

    def __init__(self, access_data, *args, **kwargs):
        self.config = kwargs.get('config')
        self.init_clients(access_data)
        self.size = None

    def init_clients(self, access_data):
        LOG.debug("Trying to obtain authenticated OS clients")
        self.cinderclient = cinder.Client(
            '1', username=access_data['os_username'],
            auth_url=self.config.get('basic', 'auth_protocol')+"://" + access_data['auth_endpoint_ip'] + ':5000/v2.0/',
            api_key=access_data['os_password'],
            project_id=access_data['os_tenant_name'],
            insecure=True)
        self.novaclient = nova.Client(
            '2', username=access_data['os_username'],
            auth_url=self.config.get('basic', 'auth_protocol')+"://" + access_data['auth_endpoint_ip'] + ':5000/v2.0/',
            api_key=access_data['os_password'],
            project_id=access_data['os_tenant_name'],
            insecure=True)
        self.key_client = keystone_v2.Client(
            username=access_data['os_username'],
            auth_url=self.config.get('basic', 'auth_protocol')+"://" + access_data['auth_endpoint_ip'] + ':5000/v2.0/',
            password=access_data['os_password'],
            tenant_name=access_data['os_tenant_name'],
            insecure=True)
        image_api_url = self.key_client.service_catalog.url_for(
            service_type="image")
        self.glanceclient = glance.Client(
            '1',
            endpoint=image_api_url,
            token=self.key_client.auth_token,
            insecure=True)
        LOG.debug('Authentication ends well')

    def generate_report(self, storage, r_res, w_res):
        path = os.path.join(os.path.dirname(__file__), 'speed_template.html')
        temp = open(path, 'r')
        template = temp.read()
        temp.close()
        r_res.insert(0, 0)
        r_res = [i/(1000.0 * int(self.size)) for i in r_res]
        r_average = round(sum(r_res) / 3.0, 2)
        read = ''
        for i in range(1, 4):
            read +='<tr><td>{} attempt:</td><td align="right">Speed {} MB/s</td><tr>\n'.format(i, round(r_res[i],2))
        w_res.insert(0, 0)
        w_res = [i/(1000.0 * int(self.size)) for i in w_res]
        w_average = round(sum(w_res) / 3.0, 2)
        write = ''
        for i in range(1, 4):
            write +='<tr><td>{} attempt:</td><td align="right">Speed {} MB/s</td><tr>\n'.format(i, round(w_res[i], 2))
        return template.format(read=read,
                               storage=storage,
                               write=write,
                               r_average=r_average,
                               w_average=w_average), r_average, w_average


class BlockStorageSpeed(BaseStorageSpeed):

    def __init__(self, access_data, *args, **kwargs):
        super(BlockStorageSpeed, self).__init__(access_data, *args, **kwargs)
        self.size = kwargs.get('volume_size') or 1

    def create_test_volume(self):
        LOG.debug('Creating test volume')
        self.vol = self.cinderclient.volumes.create(int(self.size))
        mcv = self.novaclient.servers.find(name='mcv')
        attach = self.novaclient.volumes.create_server_volume(mcv.id, self.vol.id, device='/dev/vdb')
        path = '/dev/disk/by-id/virtio-%s' % self.vol.id[:20]
        for i in range(0, 60):
            if os.path.exists(path):
                LOG.debug('Volume created')
                break
            time.sleep(1)
        LOG.debug('Mounting volume to mcv VM')
        subprocess.call('mkfs.ext4 %s' % path, shell=True)
        subprocess.call('mkdir -p /mnt/testvolume', shell=True)
        try:
            subprocess.call('mount %s /mnt/testvolume' % path, shell=True)
        except IOError, OSError:
            LOG.error('Mounting volume failed')
            raise RuntimeError
        LOG.debug('Volume successfully created')

    def measure_write(self):
        start_time = time.time()
        count = 1000 * int(self.size)
        subprocess.call(['dd', 'conv=notrunc', 'if=/dev/urandom', 'of=/mnt/testvolume/testimage.ss.img', 'bs=1M', 'count=%d' % count])
        return time.time() - start_time

    def measure_read(self):
        start_time = time.time()
        count = 1000 * int(self.size)
        subprocess.call(['dd', 'if=/mnt/testvolume/testimage.ss.img', 'of=/dev/zero', 'bs=1M', 'count=%d' % count])
        return time.time() - start_time

    def measure_speed(self):
        self.create_test_volume()
        r_res = []
        w_res = []
        LOG.debug('Starting measurind r/w speed')
        for i in range(0, 3):
            w_res.append(self.measure_write())
            r_res.append(self.measure_read())
        self.cleanup()
        return self.generate_report('Block', r_res, w_res)

    def cleanup(self):
        LOG.debug('Start cleanup resources')
        mcv = self.novaclient.servers.find(name='mcv')
        try:
            subprocess.call('umount /mnt/testvolume', shell=True)
            subprocess.call('rm -rf /mnt/testvolume', shell=True)
        except OSError:
            LOG.error('Unmounting volume failed')

        self.novaclient.volumes.delete_server_volume(mcv.id, self.vol.id)
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
        self.size = kwargs.get('image_size') or 1

    def generate_image(self):
        LOG.debug('Generating image')
        filename = 'testglancespeed.ss.img'
        self.of = os.path.join(os.getcwd(), filename)
        if not os.path.exists(self.of):
            count = 1000 * int(self.size)
            subprocess.call(['dd', 'if=/dev/urandom', 'of=' + self.of, 'bs=1M', 'count=%d' % count])
        LOG.debug('Test image successfully generated')

    def measure_write(self):
        start_time = time.time()
        LOG.debug('Uploading image')
        self.img = self.glanceclient.images.create(
            name='mcv-test-speed', data=open(self.of, 'rb'),
            disk_format='raw', container_format='bare')
        return time.time() - start_time

    def measure_read(self):
        start_time = time.time()
        LOG.debug('Downloading image')
        data = self.glanceclient.images.data(self.img.id)
        return time.time() - start_time

    def measure_speed(self):
        self.generate_image()
        r_res = []
        w_res = []
        LOG.debug('Start measuring r/w speed')
        for i in range(0, 3):
            w_res.append(self.measure_write())
            r_res.append(self.measure_read())
            self.cleanup()
        return self.generate_report('Object', r_res, w_res)

    def cleanup(self):
        self.img.delete()
