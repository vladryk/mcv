import logging
import time

import glanceclient as glance
from novaclient import client as nova
from keystoneclient.v2_0 import client as keystone_v2

LOG = logging


class Preparer(object):
    def __init__(self, uname=None, passwd=None,
                 auth_url=None, tenant=None):
        self.server = None
        self.uname = uname
        self.passwd = passwd
        self.auth_url = auth_url
        self.tenant = tenant
        self.ip = ''
        super(Preparer, self).__init__()

    def _get_clients(self):
        self.key_client = keystone_v2.Client(
            username=self.uname,
            auth_url=self.auth_url,
            password=self.passwd,
            tenant_name=self.tenant,
            insecure=True
        )
        image_api_url = self.key_client.service_catalog.url_for(
            service_type="image")
        self.glance = glance.Client(
            '1',
            endpoint=image_api_url,
            token=self.key_client.auth_token,
            insecure=True
        )
        self.nova = nova.Client(
            '2',
            self.uname,
            self.passwd,
            self.tenant,
            self.auth_url,
            insecure=True
        )

    def _check_image(self):
        LOG.info('Check cirros-image in glance')
        # Note: made path to image configurable
        path = '/etc/toolbox/rally/cirros-0.3.1-x86_64-disk.img'
        self._get_clients()
        i_list = self.glance.images.list()
        image = False
        for im in i_list:
            if im.name == 'cirros-image':
                image = True
        if not image:
            LOG.info('Upload image to glance')
            self.glance.images.create(name='cirros-image', disk_format="qcow2",
                                      container_format="bare", data=open(path))
        else:
            LOG.info('Cirros-image exists')

    def _check_instance(self):
        # Update instance information
        self.server = self.nova.servers.find(id=self.server.id)

        print 'Status insance is %s' % self.server.status
        if self.server.status == 'BUILD':
            time.sleep(60)
            self._check_instance()
        if self.server.status == 'ERROR':
            LOG.debug("Something went wrong with the command, please"\
                      " refer to nova logs to find out what")
            return False
        return True

    def _launch_instance(self):
        LOG.info('Launch instance from cirros-image')
        image = self.nova.images.find(name="cirros-image")
        flavor = self.nova.flavors.find(name="m1.nano")
        network = self.nova.networks.find(label="net04")
        self.server = self.nova.servers.create(name="speed-test",
                                               image=image.id,
                                               flavor=flavor.id,
                                               nics=[{'net-id': network.id}])
        success = self._check_instance()
        if success:
            LOG.info('Instance is running')
        else:
            return False

        # Note: make network name configurable
        floating_ip = self.nova.floating_ips.create(
            self.nova.floating_ip_pools.list()[0].name)

        self.server.add_floating_ip(floating_ip)
        self.ip = floating_ip.ip
        # Update instance information
        self.server = self.nova.servers.find(id=self.server.id)
        return True

    def delete_instance(self):
        self._get_clients()
        LOG.info('Removing instance')
        i_list = self.nova.servers.list()
        for vm in i_list:
            if vm.name == 'speed-test':
                self.server = vm

        if self.server:
            self.server.delete()

    def prepare_instance(self):
        self._check_image()
        if not self._launch_instance():
            return None
        else:
            return self.ip

