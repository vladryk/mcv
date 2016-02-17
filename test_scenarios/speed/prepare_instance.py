import logging
import time
from threading import Thread

import glanceclient as glance
from novaclient import client as nova
from novaclient import exceptions
from keystoneclient.v2_0 import client as keystone_v2

LOG = logging


class Preparer(object):
    def __init__(self, uname=None, passwd=None,
                 auth_url=None, tenant=None,
                 region_name=None):
        self.servers = []
        self.uname = uname
        self.passwd = passwd
        self.auth_url = auth_url
        self.tenant = tenant
        self.region_name=region_name
        self.ip_list = []
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
            username=self.uname,
            api_key=self.passwd,
            project_id=self.tenant,
            auth_url=self.auth_url,
            region_name=self.region_name,
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

    def _check_instance(self, i):
        # Update instance information
        self.servers[i] = self.nova.servers.find(
            id=self.servers[i].id)
        server = self.servers[i]

        while server.status == 'BUILD':
            print 'Status instance id %s is %s' % (server.id, server.status)
            time.sleep(10)
            server = self.nova.servers.find(
                id=self.servers[i].id)

        if server.status == 'ERROR':
            LOG.warning("Server id %s is failed to start" % server.id)
            LOG.warning("Compute node %s skips test" % getattr(
                server, 'OS-EXT-SRV-ATTR:host'))
            LOG.debug("Something went wrong with the command, please"
                      " refer to nova logs to find out what")
            self.servers.remove(server)
            return

        LOG.info('Instance id %s is running' % server.id)

    def _check_instances(self):
        check_threads = []
        for i in range(len(self.servers)):
            thread = Thread(target=self._check_instance, args=(i,))
            thread.start()
            check_threads.append(thread)

        while len(check_threads):
            check_threads = [thread for thread in check_threads if
                             thread.isAlive()]
            time.sleep(1)

    def _launch_instances(self):
        LOG.info('Launch instance from cirros-image')
        image = self.nova.images.find(name="cirros-image")
        try:
            flavor = self.nova.flavors.findall(ram=64)[0]
        except exceptions.NotFound:
            flavor = self.nova.flavors.list()[0]
        network = self.nova.networks.find(label="net04")

        compute_hosts = [host for host in self.nova.hosts.list(
            zone='nova') if host.service == 'compute']

        for compute_host in compute_hosts:
            zone = 'nova:%s' % compute_host.host_name
            self.servers.append(
                self.nova.servers.create(name="speed-test",
                                         image=image.id,
                                         flavor=flavor.id,
                                         availability_zone=zone,
                                         nics=[{'net-id': network.id}]))
        self._check_instances()
        if len(self.servers):
            LOG.info('%s instances is running' % len(self.servers))
        else:
            return False

        # Note: make network name configurable
        for server in self.servers:
            floating_ip = self.nova.floating_ips.create(
                self.nova.floating_ip_pools.list()[0].name)

            server.add_floating_ip(floating_ip)
            self.ip_list.append(floating_ip)
        return True

    def delete_instances(self):
        self._get_clients()
        LOG.info('Removing instances')
        self.servers = [server for server in self.nova.servers.list() if
                        server.name == 'speed-test']
        self.ip_list = [[ip['addr'] for ip in server.addresses.values()[0] if
                         ip['OS-EXT-IPS:type'] == 'floating'][0] for server in
                        self.servers]

        [server.delete() for server in self.servers]
        self.servers = [server for server in self.nova.servers.list() if
                        server.name == 'speed-test']
        while len(self.servers):
            LOG.info('Waiting for removing instances')
            self.servers = [server for server in self.nova.servers.list() if
                            server.name == 'speed-test']
            time.sleep(5)
        floating_ips = [self.nova.floating_ips.find(ip=ip) for ip in
                        self.ip_list]
        [floating_ip.delete() for floating_ip in floating_ips]

    def prepare_instances(self):
        self._check_image()
        if not self._launch_instances():
            return None
        else:
            return [server.id for server in self.servers]

