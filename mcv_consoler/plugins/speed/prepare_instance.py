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

import time

from mcv_consoler.common.cfgparser import config_parser
from mcv_consoler.common import clients as Clients
from mcv_consoler.logger import LOG
from mcv_consoler import utils
from novaclient import exceptions

LOG = LOG.getLogger(__name__)


class Preparer(object):
    def __init__(self, access_data):
        super(Preparer, self).__init__()
        self.nova = Clients.get_nova_client(access_data)
        self.glance = Clients.get_glance_client(access_data)
        self.config = config_parser
        self.image_name = 'fedora-image'
        self.key_name = 'fedora-key'

    def _check_image(self, image_path):
        LOG.debug('Check %s in glance' % self.image_name)
        image_list = [image for image in self.glance.images.list() if
                      image.name == self.image_name]
        if not image_list:
            LOG.info('Uploading image to glance...')
            self.glance.images.create(name=self.image_name, disk_format="qcow2",
                                      container_format="bare",
                                      data=open(image_path), is_public=True)
        else:
            LOG.debug('%s exists' % self.image_name)

    def _get_server(self, server_id):
        try:
            server = self.nova.servers.find(id=server_id)
            return server
        except (exceptions.NotFound, exceptions.NoUniqueMatch):
            LOG.error(
                'Error: can not find server with id %s, deleting' % server_id)
            return None

    def _get_flavor(self, flavor_req):
        try:
            flavor = self.nova.flavors.findall(**flavor_req)[0]
        except (exceptions.NotFound, IndexError):
            LOG.debug('No suitable flavors was found, creating new flavor')

            # TODO(vokhrimenko): make these default values placed in config.py later
            ram = flavor_req['ram'] if 'ram' in flavor_req else 1024
            vcpus = flavor_req['vcpus'] if 'vcpus' in flavor_req else 1
            disk = flavor_req['disk'] if 'disk' in flavor_req else 0
            old_flavors = self.nova.flavors.findall(name='speedtest')
            if old_flavors:
                [old_flavor.delete() for old_flavor in old_flavors]
            flavor = self.nova.flavors.create('speedtest', ram, vcpus, disk)
        LOG.debug('Using flavor %s' % flavor.name)
        return flavor

    def _check_instances(self, server_ids):
        check_ids = list(server_ids)
        i = 0
        while check_ids:
            for server_id in check_ids:
                server = self._get_server(server_id)
                if server is None:
                    check_ids.remove(server_id)
                    server_ids.remove(server_id)
                    continue
                LOG.debug(
                    'Status instance id %s is %s' % (server.id, server.status))
                if server.status == 'BUILD':
                    if i > 30:
                        LOG.debug('Server %s is still in building state, '
                                  'removing' % server_id)
                        server.delete()
                        check_ids.remove(server_id)
                        server_ids.remove(server_id)
                elif server.status == 'ERROR':
                    LOG.warning("Server id %s is failed to start" % server.id)
                    LOG.warning("Compute node %s skips test" % getattr(
                        server, 'OS-EXT-SRV-ATTR:host'))
                    LOG.debug("Something went wrong with the command, please"
                              " refer to nova logs to find out what")
                    server.delete()
                    check_ids.remove(server_id)
                    server_ids.remove(server_id)
                elif server.status == 'ACTIVE':
                    check_ids.remove(server_id)
                else:
                    LOG.error('Unexpected server status "%s", '
                              'id %s, removing' % (server.status, server_id))
                    server.delete()
                    check_ids.remove(server_id)
                    server_ids.remove(server_id)
            i += 1
            if check_ids:
                time.sleep(10)

    def _launch_instances(self, flavor_req, availability_zone):
        LOG.debug('Launch instances from %s' % self.image_name)
        image = self.nova.images.findall(name=self.image_name)[0]
        flavor = self._get_flavor(flavor_req)
        try:
            self.key_fedora = self.nova.keypairs.get(self.key_name)
            self.key_fedora.delete()
            self.key_fedora = self.nova.keypairs.create(self.key_name)
        except exceptions.NotFound:
            self.key_fedora = self.nova.keypairs.create(self.key_name)
        f = open('/home/mcv/fedora.pem', 'w')
        f.write(self.key_fedora.private_key)
        f.close()

        network_name = utils.GET(self.config, "network_name", "network_speed")
        if not network_name:
            LOG.error("Failed to get option 'network_speed:network_name' from "
                      "configuration file. Using default value 'net04'")
            network_name = 'net04'
        try:
            network = self.nova.networks.find(label=network_name)
        except exceptions.NotFound:
            LOG.error('No networks with default label was found')
            raise RuntimeError

        compute_hosts = [host for host in self.nova.hosts.list(
            zone=availability_zone) if host.service == 'compute']

        compute_nodes_limit = utils.GET(self.config,
                                        'compute_nodes_limit',
                                        'speed')
        if compute_nodes_limit is not None:
            compute_hosts = compute_hosts[:int(compute_nodes_limit)]
            LOG.debug('Speed will be measured on {} compute nodes'.format(
                len(compute_hosts)))
        else:
            LOG.debug('Speed will be measured on all compute nodes')

        if not compute_hosts:
            LOG.error('No compute hosts was found')
            raise RuntimeError

        server_ids = []

        for compute_host in compute_hosts:
            zone = '%s:%s' % (availability_zone, compute_host.host_name)
            try:
                server_ids.append(
                    self.nova.servers.create(name="speed-test",
                                             image=image.id,
                                             flavor=flavor.id,
                                             key_name=self.key_name,
                                             availability_zone=zone,
                                             nics=[{'net-id': network.id}]).id)
            except Exception:
                LOG.error('Error - nova can not create test nodes')
                raise RuntimeError

        self._check_instances(server_ids)
        if not server_ids:
            return None
        network_name = utils.GET(
                 self.config, 'network_ext_name', 'network_speed'
                ) or self.nova.floating_ip_pools.list()[0].name

        server_ids_copy = server_ids[:]

        for server_id in server_ids_copy:
            server = self._get_server(server_id)
            if server is None:
                server_ids.remove(server_id)
                continue
            try:
                floating_ip = self.nova.floating_ips.create(network_name)
                server.add_floating_ip(floating_ip)
            except Exception:
                server_ids.remove(server_id)
                LOG.error("Can't create floating IP from pool")

        if server_ids:
            LOG.debug('%s instances is running and ready' % len(server_ids))
            return server_ids
        else:
            return None

    def delete_instances(self):
        LOG.debug('Removing instances')
        servers = [server for server in self.nova.servers.list() if
                   server.name == 'speed-test']
        ip_list = [[ip['addr'] for ip in server.addresses.values()[0] if
                    ip['OS-EXT-IPS:type'] == 'floating'][0] for server in
                   servers]

        [server.delete() for server in servers]
        servers = [server for server in self.nova.servers.list() if
                   server.name == 'speed-test']
        while servers:
            LOG.debug('Waiting for removing instances')
            servers = [server for server in self.nova.servers.list() if
                       server.name == 'speed-test']
            time.sleep(5)
        floating_ips = [self.nova.floating_ips.find(ip=ip) for ip in
                        ip_list]
        [floating_ip.delete() for floating_ip in floating_ips]

        old_flavors = self.nova.flavors.findall(name='speedtest')
        if old_flavors:
            [old_flavor.delete() for old_flavor in old_flavors]
        self.key_fedora.delete()

    def prepare_instances(self, image_path, flavor_req, availability_zone):
        self._check_image(image_path)
        return self._launch_instances(flavor_req, availability_zone)
