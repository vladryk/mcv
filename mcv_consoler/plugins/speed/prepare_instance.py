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

    def _check_image(self, image_path):
        LOG.info('Check cirros-image in glance')
        image_list = [image for image in self.glance.images.list() if
                      image.name == 'cirros-image']
        if not image_list:
            LOG.info('Upload image to glance')
            self.glance.images.create(name='cirros-image', disk_format="qcow2",
                                      container_format="bare",
                                      data=open(image_path), is_public=True)
        else:
            LOG.info('Cirros-image exists')

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
            LOG.info('No suitable flavors was found, creating new flavor')

            ram = flavor_req['ram'] if 'ram' in flavor_req else 64
            vcpus = flavor_req['vcpus'] if 'vcpus' in flavor_req else 1
            disk = flavor_req['disk'] if 'disk' in flavor_req else 0
            old_flavors = self.nova.flavors.findall(name='speedtest')
            if old_flavors:
                [old_flavor.delete() for old_flavor in old_flavors]
            flavor = self.nova.flavors.create('speedtest', ram, vcpus, disk)
        LOG.info('Using flavor %s' % flavor.name)
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
                LOG.info(
                    'Status instance id %s is %s' % (server.id, server.status))
                if server.status == 'BUILD':
                    if i > 20:
                        LOG.info('Server %s is still in building state, '
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

    def _launch_instances(self, flavor_req):
        LOG.info('Launch instances from cirros-image')
        image = self.nova.images.findall(name="cirros-image")[0]
        flavor = self._get_flavor(flavor_req)
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
            zone='nova') if host.service == 'compute']

        if not compute_hosts:
            LOG.error('No compute hosts was found')
            raise RuntimeError

        server_ids = []

        for compute_host in compute_hosts:
            zone = 'nova:%s' % compute_host.host_name
            try:
                server_ids.append(
                    self.nova.servers.create(name="speed-test",
                                             image=image.id,
                                             flavor=flavor.id,
                                             availability_zone=zone,
                                             nics=[{'net-id': network.id}]).id)
            except Exception:
                LOG.error('Error - nova can not create test nodes')
                raise RuntimeError

        self._check_instances(server_ids)
        if not server_ids:
            return None

        for server_id in server_ids:
            server = self._get_server(server_id)
            if server is None:
                server_ids.remove(server_id)
                continue

            floating_ip = self.nova.floating_ips.create(
                self.nova.floating_ip_pools.list()[0].name)
            server.add_floating_ip(floating_ip)

        if server_ids:
            LOG.info('%s instances is running and ready' % len(server_ids))
            return server_ids
        else:
            return None

    def delete_instances(self):
        LOG.info('Removing instances')
        servers = [server for server in self.nova.servers.list() if
                   server.name == 'speed-test']
        ip_list = [[ip['addr'] for ip in server.addresses.values()[0] if
                    ip['OS-EXT-IPS:type'] == 'floating'][0] for server in
                   servers]

        [server.delete() for server in servers]
        servers = [server for server in self.nova.servers.list() if
                   server.name == 'speed-test']
        while servers:
            LOG.info('Waiting for removing instances')
            servers = [server for server in self.nova.servers.list() if
                       server.name == 'speed-test']
            time.sleep(5)
        floating_ips = [self.nova.floating_ips.find(ip=ip) for ip in
                        ip_list]
        [floating_ip.delete() for floating_ip in floating_ips]

        old_flavors = self.nova.flavors.findall(name='speedtest')
        if old_flavors:
            [old_flavor.delete() for old_flavor in old_flavors]

    def prepare_instances(self, image_path, flavor_req):
        self._check_image(image_path)
        return self._launch_instances(flavor_req)
