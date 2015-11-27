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
import logging
import os

import novaclient.client as nova
import cinderclient.client as cinder
from neutronclient.neutron import client as neutron
import glanceclient as glance
from keystoneclient.v2_0 import client as keystone_v2

LOG = logging

RESOURCES_TEMPLATE = {
    'flavors': None,
    'active_flavors': [],
    'paused_flavors': [],
    'most_used_flavors': None,
    'volumes': {
        '<10Gb': 0,
        '<50Gb': 0,
        '<100Gb': 0,
        '<500Gb': 0,
        '>500Gb': 0
    },
    'most_used_volumes': 0,
    'unattached': None,
    'images': {
        '<10Gb': 0,
        '<50Gb': 0,
        '<100Gb': 0,
        '<500Gb': 0,
        '>500Gb': 0
    },
    'most_used_images': 0,
    'unused': 0,
    'networks': 0,
    'routers': 0,
    'subnets': 0,
    'unassociated_ips': 0,
    'unattached_ips': 0
}


class ResourceSearch(object):

    resources = None
    access_data = None

    def list_servers(self, list_servers):
        res = []
        for s in list_servers:
            try:
                reason = s.fault['message'] + 'Code %d' % s.fault['code']
            except AttributeError:
                # Need this because non-erred servers haven't such attribute
                reason = ''
            res.append(
                {'id': s.id,
                 'name': s.name,
                 'status': s.status,
                 'reason': reason
                 })
        return res

    def list_images(self, list_images):
        res = []
        for i in list_images:
            res.append(
                {'id': i.id,
                 'name': i.name,
                 'status': i.status,
                 'updated_at': i.updated_at
                 })
        return res

    def list_volumes(self, list_volumes):
        res = []
        for v in list_volumes:
            res.append(
                {'id': v.id,
                 'name': v.display_name,
                 'bootable': v.bootable,
                 'status': v.status
                 })
        return res

    def list_flavors(self, list_flavors):
        res = {}
        for f in list_flavors:
            res.update(
                {f.id: 'Flavour {}: RAM {} disc {}'.format(f.name, f.ram, f.disk)})
        return res

    def generate_json(self):
        res = json.dumps(self.resources, sort_keys=True,
                          indent=4, separators=(',', ': '))
        return res

    def search_resources(self):
        raise NotImplementedError

    def fill_the_template(self):
        raise NotImplementedError

    def init_clients(self, access_data):
        LOG.debug("Trying to obtain authenticated OS clients")
        self.key_client = keystone_v2.Client(
            username=access_data['os_username'],
            auth_url=self.config.get('basic', 'auth_protocol') + '://' + access_data['auth_endpoint_ip'] + ':5000/v2.0/',
            password=access_data['os_password'],
            tenant_name=access_data['os_tenant_name'],
            insecure=True)

        self.novaclient = nova.Client(
            '2', username=access_data['os_username'],
            auth_url=self.config.get('basic', 'auth_protocol') + '://' + access_data['auth_endpoint_ip'] + ':5000/v2.0/',
            api_key=access_data['os_password'],
            project_id=access_data['os_tenant_name'],
            insecure=True)

        self.cinderclient = cinder.Client(
            '1', username=access_data['os_username'],
            auth_url=self.config.get('basic', 'auth_protocol') + '://' + access_data['auth_endpoint_ip'] + ':5000/v2.0/',
            api_key=access_data['os_password'],
            project_id=access_data['os_tenant_name'],
            insecure=True)
        image_api_url = self.key_client.service_catalog.url_for(
            service_type="image")
        self.glanceclient = glance.Client(
            '1',
            endpoint=image_api_url,
            token=self.key_client.auth_token,
            insecure=True)
        network_api_url = self.key_client.service_catalog.url_for(
            service_type="network")
        self.neutronclient = neutron.Client(
            '2.0', token=self.key_client.auth_token,
            endpoint_url=network_api_url,
            auth_url=self.config.get('basic', 'auth_protocol') + '://' + access_data['auth_endpoint_ip'] + ':5000/v2.0/',
            insecure=True)


class ErrorResourceSearch(ResourceSearch):

    def __init__(self, access_data, *args, **kwargs):
        self.config = kwargs.get('config')
        self.resources = {
            'servers': [],
            'volumes': [],
            'images': [],
            'ports': []}

        self.init_clients(access_data)

    def search_error_servers(self):
        LOG.debug('Collecting error servers data')
        # Check only for Exception because of difference between clients outputs
        try:
            serv = self.novaclient.servers.list()
        except Exception:
            LOG.error('Failed connection to nova, report will be incomplete')
            return
        res = self.list_servers(serv)
        for s in res:
            if s['status'] == 'ERROR':
                self.resources['servers'].append(s)

    def search_error_volumes(self):
        LOG.debug('Collecting error volumes data')
        try:
            vol = self.cinderclient.volumes.list()
        except Exception:
            LOG.error('Failed connect to the cinder, report will be incomplete')
            return
        res = self.list_volumes(vol)
        for v in res:
            if v['status'] == 'error':
                self.resources['volumes'].append(v)

    def search_error_images(self):
        LOG.debug('Collecting error images data')
        try:
            images = self.glanceclient.images.list()
        except Exception:
            LOG.error('Failed obtain data from glance, report will be incomplete')
            return
        res = self.list_images(images)
        for i in res:
            if i['status'] == 'killed':
                self.resources['images'].append(i)

    def search_down_ports(self):
        LOG.debug('Collecting down ports data')
        try:
            res = self.neutronclient.list_ports()
        except Exception:
            LOG.error('Failed connect to neutron, report will be incomplete')
            return
        for p in res['ports']:
            if p['status'] == 'DOWN':
                self.resources['ports'].append(
                    {'id': p['id'],
                     'name': p['name'],
                     'status': p['status'],
                     'fixed_ips': [ip['ip_address'] for ip in p['fixed_ips']]
                    })

    def search_resources(self):
        self.search_error_servers()
        self.search_error_volumes()
        self.search_error_images()
        self.search_down_ports()
        return self.fill_the_template()

    def fill_the_template(self):
        path = os.path.join(os.path.dirname(__file__), 'erred_template.txt')
        temp = open(path, 'r')
        template = temp.read()
        temp.close()
        servers = ''
        for s in self.resources['servers']:
            servers +='<tr><td>ID {id}:</td><td align="right">Name {name} Status {status} Reason {reason}</td><tr>\n'.format(**s)
        images = ''
        for i in self.resources['images']:
            images +='<tr><td>ID {id}:</td><td align="right">Name {name} Status {status} Updated at {updated_at}</td>\n'.format(**i)
        volumes = ''
        for v in self.resources['volumes']:
            volumes +='<tr><td>ID {id}:</td><td align="right">Name {name} Status {status} Is bootable {bootable}</td>\n'.format(**v)
        ports = ''
        for p in self.resources['ports']:
            ports +='<tr><td>ID {id}:</td><td align="right">Name {name} Status {status} Fixed IPs {fixed_ips}</td>\n'.format(**p)
        return template.format(servers=servers,
                               images=images,
                               ports=ports,
                               volumes=volumes)


class GeneralResourceSearch(ResourceSearch):

    def __init__(self, access_data, *args, **kwargs):
        self.config = kwargs.get('config')
        self.resources = RESOURCES_TEMPLATE
        self.init_clients(access_data)

    def _count_vms(self, flavor_id, vms):
        counter = 0
        for v in vms:
            if v.flavor['id'] == flavor_id:
                counter += 1
        return counter

    def _count_usage(self, usage):
        res = {}
        for f in usage:
            if sum(usage.itervalues()) != 0:
                if usage[f] * 1.0 / sum(usage.itervalues()) > 0.3:
                    used = usage[f] * 100 / sum(usage.itervalues())
                    res[f] = '%d%%' % used

        return res

    def get_flavor_data(self):
        LOG.debug('Collecting flavor data')
        try:
            flavors = self.novaclient.flavors.list()
        except Exception:
            LOG.error('Failed connection to nova, report will be incomplete')
            return
        vms = self.novaclient.servers.list()
        res = self.list_flavors(flavors)
        self.resources['flavors'] = res
        active_vms = [v for v in vms if v.status == 'ACTIVE']
        paused_vms = [v for v in vms if v.status == 'PAUSED']
        self.resources['active_flavors'] = {f.name: self._count_vms(f.id, active_vms) 
                                                    for f in flavors 
                                                    if self._count_vms(f.id, active_vms) != 0}
        self.resources['paused_flavors'] = {f.name: self._count_vms(f.id, paused_vms) 
                                                    for f in flavors
                                                    if self._count_vms(f.id, paused_vms) != 0}

        all_keys = [k for k in self.resources['active_flavors'].keys()
                    + self.resources['paused_flavors'].keys()]
        total_usage = {
            k: self.resources['active_flavors'].get(k) or 0
                + self.resources['paused_flavors'].get(k) or 0
                for k in all_keys}
        most_used = self._count_usage(total_usage)
        self.resources['most_used_flavors'] = most_used
        LOG.debug('Flavor usage statistic successfully collected')

    def get_volume_data(self):
        LOG.debug('Collecting volume usage data')
        try:
            volumes = self.cinderclient.volumes.list()
        except Exception:
            LOG.error('Failed connect to the cinder, report will be incomplete')
            return
        for v in volumes:
            if v.status == 'in-use':
                if v.size < 10:
                    self.resources['volumes']['<10Gb'] += 1
                elif v.size < 50:
                    self.resources['volumes']['<50Gb'] += 1
                elif v.size < 100:
                    self.resources['volumes']['<100Gb'] += 1
                elif v.size < 500:
                    self.resources['volumes']['<500Gb'] += 1
                else:
                    self.resources['volumes']['>500Gb'] += 1

        most_used = self._count_usage(self.resources['volumes'])
        self.resources['most_used_volumes'] = most_used
        unused = sum([v.size for v in volumes if v.status != 'in-use'])
        unattached = unused * 100 / sum([v.size for v in volumes])
        self.resources['unattached'] = '%d%%' % unattached
        LOG.debug('Volume usage statistic successfully collected')

    def get_image_data(self):
        LOG.debug('Collecting image usage data')
        try:
            all_images = self.glanceclient.images.list()
        except Exception:
            LOG.error('Failed obtain data from glance, report will be incomplete')
            return
        vms = self.novaclient.servers.list()
        used_size_id = [v.image['id'] for v in vms]
        used_size = [i for i in all_images if i.id in used_size_id]
        for i in used_size:
            if i.size < 10*1000000000:
                self.resources['images']['<10Gb'] += 1
            elif i.size < 50*1000000000:
                self.resources['images']['<50Gb'] += 1
            elif i.size < 100*1000000000:
                self.resources['images']['<100Gb'] += 1
            elif i.size < 500*1000000000:
                self.resources['images']['<500Gb'] += 1
            else:
                self.resources['images']['>500Gb'] += 1
        most_used = self._count_usage(self.resources['images'])
        self.resources['most_used_images'] = most_used
        # Need it because glance returns generator
        all_images = self.glanceclient.images.list()
        unused = sum(self.resources['images'].itervalues()) * 100 / sum([i.size for i in all_images])
        self.resources['unused'] = '%d%%' % unused
        LOG.debug('Image usage statistic successfully collected')

    def get_network_data(self):
        LOG.debug('Collecting network resources usage data')
        try:
            networks = self.neutronclient.list_networks()['networks']
        except Exception:
            LOG.error('Failed connect to neutron, report will be incomplete')
            return
        self.resources['networks'] = len(networks)
        routers = self.neutronclient.list_routers()['routers']
        self.resources['routers'] = len(routers)
        all_agents = self.neutronclient.list_agents()['agents']
        dhcp_agents = [a for a in all_agents if a['agent_type'] == 'DHCP agent']
        subnets = sum(a['configurations']['subnets'] for a in dhcp_agents)
        self.resources['subnets'] = subnets
        floating_ips = self.neutronclient.list_floatingips()['floatingips']
        unattached = [ip for ip in floating_ips if not ip['tenant_id']]
        unassociated = [ip for ip in floating_ips if not ip['port_id'] and not ip in unattached]
        self.resources['unassociated_ips'] = len(unassociated)
        self.resources['unattached_ips'] = len(unattached)

    def search_resources(self):
        self.get_flavor_data()
        self.get_volume_data()
        self.get_image_data()
        self.get_network_data()
        html = self.fill_the_template()
        return html

    def fill_the_template(self):
        path = os.path.join(os.path.dirname(__file__), 'statistic_template.txt')
        temp = open(path, 'r')
        template = temp.read()
        temp.close()
        return template.format(**self.resources)
