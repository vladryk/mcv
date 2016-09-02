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
from jinja2 import Template

from flask_table import Table, Col

from mcv_consoler.common import clients as Clients

LOG = logging.getLogger(__name__)

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

RESOURCE_MAP = {
    'flavors': 'Flavors configured',
    'active_flavors': 'Active flavors',
    'paused_flavors': 'Paused flavors',
    'most_used_flavors': 'Most used flavors',
    'volumes': 'Volumes',
    'most_used_volumes': 'Most used volumes',
    'unattached': 'Unattached volumes',
    'images': 'Images',
    'most_used_images': 'Most used images',
    'unused': 'Unused images',
    'networks': 'Networks amount',
    'routers': 'Routers amount',
    'subnets': 'Subnets amount',
    'unassociated_ips': 'Unassociated floating IPs',
    'unattached_ips': 'Unattached floating IPs'

}

class ErredTable(Table):
    type = Col('TYPE')
    name = Col('NAME')
    id = Col('ID')
    status = Col('STATUS')
    other = Col('OTHER')


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
                 'other': reason,
                 'type': 'server',
                 })
        return res

    def list_images(self, list_images):
        res = []
        for i in list_images:
            res.append(
                {'id': i.id,
                 'name': i.name,
                 'status': i.status,
                 'other': 'Updated at: ' + str(i.updated_at),
                 'type': 'image'
                 })
        return res

    def list_volumes(self, list_volumes):
        res = []
        for v in list_volumes:
            res.append(
                {'id': v.id,
                 'name': v.name,
                 'other': 'Is bootable:' + str(v.bootable),
                 'status': v.status,
                 'type': 'volume'
                 })
        return res

    def list_flavors(self, list_flavors):
        res = {}
        for f in list_flavors:
            res.update(
                {f.id: 'Flavour {}: RAM {} disc {}'.format(f.name,
                                                           f.ram,
                                                           f.disk)})
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
        self.novaclient = Clients.get_nova_client(access_data)
        self.cinderclient = Clients.get_cinder_client(access_data)
        self.glanceclient = Clients.get_glance_client(access_data)
        self.neutronclient = Clients.get_neutron_client(access_data)
        LOG.debug("Finish obtaining OS clients.")


class ErrorResourceSearch(ResourceSearch):

    def __init__(self, access_data, *args, **kwargs):
        self.config = kwargs.get('config')
        self.resources = []
        self.init_clients(access_data)

    def search_error_servers(self):
        LOG.debug('Collecting error servers data')
        # Check only for Exception because of difference between
        # clients outputs

        try:
            serv = self.novaclient.servers.list()
        except Exception:
            LOG.error('Failed connection to nova, report will be incomplete')
            return

        res = self.list_servers(serv)
        for s in res:
            if s['status'] == 'ERROR':
                self.resources.append(s)

    def search_error_volumes(self):
        LOG.debug('Collecting error volumes data')

        try:
            vol = self.cinderclient.volumes.list()
        except Exception:
            LOG.error('Failed connect to the cinder, '
                      'report will be incomplete')
            return

        res = self.list_volumes(vol)
        for v in res:
            if v['status'] == 'error':
                self.resources.append(v)

    def search_error_images(self):
        LOG.debug('Collecting error images data')

        try:
            images = self.glanceclient.images.list()
        except Exception:
            LOG.error('Failed obtain data from glance, '
                      'report will be incomplete')
            return

        res = self.list_images(images)
        for i in res:
            if i['status'] == 'killed':
                self.resources.append(i)

    def search_down_ports(self):
        LOG.debug('Collecting down ports data')
        try:
            res = self.neutronclient.list_ports()
        except Exception:
            LOG.error('Failed connect to neutron, report will be incomplete')
            return
        for p in res['ports']:
            if p['status'] == 'DOWN':
                adresses = [ip['ip_address'] for ip in p['fixed_ips']]
                res = ''
                for adr in adresses:
                    res += str(adr) + ',\n'
                self.resources.append(
                    {'id': p['id'],
                     'name': p['name'],
                     'status': p['status'],
                     'other': 'Fixed IPs: ' + res,
                     'type': 'port'
                     })

    def search_resources(self):
        self.search_error_servers()
        self.search_error_volumes()
        self.search_error_images()
        self.search_down_ports()
        return self.fill_the_template()

    def fill_the_template(self):
        path = os.path.join(os.path.dirname(__file__), 'erred_template.html')
        temp = open(path, 'r')
        erred_template = temp.read()
        temp.close()

        table = ErredTable(self.resources)
        table_html = table.__html__()
        template = Template(erred_template)
        res = template.render(table=table_html)

        return res


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
        total = 0
        for d in usage:
            for k, v in d.iteritems():
                total += v
        if total != 0:
            for d in usage:
                for k, v in d.iteritems():
                    if v * 1.0 / total > 0.3:
                        used = v * 100 / total
                        res[k] = '%d%%' % used

        return res

    def repr_dict(self, rdict, s_comment='', m_comment='', e_comment='', direct_order=True):
        res = ''
        for k, v in rdict.iteritems():
            if direct_order:
                res += '%s %s %s %s %s<br>' % \
                       (s_comment, k, m_comment, str(v), e_comment)
            else:
                res += '%s %s %s %s %s<br>' % \
                       (s_comment, str(v), m_comment, k, e_comment)
        return res

    def repr_list_dict(self, rlist, s_comment='', m_comment='', e_comment=''):
        res = ''
        for d in rlist:
            for k, v in d.iteritems():
                res += '%s %s %s %s %s<br>' % \
                       (s_comment, str(v), m_comment, k, e_comment)
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
        self.resources['flavors'] = self.repr_dict(res,s_comment='ID')
        active_vms = [v for v in vms if v.status == 'ACTIVE']
        paused_vms = [v for v in vms if v.status == 'PAUSED']
        active_flavors = {f.name: self._count_vms(f.id, active_vms)
                          for f in flavors
                          if self._count_vms(f.id, active_vms)}
        self.resources['active_flavors'] = self.repr_dict(
            active_flavors, s_comment='Flavor', m_comment='Used by', e_comment='VMs')
        paused_flavors = {f.name: self._count_vms(f.id,
                                                                    paused_vms)
                                            for f in flavors
                                            if self._count_vms(f.id,
                                                               paused_vms)}
        self.resources['paused_flavors'] = self.repr_dict(
            active_flavors, s_comment='Flavor', m_comment='Used by', e_comment='VMs')
        all_keys = [k for k in active_flavors.keys() +
                    paused_flavors.keys()]
        total_usage = []
        for k in all_keys:
            total_usage.append({
                k:active_flavors.get(k) or 0 + paused_flavors.get(k) or 0 })

        most_used = self._count_usage(total_usage)

        self.resources['most_used_flavors'] = self.repr_dict(
            most_used, s_comment='Flavor', m_comment='used by', e_comment='VMs')
        LOG.debug('Flavor usage statistic successfully collected')

    def get_volume_data(self):
        LOG.debug('Collecting volume usage data')
        try:
            volumes = self.cinderclient.volumes.list()
        except Exception:
            LOG.error('Failed connect to the cinder, '
                      'report will be incomplete')
            return
        res_volumes = [
            {'10Gb': 0},
            {'50Gb': 0},
            {'100Gb': 0},
            {'500Gb': 0},
            {'500Gb': 0},
         ]
        for v in volumes:
            if v.status == 'in-use':
                if v.size < 10:
                    res_volumes[0]['10Gb'] += 1
                elif v.size < 50:
                    res_volumes[1]['50Gb'] += 1
                elif v.size < 100:
                    res_volumes[2]['100Gb'] += 1
                elif v.size < 500:
                    res_volumes[3]['500Gb'] += 1
                else:
                    res_volumes[4]['500Gb'] += 1
        self.resources['volumes'] = self.repr_list_dict(
            res_volumes[:-1], m_comment=' volumes less than', e_comment='size')
        self.resources['volumes'] += ' %s volumes is bigger than 500Gb size' % \
                                     res_volumes[4]['500Gb']

        most_used = self._count_usage(res_volumes)
        self.resources['most_used_volumes'] = self.repr_dict(
            most_used, m_comment='of volumes has size, less than', direct_order=False)
        unused = sum([v.size for v in volumes if v.status != 'in-use'])
        full_size = sum([v.size for v in volumes])
        if full_size:
            unattached = unused * 100 / full_size
        else:
            unattached = 100
        self.resources['unattached'] = '%d%%' % unattached
        LOG.debug('Volume usage statistic successfully collected')

    def get_image_data(self):
        LOG.debug('Collecting image usage data')

        try:
            all_images = self.glanceclient.images.list()
        except Exception:
            LOG.error('Failed obtain data from glance, '
                      'report will be incomplete')
            return

        vms = self.novaclient.servers.list()
        used_size_id = [v.image['id'] for v in vms if v.image]
        used_size = [i for i in all_images if i.id in used_size_id]
        res_images = [
            {'10Gb': 0},
            {'50Gb': 0},
            {'100Gb': 0},
            {'500Gb': 0},
            {'500Gb': 0},
         ]

        for i in used_size:
            if i.size < 10 * 1000000000:
                res_images[0]['10Gb'] += 1
            elif i.size < 50 * 1000000000:
                res_images[1]['50Gb'] += 1
            elif i.size < 100 * 1000000000:
                res_images[2]['100Gb'] += 1
            elif i.size < 500 * 1000000000:
                res_images[3]['500Gb'] += 1
            else:
                res_images[4]['500Gb'] += 1
        self.resources['images'] = self.repr_list_dict(
            res_images[:-1], m_comment=' images less than', e_comment='size')
        self.resources['images'] += ' %s images is bigger than 500Gb size' % \
                                     res_images[4]['500Gb']

        most_used = self._count_usage(res_images)

        self.resources['most_used_images'] = self.repr_dict(
            most_used, m_comment='of images has size, less than', direct_order=False)
        # Need it because glance returns generator
        all_images = self.glanceclient.images.list()
        full_size = sum([i.size for i in all_images if i.size])
        if full_size:
            unused = sum([i.size for i in used_size]
                         ) * 100 / full_size
        else:
            unused = 100
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
        dhcp_agents = [a for a in all_agents
                       if a['agent_type'] == 'DHCP agent']

        subnets = sum(a['configurations']['subnets'] for a in dhcp_agents)
        self.resources['subnets'] = subnets
        floating_ips = self.neutronclient.list_floatingips()['floatingips']
        unattached = [ip for ip in floating_ips if not ip['tenant_id']]
        unassociated = [ip for ip in floating_ips if not ip['port_id'] and
                        ip not in unattached]
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
        path = os.path.join(os.path.dirname(__file__),
                            'statistic_template.html')
        temp = open(path, 'r')
        general_temp = temp.read()
        temp.close()
        template = Template(general_temp)
        resource_dict = dict((RESOURCE_MAP[k], v) for k, v in self.resources.iteritems())
        res = template.render(result=resource_dict)

        return res
