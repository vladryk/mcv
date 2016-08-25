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

import functools
import os
import urlparse
import weakref

import cinderclient.client as cinder
import fuelclient
import fuelclient.client
import fuelclient.fuelclient_settings
import glanceclient as glance
from heatclient import client as heat
from keystoneclient.v2_0 import client as keystone_v2
from neutronclient.neutron import client as neutron
import novaclient.client as nova
import saharaclient.client as sahara

from mcv_consoler import exceptions
from mcv_consoler.common import config as mcv_config
from mcv_consoler import utils


class OSClientsProxy(utils.LazyAttributeMixin):
    keystone = utils.LazyAttribute()
    nova = utils.LazyAttribute()
    cinder = utils.LazyAttribute()
    glance = utils.LazyAttribute()
    neutron = utils.LazyAttribute()
    heat = utils.LazyAttribute()
    sahara = utils.LazyAttribute()
    fuel = utils.LazyAttribute()

    def __init__(self, access_data):
        self.access_data = access_data

    def lazy_attribute_handler(self, target):
        try:
            handler = {
                'keystone': get_keystone_client,
                'nova': get_nova_client,
                'cinder': get_cinder_client,
                'glance': get_glance_client,
                'neutron': get_neutron_client,
                'heat': get_heat_client,
                'sahara': get_sahara_client,
                'fuel': FuelClientProxy}[target]
        except KeyError:
            raise exceptions.ProgramError(
                'Invalid lazy attribute lookup on {!r} - missing handler '
                '({!r})'.format(self, target))
        return handler(self.access_data)


keystone_keys = ('username',
                 'password',
                 'tenant_name',
                 'auth_url',
                 'region_name',
                 'insecure',
                 'debug',)

nova_keys = ('username',
             'api_key',
             'project_id',
             'auth_url',
             'region_name',
             'insecure',)

cinder_keys = ('username',
               'api_key',
               'project_id',
               'auth_url',
               'region_name',
               'insecure',)

glance_keys = ('insecure',)

neutron_keys = ('insecure',
                'auth_url',)

heat_keys = ('insecure',)

sahara_keys = ('api_key',
               'project_id',
               'insecure',
               'username',
               'auth_url')


def _filter_keys(data_dict, keys):
    """Returns items with keys from the preset tuple."""

    results = {}
    for key in keys:
        if key in data_dict:
            results[key] = data_dict[key]
    return results


def get_keystone_client(access_data):
    # @TODO(albartash): implement Keystone v3
    client_data = _filter_keys(access_data, keystone_keys)
    return keystone_v2.Client(**client_data)


def get_nova_client(access_data):
    client_data = _filter_keys(access_data, nova_keys)
    client_data['timeout'] = 10
    return nova.Client('2', **client_data)


def get_cinder_client(access_data):
    client_data = _filter_keys(access_data, cinder_keys)
    return cinder.Client('2', **client_data)


def get_glance_client(access_data):
    keystone_client = get_keystone_client(access_data)
    client_data = _filter_keys(access_data, glance_keys)
    client_data['endpoint'] = keystone_client.service_catalog.url_for(
        service_type="image")
    client_data['token'] = keystone_client.auth_token
    return glance.Client('1', **client_data)


def get_neutron_client(access_data):
    keystone_client = get_keystone_client(access_data)
    client_data = _filter_keys(access_data, neutron_keys)
    client_data['endpoint_url'] = keystone_client.service_catalog.url_for(
        service_type="network")
    client_data['token'] = keystone_client.auth_token
    return neutron.Client('2.0', **client_data)


def get_heat_client(access_data):
    keystone_client = get_keystone_client(access_data)
    client_data = _filter_keys(access_data, heat_keys)
    client_data['endpoint'] = keystone_client.service_catalog.url_for(
        service_type='orchestration')
    client_data['token'] = keystone_client.auth_token

    return heat.Client('1', **client_data)


def get_sahara_client(access_data):
    keystone_client = get_keystone_client(access_data)
    client_data = _filter_keys(access_data, sahara_keys)
    # Better use service_list and name, but it requires admin user
    service_type = 'data_processing'
    try:
        client_data['sahara_url'] = keystone_client.service_catalog.url_for(
                service_type=service_type)
    except Exception:
        service_type = 'data-processing'
        client_data['sahara_url'] = keystone_client.service_catalog.url_for(
                service_type=service_type)

    client_data['input_auth_token'] = keystone_client.auth_token
    client = sahara.Client(
        '1.0',
        service_type=service_type,
        **client_data)
    return client


class FuelClientProxy(utils.LazyAttributeMixin):
    cluster_settings = utils.LazyAttribute('cluster-settings')
    deployment_history = utils.LazyAttribute()
    deployment_info = utils.LazyAttribute('deployment-info')
    environment = utils.LazyAttribute()
    fuel_version = utils.LazyAttribute('fuel-version')
    graph = utils.LazyAttribute()
    network_configuration = utils.LazyAttribute('network-configuration')
    network_group = utils.LazyAttribute('network-group')
    node = utils.LazyAttribute()
    openstack_config = utils.LazyAttribute('openstack-config')
    plugins = utils.LazyAttribute()
    release = utils.LazyAttribute()
    task = utils.LazyAttribute()
    vip = utils.LazyAttribute()

    _instance_ref = None

    def __init__(self, access_data):
        # keep access_data argument to be similar with get_*_client call
        del access_data

        # fuelclient <= 9.0.0 define settings as singleton. As result - we
        # can't connect only one fuel instance at a time. On 9.0.1 it was
        # changed. So when it will be released we can remove this check/limit
        # from our code too.
        if self._instance_ref is not None and self._instance_ref():
            raise RuntimeError(
                'Try to redefine fuelclient instance. You must don\'t do it, '
                'because of singletone nature of fuelclient settings.')

        type(self)._instance_ref = weakref.ref(self)

        env_var = mcv_config.FUELCLIENT_SETTINGS_ENV_VAR
        os.environ[env_var] = mcv_config.FUELCLIENT_CONFIG

        # force settings reread
        setattr(fuelclient.fuelclient_settings, '_SETTINGS', None)

        # TODO(dbogun): remove when fuelclient become normal(not singleton)
        # FIX address stored in current instance of APIClient
        settings = fuelclient.fuelclient_settings.get_settings()
        url_base = "http://{server}:{port}".format(
            server=settings.SERVER_ADDRESS, port=settings.SERVER_PORT)
        url_base = functools.partial(urlparse.urljoin, url_base)
        for attr, value in (
                ('root', url_base),
                ('keystone_base', url_base('/keystone/v2.0')),
                ('api_root', url_base('/api/v1/')),
                ('ostf_root', url_base('/ostf/'))):
            setattr(fuelclient.client.APIClient, attr, value)

        # force authentication
        for attr in '_keystone_client', '_auth_required', '_session':
            setattr(fuelclient.client.APIClient, attr, None)

    @staticmethod
    def filter_nodes_by_status(node_set, status='ready'):
        for node in node_set:
            if status != node['status']:
                continue
            yield node

    @staticmethod
    def filter_nodes_by_role(node_set, role):
        for node in node_set:
            if role not in node['roles']:
                continue
            yield node

    @staticmethod
    def get_node_network(node, network):
        for net_info in node['network_data']:
            if net_info['name'] != network:
                continue
            break
        else:
            raise exceptions.FrameworkError(
                'There is no network "{}" on node "{}"'.format(
                    network, node['fqdn']))
        return net_info

    @classmethod
    def get_node_address(
            cls, node, network=mcv_config.FUEL_ADMIN_NETWORK_NAME):
        net_info = cls.get_node_network(node, network)
        try:
            addr = net_info['ip']
        except:
            raise exceptions.FrameworkError(
                'There is no IP address on node {} in network {}'.format(
                    node['fqdn'], network))
        return addr.rsplit('/', 1)[0]

    @classmethod
    def release_instance(cls):
        cls._instance_ref = None

    def lazy_attribute_handler(self, target):
        return fuelclient.get_client(target)


get_fuel_client = FuelClientProxy
