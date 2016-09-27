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

import functools
from itertools import imap
import os
import six
import urlparse
import weakref

import cinderclient.client
import cinderclient.exceptions
import fuelclient
import fuelclient.cli.error
import fuelclient.client
import fuelclient.fuelclient_settings
import glanceclient
import glanceclient.exc
import heatclient.client
import heatclient.exc
from keystoneauth1 import identity
from keystoneauth1 import session
import keystoneclient
import neutronclient.common.exceptions
import neutronclient.neutron.client
import novaclient.client
import novaclient.exceptions
import saharaclient.client

from mcv_consoler.common import config as mcv_config
from mcv_consoler import exceptions
from mcv_consoler import utils


class _ClientProxyBase(utils.LazyAttributeMixin):
    def __init__(self, ctx, access_data):
        self.ctx = ctx
        self.access_data = access_data


class OSClientsProxy(_ClientProxyBase):
    keystone = utils.LazyAttribute()
    keystone_exc = keystoneclient.exceptions

    nova = utils.LazyAttribute()
    nova_exc = novaclient.exceptions

    cinder = utils.LazyAttribute()
    cinder_exc = cinderclient.exceptions

    glance = utils.LazyAttribute()
    glance_exc = glanceclient.exc

    neutron = utils.LazyAttribute()
    neutron_exc = neutronclient.common.exceptions

    heat = utils.LazyAttribute()
    heat_exc = heatclient.exc

    sahara = utils.LazyAttribute()
    # sahara_exc: looks like saharaclient have no it's own exceptions

    fuel = utils.LazyAttribute()
    fuel_exc = fuelclient.cli.error

    def lazy_attribute_handler(self, target):
        try:
            handler = {
                'keystone': get_keystone_client,
                'nova': get_nova_client,
                'cinder': get_cinder_client,
                'glance': get_glance_client,
                'neutron': get_neutron_client,
                'heat': get_heat_client,
                'sahara': get_sahara_client}[target]
        except KeyError:
            if target != 'fuel':
                raise exceptions.ProgramError(
                    'Invalid lazy attribute lookup on {!r} - missing handler '
                    '({!r})'.format(self, target))
            result = FuelClientProxy(self.ctx, self.access_data)
        else:
            result = handler(self.access_data)

        return result


def get_keystone_client(access_data):
    # @TODO(albartash): implement Keystone v3
    return keystoneclient.v2_0.Client(
        region_name=access_data['region_name'],
        session=KeystoneSession(access_data).session)


def get_nova_client(access_data):
    return novaclient.client.Client(
        '2',
        region_name=access_data['region_name'],
        session=KeystoneSession(access_data).session)


def get_cinder_client(access_data):
    return cinderclient.client.Client(
        '2',
        region_name=access_data['region_name'],
        session=KeystoneSession(access_data).session)


def get_glance_client(access_data):
    endpoint = KeystoneSession(access_data).session.get_endpoint(
        service_type='image', region_name=access_data['region_name'])
    return glanceclient.Client(
        '1',
        endpoint=endpoint,
        session=KeystoneSession(access_data).session)


def get_neutron_client(access_data):
    return neutronclient.neutron.client.Client(
        '2.0',
        region_name=access_data['region_name'],
        session=KeystoneSession(access_data).session)


def get_heat_client(access_data):
    endpoint = KeystoneSession(access_data).session.get_endpoint(
        service_type='orchestration', region_name=access_data['region_name'])
    return heatclient.client.Client(
        '1',
        endpoint,
        session=KeystoneSession(access_data).session)


def get_sahara_client(access_data):
    service_type = 'data-processing'
    try:
        KeystoneSession(access_data).session.get_endpoint(
            service_type=service_type, region_name=access_data['region_name'])
    except Exception:
        service_type = 'data_processing'
        KeystoneSession(access_data).session.get_endpoint(
            service_type=service_type, region_name=access_data['region_name'])

    client = saharaclient.client.Client(
        '1.0',
        service_type=service_type,
        session=KeystoneSession(access_data).session,
        region_name=access_data['region_name'])
    return client


@six.add_metaclass(utils.Singleton)
class KeystoneSession(object):

    def __init__(self, access_data):
        client_data = {
            'auth_url': access_data['auth_url'],
            'username': access_data['username'],
            'password': access_data['password'],
            'tenant_name': access_data['tenant_name']
        }
        identity_plugin = identity.Password(**client_data)
        verify = not access_data.get('insecure', True)
        self.session = session.Session(auth=identity_plugin, verify=verify)


class FuelClientProxy(_ClientProxyBase):
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

    exc = fuelclient.cli.error

    _instance_ref = None

    def __init__(self, ctx, access_data):
        super(FuelClientProxy, self).__init__(ctx, access_data)

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
        os.environ[env_var] = self.ctx.work_dir.resource(
            self.ctx.work_dir.RES_FUELCLIENT_SETTINGS)

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
        return [node for node in node_set if status == node['status']]

    @staticmethod
    def filter_nodes_by_role(node_set, *roles):
        res = list()
        for node in node_set:
            if any(imap(node['roles'].__contains__, roles)):
                res.append(node)
        return res

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
        except Exception:
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
