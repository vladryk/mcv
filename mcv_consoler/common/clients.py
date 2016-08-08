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

from mcv_consoler.common import config as mcv_config


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


class _FuelClientLookup(object):
    name = None

    def __init__(self, target=None):
        self.target = target

    def __get__(self, instance, owner):
        self._detect_name(owner)

        handler = instance.get_resource_handler(self.target)
        setattr(instance, self.name, handler)

        return handler

    def _detect_name(self, owner):
        if self.name is not None:
            return

        for name, value in vars(owner).items():
            if value is not self:
                continue
            break
        else:
            raise TypeError(
                'Unable to detect descriptor name (class={!r} '
                'descriptor={!r})'.format(owner, self))

        self.name = name
        if self.target is None:
            self.target = self.name


class FuelClientProxy(object):
    cluster_settings = _FuelClientLookup('cluster-settings')
    deployment_history = _FuelClientLookup()
    deployment_info = _FuelClientLookup('deployment-info')
    environment = _FuelClientLookup()
    fuel_version = _FuelClientLookup('fuel-version')
    graph = _FuelClientLookup()
    network_configuration = _FuelClientLookup('network-configuration')
    network_group = _FuelClientLookup('network-group')
    node = _FuelClientLookup()
    openstack_config = _FuelClientLookup('openstack-config')
    plugins = _FuelClientLookup()
    release = _FuelClientLookup()
    task = _FuelClientLookup()
    vip = _FuelClientLookup()

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

    def get_resource_handler(self, name):
        return fuelclient.get_client(name)

    @classmethod
    def release_instance(cls):
        cls._instance_ref = None


get_fuel_client = FuelClientProxy
