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

import cinderclient.client as cinder
import glanceclient as glance
from heatclient import client as heat
from keystoneclient.v2_0 import client as keystone_v2
from neutronclient.neutron import client as neutron
import novaclient.client as nova
import saharaclient.client as sahara

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
    return cinder.Client('1', **client_data)


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
    client_data['sahara_url'] = keystone_client.service_catalog.url_for(
        service_type="data-processing")
    client_data['input_auth_token'] = keystone_client.auth_token
    client = sahara.Client(
        '1.0',
        service_type='data-processing',
        **client_data)
    return client
