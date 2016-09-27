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

import logging

from oslo_config import cfg

from mcv_consoler.common import config

basic = cfg.OptGroup(name='basic',
                     title='MCV configuration')

basic_opts = [
    cfg.StrOpt('auth_protocol', default='https',
               help='Authentication protocol'),
    cfg.StrOpt('mos_version', default='8.0',
               help='MOS version'),
    cfg.StrOpt('instance_ip', required=True,
               help='MCV host'),
    cfg.StrOpt('log_config', default='/etc/mcv/logging.yaml',
               help='MCV log config path'),
    cfg.BoolOpt('hide_ssl_warnings', default=False,
                help='MCV ssl warnings'),
    cfg.StrOpt('scenario', default='/etc/mcv/scenario.yaml',
               help='MCV test groups scenario path')
]

fuel = cfg.OptGroup(name='fuel',
                    title='Fuel master node configuration')

fuel_opts = [
    cfg.StrOpt('username', required=True, secret=True,
               help='Fuel username'),
    cfg.StrOpt('password', required=True, secret=True,
               help='Fuel password'),
    cfg.StrOpt('nailgun_host', default='10.20.0.2',
               help='Fuel nailgun host'),
    cfg.IntOpt('cluster_id', default=1,
               help='Fuel cluster id'),
    cfg.StrOpt('ssh_cert', default='/root/.ssh/id_rsa',
               help='Fuel ssh certificate path'),
    cfg.StrOpt('ostf_username', required=True, secret=True,
               default='admin',
               help='User in FUEL\'s keystone for OSTF plugin needs'),
    cfg.StrOpt('ostf_password', default='admin', required=True,
               secret=True, help='Password of ostf user'),
    cfg.StrOpt('ostf_tenant', required=True, secret=True,
               default='admin', help='Tenant of ostf user'),
]

auth = cfg.OptGroup(name='auth',
                    title='MOS configuration')

auth_opts = [
    cfg.StrOpt('os_username', required=True, secret=True,
               help='MOS user name'),
    cfg.StrOpt('os_tenant_name', required=True, secret=True,
               help='MOS tenant name'),
    cfg.StrOpt('os_password', required=True, secret=True,
               help='MOS password'),
    cfg.StrOpt('region_name', default='RegionOne', secret=True,
               help='MOS region name'),
    cfg.StrOpt('auth_endpoint_ip', default='1.1.1.3',
               help='MOS auth endpoint ip'),
    cfg.StrOpt('auth_fqdn', default='public.fuel.local',
               help='MOS auth domain name'),
    cfg.StrOpt('controller_ip', default='1.1.1.4',
               help='MOS controller ip'),
    cfg.StrOpt('controller_uname', required=True, secret=True,
               help='MOS controller user name'),
    cfg.StrOpt('controller_pwd', required=True, secret=True,
               help='MOS controller password'),
    cfg.StrOpt('ssh_key', default='/home/mcv/id_rsa',
               help='Path to the SSH key to access cloud nodes')
]

networking = cfg.OptGroup(name='networking',
                          title='Cloud network names')

networking_opts = [
    cfg.StrOpt('network_name', default='admin_internal_net',
               help='Internal network name'),
    cfg.StrOpt('network_ext_name', default='admin_floating_net',
               help='Floating network name'),
]

rally = cfg.OptGroup(name='rally',
                     title='Rally configuration')

rally_opts = [
    cfg.StrOpt('runner', default='RallyOnDockerRunner',
               help='Rally plugin name'),
    cfg.IntOpt('concurrency', default=5,
               help='Rally concurrency'),
    cfg.IntOpt('vlan_amount', default=1,
               help='Rally vlan amount'),
    cfg.BoolOpt('gre_enabled', default=False,
                help='Rally gre'),
    cfg.IntOpt('max_failed_tests', default=10,
               help='Rally max failed tests count'),
    cfg.BoolOpt('existing_users', default=False,
                help='Rally use pre-configured user')
]

certification = cfg.OptGroup(name='certification',
                             title='Certification configuration')

certification_opts = [
    cfg.ListOpt('services', default=['authentication', 'neutron',
                                     'cinder', 'glance', 'nova', 'keystone'],
                help='List tested services'),
    cfg.IntOpt('controllers_amount', default=1,
               help='Controllers amount'),
    cfg.IntOpt('computes_amount', default=2,
               help='Computes amount'),
    cfg.IntOpt('storage_amount', default=1,
               help='Storage amount'),
    cfg.IntOpt('tenants_amount', default=1,
               help='Tenants amount'),
    cfg.IntOpt('users_amount', default=1,
               help='Users amount'),
    cfg.IntOpt('network_amount', default=1,
               help='Network amount'),
]

workload = cfg.OptGroup(name='workload',
                        title='Workload configuration')

workload_opts = [
    cfg.IntOpt('instance_count', default=2,
               help='Workload instance count'),
    cfg.IntOpt('concurrency', default=1,
               help='Workload concurrency'),
    cfg.IntOpt('file_size', default=10000,
               help='Workload file size'),
    cfg.IntOpt('workers_count', default=3,
               help='Workload workers count'),
    cfg.IntOpt('ram', default=8096,
               help='Workload ram'),
    cfg.IntOpt('disc', default=20,
               help='Workload disc size'),
    cfg.IntOpt('vcpu', default=4,
               help='Workload cpu count')
]

tempest = cfg.OptGroup(name='tempest',
                       title='Tempest configuration')

tempest_opts = [
    cfg.StrOpt('runner', default='TempestOnDockerRunner',
               help='Tempest plugin name'),
    cfg.IntOpt('max_failed_tests', default=100,
               help='Tempest max failed tests count')
]

ostf = cfg.OptGroup(name='ostf',
                    title='OSTF configuration')

ostf_opts = [
    cfg.StrOpt('runner', default='OSTFRunner',
               help='OSTF plugin name'),
    cfg.BoolOpt('reload_config', default=False,
                help='Reloading OSTF config file for each run'),
    cfg.IntOpt('max_failed_tests', default=10,
               help='OSTF max failed tests count')
]

resources = cfg.OptGroup(name='resources',
                         title='Resource configuration')

resources_opts = [
    cfg.StrOpt('runner', default='ResourceReportRunner',
               help='Resource plugin name'),
    cfg.IntOpt('max_failed_tests', default=1,
               help='Resource max failed tests count')
]

shaker = cfg.OptGroup(name='shaker',
                      title='Shaker configuration')

shaker_opts = [
    cfg.StrOpt('runner', default='ShakerOnDockerRunner',
               help='Shaker plugin name'),
    cfg.BoolOpt('cleanup', default=True,
                help='Shaker cleanup'),
    cfg.IntOpt('timeout', default=1200,
               help='Shaker timeout'),
    cfg.IntOpt('agents_timeout', default=60,
               help='Shaker agents timeout'),
    cfg.IntOpt('max_failed_tests', default=1,
               help='Shaker max failed tests count'),
    cfg.StrOpt('image_name', default='shaker-image',
               help='Shaker image name'),
    cfg.StrOpt('flavor_name', default='shaker-flavor',
               help='Shaker flavor name')

]

network_speed = cfg.OptGroup(name='network_speed',
                             title='Network speed configuration')

network_speed_opts = [
    cfg.FloatOpt('threshold', default=7.0,
                 help='Network threshold'),
    cfg.IntOpt('max_failed_tests', default=10,
               help='Network speed max failed tests count')

]

speed = cfg.OptGroup(name='speed',
                     title='Speed configuration')

speed_opts = [
    cfg.StrOpt('runner', default='SpeedTestRunner',
               help='Speed plugin name'),
    cfg.StrOpt('availability_zone', default='nova',
               help='Speed availability zone'),
    cfg.StrOpt('speed_image_path',
               default=config.FEDORA_IMAGE_PATH,
               help='Speed image path'),
    cfg.StrOpt('flavor_req', default='ram:1024,vcpus:1,disk:0',
               help='Speed flavour requirements'),
    cfg.StrOpt('image_size', default='1G',
               help='Speed image size'),
    cfg.StrOpt('volume_size', default='1G',
               help='Speed volume size'),
    cfg.FloatOpt('threshold', default=50.0,
                 help='Speed threshold'),
    cfg.IntOpt('max_failed_tests', default=10,
               help='Speed max failed tests count'),
    # compute_nodes_limit is optional, default value is None
    cfg.IntOpt('compute_nodes_limit',
               help='Speed compute nodes limit'),
    cfg.IntOpt('attempts', default=3,
               help='Speed attempts count'),
]

nwspeed = cfg.OptGroup(name='nwspeed',
                       title='NWSpeed configuration')

nwspeed_opts = [
    cfg.StrOpt('runner', default='NWSpeedTestRunner',
               help='NWSpeed plugin name'),
    cfg.FloatOpt('threshold', default=100.0,
                 help='NWSpeed threshold'),
    cfg.FloatOpt('range', default=10.0,
                 help='NWSpeed range'),
    cfg.IntOpt('test_port', min=5903, max=6100, default=6003,
               help='NWSpeed test port (by default we use VNC port range)'),
    cfg.IntOpt('data_size', default=100,
               help='NWSpeed data size'),
    cfg.IntOpt('nodes_limit',
               help='NWSpeed nodes limit'),
    cfg.IntOpt('controllers_limit',
               help='NWSpeed controllers limit'),
    cfg.IntOpt('attempts', default=3,
               help='NWSpeed attempts count'),
    cfg.ListOpt('roles',
                help='Comma-separated list of roles to be used to filter '
                     'nodes before starting speed test'),
]

selfcheck = cfg.OptGroup(name='selfcheck',
                         title='Self check configuration')

selfcheck_opts = [
    cfg.StrOpt('runner', default='SelfCheckRunner',
               help='Self check plugin name')
]

cleanup = cfg.OptGroup(name='cleanup',
                       title='Cleanup configuration')

cleanup_opts = [
    cfg.BoolOpt('show_trash', default=False,
                help='Cleanup trash configuration'),
    cfg.IntOpt('days', default=5,
               help='Cleanup days')
]

times = cfg.OptGroup(name='times',
                     title='Times configuration')

times_opts = [
    cfg.BoolOpt('update', default=True,
                help='Times update')
]

quotas = cfg.OptGroup(name='quotas',
                      title='Quotas configuration')

quotas_opts = [
    cfg.BoolOpt('neutron', default=False,
                help='Set unlimited quotas for Neutron'),
]

cfg_for_reg = [
    (basic, basic_opts),
    (fuel, fuel_opts),
    (auth, auth_opts),
    (networking, networking_opts),
    (rally, rally_opts),
    (certification, certification_opts),
    (workload, workload_opts),
    (tempest, tempest_opts),
    (ostf, ostf_opts),
    (resources, resources_opts),
    (shaker, shaker_opts),
    (network_speed, network_speed_opts),
    (speed, speed_opts),
    (nwspeed, nwspeed_opts),
    (selfcheck, selfcheck_opts),
    (cleanup, cleanup_opts),
    (times, times_opts),
    (quotas, quotas_opts),
]

LOG = logging.getLogger()
CONF = cfg.CONF


def init_config(config_file=None):
    try:
        for group, opts in cfg_for_reg:
            CONF.register_group(group)
            CONF.register_opts(opts, group)
        config_files = [config_file if config_file else
                        config.DEFAULT_CONFIG_FILE]
        CONF(args='', default_config_files=config_files)
        # try to take each value from CONF - if the
        # value in the configuration file is incorrect
        # will be thrown an error
        for group, opts in cfg_for_reg:
            for opt in opts:
                assert CONF[group.name][opt.name]
        return True
    except cfg.Error as e:
        LOG.error(e)
        return False
