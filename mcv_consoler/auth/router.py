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

import itertools
import logging
import os
import re
import socket
import shutil
import subprocess
import tempfile
import time
import traceback

import paramiko
import yaml
from requests.exceptions import ConnectionError
from requests.exceptions import Timeout
import keystoneclient
from novaclient import exceptions as nexc
from oslo_config import cfg

import mcv_consoler.exceptions
from mcv_consoler.common import context
from mcv_consoler.common import clients
from mcv_consoler.common import ssh
from mcv_consoler.common import config as mcv_config
from mcv_consoler.common import resource
from mcv_consoler import utils
from mcv_consoler.utils import run_cmd

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


REMOTE_GRAB_FUEL_CREDENTIALS = """\
from __future__ import print_function

import os
import sys

import fuelclient.fuelclient_settings

devnull = open(os.devnull, 'wt')
stdout, sys.stdout = sys.stdout, devnull

try:
    settings = fuelclient.fuelclient_settings.get_settings()
finally:
    sys.stdout = stdout

print(settings.dump())
"""


class Router(object):
    """Defines base class for Routing."""

    _idx = itertools.count()
    SSH_DEST_FUELMASTER = next(_idx)
    del _idx

    def __init__(self, ctx, **kwargs):
        self.ctx = ctx
        self.hosts = EtcHosts()

        self.os_data = self.get_os_data()

    def get_os_data(self):
        # TODO(albartash): needs to be received from endpoint-list
        protocol = CONF.basic.auth_protocol

        endpoint_ip = CONF.auth.auth_endpoint_ip
        auth_url_tpl = '{hprot}://{ip}:{port}/v{version}'
        tenant_name = CONF.auth.os_tenant_name
        password = CONF.auth.os_password
        insecure = (protocol == "https")
        # NOTE(albartash): port 8443 is not ready to use somehow
        nailgun_port = 8000

        os_data = {'username': CONF.auth.os_username,
                   'password': password,
                   'tenant_name': tenant_name,
                   'auth_url': auth_url_tpl.format(hprot=protocol,
                                                   ip=endpoint_ip,
                                                   port=5000,
                                                   version="2.0"),
                   'ips': {
                       'controller': CONF.auth.controller_ip,
                       'endpoint': endpoint_ip,
                       'instance': CONF.basic.instance_ip},
                   'auth': {
                       'controller_uname': CONF.auth.controller_uname,
                       'controller_pwd': CONF.auth.controller_pwd},
                   'fuel': {
                       'username': CONF.fuel.username,
                       'password': CONF.fuel.password,
                       'nailgun': CONF.fuel.nailgun_host,
                       'nailgun_port': nailgun_port,
                       'cluster_id': CONF.fuel.cluster_id,
                       # TODO(albartash): fix in router.py (None to "")
                       'ca_cert': "",
                       'cert': CONF.fuel.ssh_cert,
                   },
                   'debug': mcv_config.DEBUG,
                   'insecure': insecure,
                   'mos_version': CONF.basic.mos_version,
                   'auth_fqdn': CONF.auth.auth_fqdn,
                   }

        return os_data

    def stop_all_docker_containers(self):
        LOG.debug('Stopping docker containers')
        cmd = 'docker ps -q | xargs -r docker stop'
        return run_cmd(cmd)

    def setup_connections(self):
        """Set up connections for routing requests."""
        raise NotImplementedError

    def cleanup(self):
        """Clean up routing rules if necessary."""
        raise NotImplementedError

    def _ssh_connect(self, dest, connect=False):
        if dest == self.SSH_DEST_FUELMASTER:
            auth = self.os_data['fuel']
            args = {
                'host': auth['nailgun'],
                'username': auth['username'],
                'password': auth['password']}
        else:
            raise ValueError(
                'Invalid value for argument "dest": {!r}'.format(dest))

        client = ssh.SSHClient(**args)

        if connect:
            if not client.connect():
                raise mcv_consoler.exceptions.AccessError(
                    'Can\'t access FUEL master node via SSH {}'.format(
                        client.identity))

        return client


class MRouter(Router):
    pass


class CRouter(Router):
    def make_sure_controller_name_could_be_resolved(self):
        LOG.debug('Trying to update /etc/hosts file')
        a_fqdn = self.os_data['auth_fqdn']
        public_ip = self.os_data['public_endpoint_ip']
        if not a_fqdn:
            LOG.debug('No FQDN specified. Nothing to update')
            return
        if not public_ip:
            LOG.debug("Public IP is empty or missing. Can't patch anything")
            return
        LOG.debug('Adding new record: %s \t%s' % (a_fqdn, public_ip))
        self.hosts.modify({a_fqdn: public_ip})

    def setup_connections(self):
        self.get_fuelclient_credentials()
        context.add(
            self.ctx, 'fuel', clients.FuelClientProxy(self.ctx, self.os_data))

        try:
            self.populate_cluster_nodes_info()
            self.get_os_ssh_key()
            self.setup_sshuttle_tunnel()
            self.get_openrc()
            self.populate_etc_hosts()
            self.make_sure_controller_name_could_be_resolved()
        finally:
            self.ctx.fuel.release_instance()

        LOG.debug('Connections have been set successfully.')
        # TODO(dbogun): remove return value
        return True

    def cleanup(self):
        LOG.debug('Removing files with credentials to cloud.')
        work_dir = self.ctx.work_dir_global
        for res in (work_dir.RES_OS_OPENRC, work_dir.RES_OS_SSH_KEY):
            try:
                path = work_dir.resource(res)
                os.remove(path)
            except mcv_consoler.exceptions.FileResourceNotFoundError:
                pass
            except OSError as e:
                LOG.debug('Cannot remove file {fp}. Reason: {reason}'.format(
                    fp=e.filename, reason=e.message))

        LOG.debug('Restoring /etc/hosts')
        self.hosts.restore()
        self.stop_all_docker_containers()

    def get_fuelclient_credentials(self):
        work_dir = self.ctx.work_dir_global
        try:
            work_dir.resource(work_dir.RES_FUELCLIENT_SETTINGS)
            LOG.debug('Use fuelclient settings provided by user.')
            return
        except mcv_consoler.exceptions.FileResourceNotFoundError:
            pass

        fuel = self._ssh_connect(self.SSH_DEST_FUELMASTER, connect=True)

        proc = fuel.exec_cmd(
            'python', stdin=REMOTE_GRAB_FUEL_CREDENTIALS, exc=True,
            hide_stdout=True)

        # overwrite fuelmaster host address, because we can receive address
        # from different interface
        settings = yaml.load(proc.stdout)
        settings['SERVER_ADDRESS'] = self.os_data['fuel']['nailgun']

        path = work_dir.resource(
            work_dir.RES_FUELCLIENT_SETTINGS, lookup=False)
        with open(path, 'wt') as fd:
            yaml.dump(settings, fd)

    def populate_cluster_nodes_info(self):
        cluster = CONF.fuel.cluster_id

        node_set = self.ctx.fuel.node.get_all(environment_id=cluster)
        node_set = self.ctx.fuel.filter_nodes_by_status(node_set)

        context.add(self.ctx, 'nodes', node_set)

        nodes_by_role = {}
        for node in node_set:
            for role in node['roles']:
                nodes_by_role.setdefault(role, []).append(node)
        if not nodes_by_role.get(mcv_config.FUEL_ROLE_CONTROLLER):
            raise mcv_consoler.exceptions.AccessError(
                'There is no any controller node')
        context.add(self.ctx, 'nodes_by_role', nodes_by_role)

    def get_os_ssh_key(self):
        work_dir = self.ctx.work_dir_global
        try:
            work_dir.resource(work_dir.RES_OS_SSH_KEY)
            LOG.debug('Use OS ssh key provide by user.')
            return
        except mcv_consoler.exceptions.FileResourceNotFoundError:
            pass

        fuel = self._ssh_connect(self.SSH_DEST_FUELMASTER, connect=True)
        proc = fuel.exec_cmd(
            "cat {}".format(self.os_data['fuel']['cert']),
            exc=True, hide_stdout=True)

        path = work_dir.resource(work_dir.RES_OS_SSH_KEY, lookup=False)
        ssh.save_private_key(path, proc.stdout)
        LOG.debug('Saving RSA key to file %s...', path)

    def setup_sshuttle_tunnel(self):
        LOG.debug(
            'Make SSH port forwarding on controller node on SSH port for '
            'sshuttle')
        node, forward = self._setup_port_forwarding_for_sshuttle()
        self.ctx.resources.add(resource.ClosableResource(forward), True)

        net_info = self.ctx.fuel.get_node_network(
            node, mcv_config.FUEL_PUBLIC_NETWORK_NAME)
        dest = [net_info['cidr']]
        LOG.debug('Setup sshuttle "tunnel"')
        sshuttle = self._setup_sshuttle(forward, dest)
        self.ctx.resources.add(
            resource.SubprocessResource(sshuttle), True)

    def _setup_port_forwarding_for_sshuttle(self):
        fuel_access = self.os_data['fuel']
        os_ssh_key = self.ctx.work_dir_global.resource(
            self.ctx.work_dir_global.RES_OS_SSH_KEY)

        for node in self.ctx.nodes_by_role[mcv_config.FUEL_ROLE_CONTROLLER]:
            addr = self.ctx.fuel.get_node_address(node)
            ssh_fuel_creds = ssh.Credentials(
                fuel_access['nailgun'], fuel_access['username'],
                password=fuel_access['password'])

            try:
                forward = ssh.LocalPortForwarder(
                    addr, mcv_config.OS_NODE_SSH_PORT,
                    via=ssh_fuel_creds)
            except mcv_consoler.exceptions.PortForwardingError as e:
                LOG.error(
                    'Unable to setup SSH port forwarding to {dest}:{port} via '
                    '{via}: {exc}'.format(
                        dest=addr, port=mcv_config.OS_NODE_SSH_PORT,
                        via=fuel_access['nailgun'], exc=e))
                continue

            LOG.debug(
                'Test SSH port forwarding to {dest}:{port} via {via}'.format(
                    dest=addr, port=mcv_config.OS_NODE_SSH_PORT,
                    via=ssh_fuel_creds.identity))

            try:
                client = ssh.SSHClient(
                    forward.local, mcv_config.OS_NODE_SSH_USER,
                    rsa_key=os_ssh_key, port=forward.port)
                if not client.connect():
                    raise mcv_consoler.exceptions.AccessError(
                        'Unable to make SSH connection via SSH forwarded port')
                try:
                    hostname = client.exec_cmd('hostname -f', exc=True)
                    if hostname.stdout.rstrip() != node['fqdn']:
                        raise mcv_consoler.exceptions.AccessError(
                            'Unexpected host fond. Expect hostname '
                            '{} got {}'.format(hostname.stdout, node['fqdn']))
                except mcv_consoler.exceptions.RemoteError as e:
                    raise mcv_consoler.exceptions.AccessError(
                        'Unusable controller host {}: {}'.format(addr, e))
                finally:
                    client.close()
            except mcv_consoler.exceptions.AccessError as e:
                LOG.error(e)
                forward.close()
                continue

            break
        else:
            raise mcv_consoler.exceptions.AccessError(
                'Unable to setup SSH port forwarding on any controller node.')

        return node, forward

    def _setup_sshuttle(self, forward, dest):
        os_ssh_key = self.ctx.work_dir_global.resource(
            self.ctx.work_dir_global.RES_OS_SSH_KEY)

        exclude = (self.os_data['fuel']['nailgun'], '127.0.0.1')
        cmd = ['sshuttle'] + ['--listen=0.0.0.0:0', '-H'] + [
            '--exclude={}'.format(x) for x in exclude] + [
            '-vv',
            '--dns',
            '--auto-nets',
            '--remote={}@{}:{}'.format(
                mcv_config.OS_NODE_SSH_USER,
                forward.local, forward.port),
            '--ssh-cmd={}'.format(
                'ssh -q -i {} '
                '-o UserKnownHostsFile=/dev/null '
                '-o StrictHostKeyChecking=no'.format(os_ssh_key))
        ] + dest

        shuttle_output = tempfile.TemporaryFile()

        LOG.debug('Run sshuttle: %r', cmd)
        try:
            proc = subprocess.Popen(
                cmd, stdout=shuttle_output, stderr=subprocess.STDOUT,
                close_fds=True)
        except OSError as e:
            raise mcv_consoler.exceptions.FrameworkError(
                'exec {!r}:'.format(cmd), e)

        LOG.debug('Wait while shuttle setup tunnel.')
        # We should "connect" some resource "behind" sshuttle tunnel to prove
        # that sshutle is up and running, instead of this timeout.
        now = time.time()
        end_time = now + mcv_config.SHUTTLE_SETUP_TIME
        while now < end_time:
            if proc.poll() is not None:
                shuttle_output.seek(0, os.SEEK_SET)
                raise mcv_consoler.exceptions.AccessError(
                    'Unable to setup shuttler tunnel.', shuttle_output.read())
            time.sleep(max(int(now + 1) - now, 0))
            now = time.time()

        return proc

    def get_openrc(self):
        work_dir = self.ctx.work_dir_global
        try:
            path = work_dir.resource(work_dir.RES_OS_OPENRC)
            LOG.debug('Use openrc provided by user')
            with open(path, 'rt') as fd:
                payload = fd.read()
            openrc = self._unpack_openrc(payload)
        except mcv_consoler.exceptions.FileResourceNotFoundError:
            node_set = self.ctx.nodes_by_role[mcv_config.FUEL_ROLE_CONTROLLER]
            for node in node_set:
                addr = self.ctx.fuel.get_node_address(node)
                LOG.debug(
                    'Trying to extract openrc from controller %s',
                    node['fqdn'])
                connect = ssh.SSHClient(
                    host=addr, username=mcv_config.OS_NODE_SSH_USER,
                    rsa_key=work_dir.resource(work_dir.RES_OS_SSH_KEY))
                connect.connect(exc=True)

                try:
                    payload = connect.exec_cmd('cat /root/openrc',
                                               exc=True,
                                               hide_stdout=True).stdout
                    openrc = self._unpack_openrc(payload)
                except mcv_consoler.exceptions.RemoteError as e:
                    LOG.debug(
                        'Unable to fetch operc from %s: %s', node['fqdn'], e)
                    continue
                finally:
                    connect.close()

                break
            else:
                raise mcv_consoler.exceptions.AccessError(
                    'Cannot get openrc from any controller node')

        for src in openrc:
            dst = src.lower()
            if dst.startswith('os_'):
                dst = dst[3:]
            self.os_data[dst] = openrc[src]

        fuel_version_info = self.ctx.fuel.fuel_version.get_all()
        self.os_data['mos_version'] = fuel_version_info['release']

    def _unpack_openrc(self, payload):
        # FIXME(dbogun): we must use shell to parse openrc script
        re_var = re.compile(
            '^\s*export\s+([a-zA-Z_0-9]+)\s*=\s*[\']*([^\']+)[\']*\s*$')

        openrc = {}
        for line in payload.splitlines():
            m = re_var.search(line)
            if m is None:
                continue
            name, value = m.groups()
            openrc[name] = value

        auth_ip = openrc['OS_AUTH_URL'].split(':')[1].strip('/')
        openrc['AUTH_ENDPOINT_IP'] = auth_ip

        # NOTE(albartash): A very important moment. As we use Keystone v2.0,
        # here we must specify a concrete version for OS_AUTH_URL in case
        # when MOS>=8.0, as this information is not presented in openrc!
        ks_version = 'v2.0'
        if not openrc['OS_AUTH_URL'].rstrip('/').endswith(ks_version):
            openrc['OS_AUTH_URL'] = openrc['OS_AUTH_URL'].rstrip(
                '/') + '/v2.0/'

        return openrc

    def populate_etc_hosts(self):
        keystone = utils.get_keystone_basic_client(self.os_data)
        auth_url = keystone.service_catalog.get_endpoints('identity')
        auth_url = auth_url['identity'][0]['publicURL']

        self.os_data['insecure'] = auth_url.startswith('https')

        ip = re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
                        auth_url)
        if ip:
            self.os_data['auth_fqdn'] = ''
            self.os_data['public_endpoint_ip'] = ip[0]
        else:
            fqdn = re.sub(r'http.*://', '', re.sub(r':5000.*', '', auth_url))
            self.os_data['auth_fqdn'] = fqdn

            node = self.ctx.nodes_by_role[mcv_config.FUEL_ROLE_CONTROLLER]
            node = node[0]

            addr = self.ctx.fuel.get_node_address(node)
            LOG.debug(
                'Trying to extract openrc from controller %s',
                node['fqdn'])
            work_dir = self.ctx.work_dir_global
            connect = ssh.SSHClient(
                host=addr, username=mcv_config.OS_NODE_SSH_USER,
                rsa_key=work_dir.resource(work_dir.RES_OS_SSH_KEY))
            connect.connect(exc=True)

            cmd = "getent ahostsv4 %s | head -1 | awk '{print $1}'" % fqdn
            proc = connect.exec_cmd(cmd)
            public_endpoint_ip = proc.stdout.rstrip()
            if not public_endpoint_ip:
                raise mcv_consoler.exceptions.ResolveFqdn(
                    "Can't resolve {} name. Command returned {}".format(
                        fqdn, proc))
            self.os_data['public_endpoint_ip'] = public_endpoint_ip

        # NOTE(albartash): In some cases we need public endpoint URL, so better
        # to make it here and use in other places as-is.
        auth_url = '{prot}://{ip}:{port}/{version}/'.format(
            prot='https' if self.os_data['insecure'] else 'http',
            ip=self.os_data['public_endpoint_ip'],
            port=5000,
            version='v2.0')
        self.os_data['public_auth_url'] = auth_url


class IRouter(Router):
    def __init__(self, ctx, **kwargs):
        super(IRouter, self).__init__(ctx, **kwargs)
        self.port_forwarding = kwargs.get('port_forwarding', False)

        self.fresh_floating_ips = []

        self.novaclient = clients.get_nova_client(self.os_data)
        self.keystoneclient = clients.get_keystone_client(self.os_data)
        self.secure_group_name = 'mcv-special-group'
        self.server = None
        self.mcvgroup = None

    def get_os_data(self):
        data = super(IRouter, self).get_os_data()

        data.update({
            'auth_fqdn': CONF.auth.auth_fqdn,
            'region_name': CONF.auth.region_name,
            'public_endpoint_ip': CONF.auth.auth_endpoint_ip,
        })
        # NOTE(albartash): As in L1 endpoint is public,
        # we will duplicate it here.
        data['public_auth_url'] = data['auth_url']

        return data

    def setup_connections(self):
        if not self.check_and_fix_access_data():
            self.hosts.restore()
            return False

        # TODO(albartash): This check will never happen. We should investigate
        # whether it's needed to be fixed.
        if self.check_mcv_secgroup() == -1:
            LOG.error('No MCV server found by ip for adding security group')
            return False

        if self.port_forwarding:
            LOG.debug('Port forwarding will be done automatically')
            if self.check_and_fix_iptables_rule() == -1:
                LOG.error('Fail to check iptables rules')
                self.hosts.restore()
                return False
        else:
            LOG.debug('No port forwarding required')

        self.check_and_fix_floating_ips()
        return True

    def get_private_endpoint_ip(self):
        """Get Private endpoint-ip from Keystone.
        (it is internalURL in Keystone)
        InternalURL - is always the same for any service.
        """
        full_url = self.keystoneclient.session.get_endpoint(
            service_type='identity',
            interface='internal',
            region_name=self.os_data['region_name']
        )
        return str(full_url.split('/')[2].split(':')[0])

    def verify_access_data_is_set(self):
        # TODO(albartash): This method is gonna be invalid, as we have
        # hierarchical structure of os_data!

        # NOTE(albartash): This method is commented out, as it's dangerous
        # and can cause troubles. Needs to be fixed later.

        #access = True
        #for key, value in self.os_data.iteritems():
        #    if value is None:
        #        LOG.error('Config value %s is not set, please provide '
        #                  'required data in /etc/mcv/mcv.conf' % key)
        #        access = False
        #return access
        return True

    def make_sure_controller_name_could_be_resolved(self):
        LOG.debug('Trying to update /etc/hosts file')
        a_fqdn = self.os_data["auth_fqdn"]
        public_ip = self.os_data['ips']['endpoint']
        if not a_fqdn:
            LOG.debug('No FQDN specified. Nothing to update')
            return
        if not public_ip:
            LOG.debug("Public IP is empty or missing. Can't patch anything")
            return
        LOG.debug('Adding new record: %s \t%s' % (a_fqdn, public_ip))
        self.hosts.modify({a_fqdn: public_ip})

    def check_and_fix_floating_ips(self):
        res = self.novaclient.floating_ips.list()
        if len(res) >= 2:
            LOG.debug("Apparently there is enough floating ips")
        else:
            LOG.info("Need to create a floating ip")
            try:
                self.fresh_floating_ips.append(
                    self.novaclient.floating_ips.create())
            except Exception as ip_e:
                LOG.warning("Apparently the cloud is out of free floating ip. "
                            "You might experience problems "
                            "with running some tests")
                LOG.debug("Error creating floating IP - %s" % str(ip_e))

                return
            return self.check_and_fix_floating_ips()

    def is_cloud_instance(self):
        """Check if MCV image is running as an instance of a cloud """

        mcv_instance_ip = self.os_data['ips']['instance']
        if mcv_instance_ip is None:
            LOG.debug("Parameter 'instance_ip' is missing in configuration "
                      "file, or it's empty. No security group will be created")
            return False

        all_floating_ips = self.novaclient.floating_ips.list()
        for ip_obj in all_floating_ips:
            if not ip_obj.instance_id:  # IP is not assigned to any instance
                continue
            if ip_obj.ip == mcv_instance_ip:
                return True

    def check_mcv_secgroup(self):
        if not self.is_cloud_instance():
            LOG.debug("Looks like mcv image is not running as an instance "
                      "of a cloud. Skipping creation of %s" % self.secure_group_name)
            return

        servers = self.novaclient.servers.list()
        for server in servers:
            addr = server.addresses
            for network, ifaces in addr.iteritems():
                for iface in ifaces:
                    if iface['addr'] == self.os_data["ips"]["instance"]:
                        self.server = server

        LOG.debug("Checking for proper security group")
        res = self.novaclient.security_groups.list()
        for r in res:
            if r.name == self.secure_group_name:
                LOG.debug("Has found one")
                self.mcvgroup = r
                # NOTE(ogrytsenko): a group could exist while being
                # not attached
                return

        LOG.debug("Nope. Has to create one")
        self.mcvgroup = self.novaclient.security_groups.create(
            self.secure_group_name, 'mcvgroup')
        LOG.debug("Created new security group %s. "
                  "Group id: %s" % (self.secure_group_name, self.mcvgroup.id))
        self.novaclient.security_group_rules.create(
            parent_group_id=self.mcvgroup.id, ip_protocol='tcp', from_port=5999,
            to_port=6001, cidr='0.0.0.0/0')
        LOG.debug("Finished creating a group and adding rules")

        LOG.debug('Trying to attach our mcv-instance to created group')
        self.server.add_security_group(self.mcvgroup.id)
        LOG.debug("Added security group {gid} to an "
                  "instance {sid}".
                  format(gid=self.mcvgroup.id, sid=self.server.id))
        LOG.debug("Finished setting-up security groups")

    def remove_security_group(self):
        if self.server is None or self.mcvgroup is None:
            LOG.debug('No security group was created. Nothing to remove')
            return

        LOG.debug("Removing created security group %s "
                  "from the server %s" % (self.secure_group_name, self.server.id))
        try:
            self.server.remove_security_group(self.mcvgroup.id)
        except nexc.NotFound:
            LOG.debug("Failed to remove security group. It's not associated with instance.")
            return
        self.novaclient.security_groups.delete(self.mcvgroup.id)

    def delete_floating_ips(self):
        LOG.debug("Removing created floating IPs")
        for floating_ip in self.fresh_floating_ips:
            try:
                floating_ip.delete()
            except Exception as e:
                LOG.debug("Error removing floating IP: %s" % e.message)

    def check_and_fix_access_data(self):
        if not self.verify_access_data_is_set():
            return False

        LOG.debug("Trying to authenticate with OpenStack "
                  "using provided credentials...")
        self.make_sure_controller_name_could_be_resolved()
        try:
            self.novaclient.servers.list()
        except nexc.ConnectionRefused:
            LOG.error("Apparently authentication endpoint address is invalid."
                      " Current value is %s" % self.os_data["ips"]["endpoint"])
            return False
        except nexc.Unauthorized:
            LOG.error("Apparently OS user credentials are incorrect.\n"
                      "Current os-username is: %s\n"
                      "Current os-password is: %s \n"
                      "Current os-tenant is: %s \n"
                      % (self.os_data["username"],
                         self.os_data["password"],
                         self.os_data["tenant_name"]
                         ))
            return False
        except (Timeout, ConnectionError) as conn_e:
            LOG.error("Apparently auth endpoint address is not valid."
                      " %s" % str(conn_e))
            return False
        LOG.debug("Access data looks valid.")
        return True

    def check_and_fix_iptables_rule(self):
        # TODO(aovchinnikov): divide this some day
        # TODO(aovchinnikov): this might change so it is much wiser
        # to do actual check
        keystone_private_endpoint_ip = self.get_private_endpoint_ip()
        port_substitution = {"cnt_ip": self.os_data["ips"]["controller"],
                             "kpeip": keystone_private_endpoint_ip,
                             }
        mk_rule = ("iptables -I INPUT 1 -p tcp -m tcp --dport 7654 -j ACCEPT "
                   "-m comment --comment \'MCV_tunnel\'")
        rkname = "remote_mcv_key"
        mk_port = "ssh -o PreferredAuthentications=publickey -o "\
                  "StrictHostKeyChecking=no -i " + rkname + " -f -N -L "\
                  "%(cnt_ip)s:7654:%(kpeip)s:35357 localhost" %\
                  port_substitution

        ssh = paramiko.client.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(hostname=self.os_data["ips"]["controller"],
                        username=self.os_data['auth']['controller_uname'],
                        password=self.os_data['auth']['controller_pwd'],
                        timeout=10)
        except paramiko.AuthenticationException:
            LOG.critical("Can not access controller via ssh "
                         "with provided credentials!")
            return -1
        except paramiko.SSHException as ssh_e:
            LOG.critical(
                "SSH error: can not access controller - %s" % str(ssh_e))
            return -1
        except socket.error as sock_e:
            LOG.critical(
                "Socket error: can not access controller via ssh - %s" % str(
                    sock_e))
            return -1

        ssh.exec_command("ssh-keygen -f" + rkname + " -N '' > /dev/null 2>&1")
        # TODO(mcv-team): ok, this should not be done by sleeping
        time.sleep(3)
        ssh.exec_command("cat " + rkname + ".pub >> .ssh/authorized_keys")
        time.sleep(3)
        stdin, stdout, stderr = ssh.exec_command("iptables -L -n")
        if stdout.read().find("MCV_tunnel") == -1:
            LOG.debug("There is no rule in controller's iptables "
                      "for proper forwarding! Have to add one")
            ssh.exec_command(mk_rule)
        else:
            LOG.debug("Controller's iptables rule seems to be in place")

        result = None
        while result is None:
            stdin, stdout, stderr = ssh.exec_command("ps aux")
            result = re.search("ssh.*35357", stdout.read())
            if result is None:
                LOG.debug("Apparently port forwarding on the controller "
                          "is not set up properly")
                time.sleep(3)
                ssh.exec_command(mk_port)
                time.sleep(5)
            else:
                LOG.debug("Apparently port forwarding on the "
                          "controller is set")

        ssh.exec_command("rm " + rkname + "*")

        res = subprocess.Popen(["sudo", "iptables", "-t", "nat", "-L -n", ],
                               shell=False, stdout=subprocess.PIPE,
                               stdin=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               preexec_fn=utils.ignore_sigint).stdout.read()

        if re.search("DNAT.*7654\n", res) is not None:
            # leave slowly, don't wake it up
            LOG.debug("Local iptables rule is set.")
            return
        cmd = "sudo iptables -L -n -t nat --line-numbers " \
              "| grep MCV_instance 1>/dev/null && echo -n YES || echo -n NO"
        out = utils.run_cmd(cmd)
        if out == 'NO':
            destination = "%s:7654" % self.os_data["ips"]["controller"]
            # TODO(albartash): rewrite with run_cmd()
            res = subprocess.Popen(["sudo", "iptables", "-t", "nat", "-I",
                                    "PREROUTING", "1", "-d",
                                    self.get_private_endpoint_ip(), "-p",
                                    "tcp", "--dport", "35357", "-j", "DNAT",
                                    "--to-destination", destination,
                                    "-m", "comment", "--comment",
                                    "\'MCV_instance\'"],
                                   stdout=subprocess.PIPE,
                                   preexec_fn=utils.ignore_sigint
                                   ).stdout.read()
            LOG.debug("Now local iptables rule is set.")

    def stop_forwarding(self):
        LOG.debug("Reverting changes needed for access to admin network")
        ssh = paramiko.client.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(hostname=self.os_data["ips"]["controller"],
                        username=self.os_data['auth']['controller_uname'],
                        password=self.os_data['auth']['controller_pwd'])
        except Exception:
            LOG.critical("SSH is broken! Please revert port forwarding on your"
                         " controller manually")
            LOG.debug(traceback.format_exc())
            return

        ssh.exec_command("ps aux | grep '[s]sh -o Preferred' | "
                         "awk '{ print $2 }'| xargs kill")

        ssh.exec_command("iptables -L -n --line-numbers | grep MCV_tunnel | "
                         "awk '{print $1}' | xargs iptables -D INPUT")

        subprocess.call("sudo iptables -L -n -t nat --line-numbers | "
                        "grep MCV_instance | awk '{print $1}' | tac | "
                        "xargs -l sudo iptables -t nat -D PREROUTING",
                        shell=True)

    def cleanup(self):
        self.remove_security_group()
        self.stop_forwarding()
        self.delete_floating_ips()
        self.hosts.restore()
        self.stop_all_docker_containers()


class EtcHosts(object):
    HOSTS_FILE = '/etc/hosts'
    TEMP_FILE = '/tmp/etc-hosts.mcv~'
    COMMENT = "# added by MCV tool"

    def __init__(self):
        self.__changed = False
        self.__restored = False

    def modify(self, hosts_dict):
        etc_hosts = self.HOSTS_FILE
        temp_file = self.TEMP_FILE

        with open(etc_hosts) as f:
            orig_content = f.read()
        stats = os.stat(etc_hosts)

        with open(temp_file, 'w') as f:
            for line in orig_content.rstrip().split('\n'):
                if line.find(self.COMMENT) >= 0:
                    continue
                f.write('%s\n' % line)
            for (name, ip) in sorted(hosts_dict.items()):
                f.write('%-30s %s\n' % ('%s %s' % (ip, name), self.COMMENT))

        os.chown(temp_file, stats.st_uid, stats.st_gid)
        os.chmod(temp_file, stats.st_mode)
        shutil.copyfile(temp_file, etc_hosts)
        os.remove(temp_file)
        self.__changed = True

    def restore(self):
        if self.__changed:
            self.modify(hosts_dict={})
            self.__changed = False
        self.__restored = True

    def __del__(self):
        # this method should never fail
        if not self.__changed:
            return
        if self.__restored:
            return
        try:
            self.restore()
        except:
            pass
