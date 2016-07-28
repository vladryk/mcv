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

import copy
import errno
import os
import re
import shelve
import socket
import shlex
import shutil
import subprocess
import time
import paramiko
from paramiko import client

from requests.exceptions import ConnectionError
from requests.exceptions import Timeout

from mcv_consoler.common import clients as Clients
from mcv_consoler.common.ssh import SSHClient

from mcv_consoler.common.config import DEBUG
from mcv_consoler.common.config import DEFAULT_CREDS_PATH
from mcv_consoler.common.config import DEFAULT_RSA_KEY_PATH
from mcv_consoler.common.config import MCV_LOCAL_PORT
from mcv_consoler.common.config import RMT_CONTROLLER_PORT
from mcv_consoler.common.config import RMT_CONTROLLER_USER

from mcv_consoler import utils
from mcv_consoler.utils import GET
from novaclient import exceptions as nexc

import traceback
from mcv_consoler.logger import LOG

from mcv_consoler.utils import run_cmd

from mcv_consoler.common.procman import ProcessManager


LOG = LOG.getLogger(__name__)


class Router(object):
    """Defines base class for Routing."""

    def __init__(self, **kwargs):
        self.config = kwargs["config"]
        self.os_data = self._get_os_data()
        self.hosts = EtcHosts()

    def _get_os_data(self):
        # TODO(albartash): needs to be received from endpoint-list
        protocol = GET(self.config, 'auth_protocol')

        endpoint_ip = GET(self.config, 'auth_endpoint_ip', 'auth')
        auth_url_tpl = '{hprot}://{ip}:{port}/v{version}'
        tenant_name = GET(self.config, 'os_tenant_name', 'auth')
        password = GET(self.config, 'os_password', 'auth')
        insecure = (protocol == "https")
        # NOTE(albartash): port 8443 is not ready to use somehow
        nailgun_port = 8000

        os_data = {'username': GET(self.config, 'os_username', 'auth'),
                   'password': password,
                   'tenant_name': tenant_name,
                   'auth_url': auth_url_tpl.format(hprot=protocol,
                                                   ip=endpoint_ip,
                                                   port=5000,
                                                   version="2.0"),
                   'ips': {
                       'controller': GET(self.config, 'controller_ip', 'auth'),
                       'endpoint': endpoint_ip,
                       'instance': GET(self.config, 'instance_ip')},
                   'auth': {
                       'controller_uname': GET(self.config, 'controller_uname',
                                               'auth'),
                       'controller_pwd': GET(self.config, 'controller_pwd',
                                             'auth')},
                   'fuel': {
                       'username': GET(self.config, 'username', 'fuel'),
                       'password': GET(self.config, 'password', 'fuel'),
                       'nailgun': GET(self.config, 'nailgun_host', 'fuel'),
                       'nailgun_port': nailgun_port,
                       'cluster_id': GET(self.config, 'cluster_id', 'fuel'),
                        # TODO(albartash): fix in router.py (None to "")
                       'ca_cert': "",
                       'cert': GET(self.config, 'ssh_cert', 'fuel'),
                   },
                  'debug': DEBUG,
                  'insecure': insecure,
                  'mos_version': GET(self.config, 'mos_version', 'basic'),
                  'auth_fqdn': GET(self.config, 'auth_fqdn', 'auth'),
                   # nova tenant
                   'project_id': tenant_name,
                   # nova and cinder passwd
                   'api_key': password
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


class MRouter(Router):

    def __init__(self, **kwargs):
        super(MRouter, self).__init__(**kwargs)
        # TODO: For L2 segment


class CRouter(Router):

    def __init__(self, **kwargs):
        super(CRouter, self).__init__(**kwargs)

        self.procman = ProcessManager()

    def _load_creds(self):
        creds = shelve.open(DEFAULT_CREDS_PATH)
        return creds

    def get_os_data(self):
        # TODO: maybe, use just os_data here?
        base_data = self.os_data

        creds = self._load_creds()

        try:
            tenant = creds['OS_TENANT_NAME']
            password = creds['OS_PASSWORD']
            os_data = {'auth_url': creds['OS_AUTH_URL'],
                       'username': creds['OS_USERNAME'],
                       'password': creds['OS_PASSWORD'],
                       'tenant_name': tenant,
                       'region_name': creds['OS_REGION_NAME'],

                       'ips': {'endpoint': creds['AUTH_ENDPOINT_IP']},

                       # nova tenant
                       'project_id': tenant,
                       # nova and cinder passwd
                       'api_key': password,

                       # NOTE(albartash): Actually, this option does not belong to
                       # openrc, but we store it in such file for usability
                       'auth_fqdn': creds['AUTH_FQDN'],
                       'mos_version': creds['MOS_VERSION'],
                       'insecure': creds['INSECURE'],
                       'public_endpoint_ip': creds['PUBLIC_ENDPOINT_IP'],
                       'public_auth_url': creds['PUBLIC_AUTH_URL']}
        except KeyError:
                LOG.debug('Fail to extract some options from openrc file!')
                LOG.debug(traceback.format_exc())
                return {}

        # NOTE(albartash): a trick to protect all data from erasing
        full_data = copy.deepcopy(base_data)
        full_data.update(os_data)
        full_data['ips'].update(base_data['ips'])

        return full_data

    def get_rsa_key(self):
        client = SSHClient(host=self.os_data['fuel']['nailgun'],
                           username=self.os_data['fuel']['username'],
                           password=self.os_data['fuel']['password'])

        key_path = self.os_data['fuel']['cert']

        if not client.connect():
            LOG.error('Fail to get RSA key!')
            return False

        sout, serr = client.exec_cmd("cat {fpath}".format(fpath=key_path))

        client.close()

        if serr:
            LOG.debug("Caught error on Master Node: {err}".format(err=serr))
            return False

        keyfile_path = DEFAULT_RSA_KEY_PATH
        try:
            LOG.debug('Saving RSA key to file {fname}...'.format(
                fname=keyfile_path))
            fp = open(keyfile_path, 'w')
            fp.write(sout)
            fp.close()
            LOG.debug('Successfully saved RSA key.')
        except IOError as e:
            LOG.error('Fail to store RSA key on MCV host!')
            LOG.debug(traceback.format_exc())
            return False

        return True

    def _get_controllers(self):
        client = SSHClient(host=self.os_data['fuel']['nailgun'],
                           username=self.os_data['fuel']['username'],
                           password=self.os_data['fuel']['password'])

        if not client.connect():
            LOG.debug('Cannot access Fuel Master Node with provided '
                      'credentials!')
            return []

        cmd = 'fuel node --list 2>/dev/null'
        controllers = []
        try:
            result = client.exec_cmd(cmd)[0]

            re_ip = re.compile('\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)')

            for line in result.splitlines():
                if 'controller' not in line:
                    continue
                ip = re_ip.search(line)
                if not ip:
                    LOG.debug('Fail to get controller IP from line: {line}'.format(
                        line=line))
                    continue
                controllers.append(ip.groups()[0])
        except paramiko.SSHException:
            return []
        finally:
            client.close()

        return controllers

    def _get_mos_version(self):
        client = SSHClient(host=self.os_data['fuel']['nailgun'],
                           username=self.os_data['fuel']['username'],
                           password=self.os_data['fuel']['password'])

        if not client.connect():
            LOG.debug('Cannot access Fuel Master Node with provided '
                      'credentials!')
            return []

        # NOTE(albartash): If we switch to Python3.4+ once,
        # please use stdout to get Fuel version. Otherwise,
        # this data must be extracted from stderr!
        cmd = 'fuel --version'
        v = ''
        try:
            result = client.exec_cmd(cmd)[1]

            re_version = re.compile('^([0-9]+\.[0-9]+)')

            version = re_version.search(result)
            if not version:
                LOG.debug('Fail to get version from Fuel Master Node!')
                v = ''
            else:
                v = version.groups()[0]
        except subprocess.CalledProcessError:
                LOG.debug('Fail to get version from Fuel Master Node!')
                v = ''
        finally:
            client.close()

        return v

    def _get_credentials(self, ctrl):
        # get openrc as dict from controller
        # using Fuel private key

        key = paramiko.RSAKey.from_private_key_file(DEFAULT_RSA_KEY_PATH)
        client = SSHClient(host=ctrl, username=RMT_CONTROLLER_USER,
                           rsa_key=key)
        if not client.connect():
            LOG.debug('Fail to reach controller node at "{addr}" with '
                      'provided RSA key!'.format(addr=ctrl))
            return {}

        openrc = {}

        cmd = 'cat /root/openrc'
        lines = client.exec_cmd(cmd)[0]

        re_var = re.compile(
            '^\s*export\s+([a-zA-Z_0-9]+)\s*=\s*[\']*([^\']+)[\']*\s*$')

        for line in lines.splitlines():
            result = re_var.search(line)
            if not result or len(result.groups()) != 2:
                continue

            name, value = result.groups()
            openrc[name] = value

        openrc['AUTH_ENDPOINT_IP'] = openrc['OS_AUTH_URL'].split(':')[1].strip('/')

        # NOTE(albartash): A very important moment. As we use Keystone v2.0,
        # here we must specify a concrete version for OS_AUTH_URL in case
        # when MOS>=8.0, as this information is not presented in openrc!
        ks_version = 'v2.0'
        if not openrc['OS_AUTH_URL'].rstrip('/').endswith(ks_version):
            openrc['OS_AUTH_URL'] = openrc['OS_AUTH_URL'].rstrip('/') + '/v2.0/'

        data = {'username': openrc['OS_USERNAME'],
                'password': openrc['OS_PASSWORD'],
                'tenant_name': openrc['OS_TENANT_NAME'],
                'auth_url': openrc['OS_AUTH_URL'],
               }
        self.keystoneclient = Clients.get_keystone_client(data)
        public_url = self.keystoneclient.service_catalog.get_endpoints(
            'identity')['identity'][0]['publicURL']
        openrc['INSECURE'] = ("https" == re.findall(r'https|http', public_url)[0])

        ip = re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', public_url)
        if ip:
            openrc['AUTH_FQDN'] = ''
            openrc['PUBLIC_ENDPOINT_IP'] = ip[0]
        else:
            fqdn = re.sub(r'http.*://', '', re.sub(r':5000.*', '', public_url))
            openrc['AUTH_FQDN'] = fqdn
            cmd = "cat /etc/hosts | grep %s| awk '{print $1}'" % fqdn
            host_resolve = client.exec_cmd(cmd)[0]
            openrc['PUBLIC_ENDPOINT_IP'] = host_resolve.rstrip()

        # NOTE(albartash): In some cases we need public endpoint URL, so better
        # to make it here and use in other places as-is.
        protocol = 'https' if openrc['INSECURE'] else 'http'
        openrc['PUBLIC_AUTH_URL'] = '{prot}://{ip}:{port}/{version}/'.format(
            prot=protocol,
            ip=openrc['PUBLIC_ENDPOINT_IP'],
            port=5000,
            version='v2.0')

        client.close()

        return openrc

    def get_and_store_credentials(self):
        # Extract credentials from openrc files
        # 0. Get list of controllers from Fuel
        # 1. SSH to controller using ssh_cert from Fuel
        # 2. Get credentials from openrc
        # 3. Store credentials in file on MCV host


        mos_version = self._get_mos_version()
        controllers = self._get_controllers()

        openrc = {}
        for ctrl in controllers:
            try:
                LOG.debug('Trying to extract openrc from controller '
                          '{ctrl}'.format(ctrl=ctrl))

                openrc = self._get_credentials(ctrl)
                if openrc:
                    break
            except Exception:
                LOG.debug('Cannot extract openrc from controller '
                          '{ctrl}'.format(ctrl=ctrl))

        if not openrc:
            LOG.debug('Cannot get credentials from controllers!')
            return False

        fp = shelve.open(DEFAULT_CREDS_PATH)
        for cred in openrc:
            fp[cred] = openrc[cred]

        fp['MOS_VERSION'] = mos_version
        fp.close()

        return True

    def _make_tunnel_to_controller(self):
        """Make SSH tunnel to a controller node from MCV host."""

        #!!! Perhaps, I do something wrong here.
        # We need to make ssh tunnel to a controller.
        # When I tried to do it separately, SSH said
        # 'Cannot fork into background without a command
        # to execute'.

        for ctrl in self._get_controllers():
            try:
                cmd = ("sshpass -p {fuel_pwd} "
                       "ssh -q -L {local_port}:{controller}:{rmt_port} "
                       "{fuel_user}@{fuel_host} "
                       "-o UserKnownHostsFile=/dev/null "
                       "-o StrictHostKeyChecking=no "
                       "-i {key_path}").format(
                    fuel_pwd=self.os_data['fuel']['password'],
                    local_port=MCV_LOCAL_PORT,
                    controller=ctrl,
                    rmt_port=RMT_CONTROLLER_PORT,
                    fuel_user=self.os_data['fuel']['username'],
                    fuel_host=self.os_data['fuel']['nailgun'],
                    key_path=DEFAULT_RSA_KEY_PATH)

                retcode = self.procman.run_standalone_process(cmd)
                if retcode is None:
                    break
            except Exception:
                LOG.debug('Controller {ctrl} is not ready for tunnelling...'.format(ctrl=ctrl))
                continue
        else:
            LOG.debug('Cannot establish tunnel to any controller!')
            return False

        LOG.debug('SSH tunnel to controller has been established '
                  'successfully.')
        return True

    def _encapsulate_networks_to_ssh_tunnel(self):
        """Encapsulate cloud networks using Sshuttle."""

        cmd = ("sudo -u mcv "
               "sshpass -p {fuel_pwd} "
               "sshuttle --listen 0.0.0.0:0 -vNHr "
               "{fuel_user}@localhost:{local_port} "
               "--dns --ssh-cmd "
               "\"ssh -q -o UserKnownHostsFile=/dev/null "
               "-o StrictHostKeyChecking=no -i {key_path}\" "
               "127.0.0.1/26").format(fuel_user=self.os_data['fuel']['username'],
                                   fuel_pwd=self.os_data['fuel']['password'],
                                   local_port=MCV_LOCAL_PORT,
                                   key_path=DEFAULT_RSA_KEY_PATH)

        # NOTE(albartash): sshuttle sometimes cannot runs properly, so we need
        # to do some attempts.
        attempts = 5
        for counter in xrange(0, attempts):
            try:
                retcode = self.procman.run_standalone_process(cmd)
                if retcode is None:
                    break
            except Exception as e:
                LOG.debug('An error while running Sshuttle: {msg}'.format(
                    msg=str(e)))
        else:
            LOG.debug('Failed to run sshuttle! Exit.')
            return False

        LOG.debug('Cloud networks have been encapsulated successfully.')
        return True

    def make_sure_controller_name_could_be_resolved(self):
        LOG.debug('Trying to update /etc/hosts file')
        openrc = self._load_creds()
        a_fqdn = openrc['AUTH_FQDN']
        public_ip = openrc['PUBLIC_ENDPOINT_IP']
        if not a_fqdn:
            LOG.debug('No FQDN specified. Nothing to update')
            return
        if not public_ip:
            LOG.debug("Public IP is empty or missing. Can't patch anything")
            return
        LOG.debug('Adding new record: %s \t%s' % (a_fqdn, public_ip))
        self.hosts.modify({a_fqdn: public_ip})

    def setup_ssh_tunnels(self):
        if not self._make_tunnel_to_controller():
            LOG.debug('Cannot make an SSH tunnel to controller using '
                      'Fuel Master Node!')
            return False

        if not self._encapsulate_networks_to_ssh_tunnel():
            LOG.debug('Cannot encapsulate cloud networks to the created '
                      'SSH tunnel!')
            return False

        LOG.debug('Tunnels have been set successfully.')
        return True

    def setup_connections(self):
        # check cert on host
        if not self.get_rsa_key():
            LOG.debug('No RSA key exists to access cloud!')
            return False
        if not self.setup_ssh_tunnels():
            LOG.debug('Cannot set up SSH tunnels!')
            return False
        if not self.get_and_store_credentials():
            LOG.debug('No credentials specified to access cloud!')
            return False
        self.make_sure_controller_name_could_be_resolved()

        LOG.debug('Connections have been set successfully.')
        return True

    def cleanup(self):

        LOG.debug('Removing files with credentials to cloud.')
        for pth in (DEFAULT_RSA_KEY_PATH, DEFAULT_CREDS_PATH):
            try:
                os.remove(pth)
            except OSError as e:
                LOG.debug('Cannot remove file {fp}. Reason: {reason}'.format(
                    fp=pth, reason=str(e)))

        LOG.debug('Cleanup all started subprocesses.')
        self.procman.cleanup()
        LOG.debug('Finish cleanup of subprocesses.')
        LOG.debug('Restoring /etc/hosts')
        self.hosts.restore()
        self.stop_all_docker_containers()


class IRouter(Router):

    def __init__(self, **kwargs):
        super(IRouter, self).__init__(**kwargs)
        self.port_forwarding = kwargs.get('port_forwarding', False)

        self.fresh_floating_ips = []

        self.novaclient = Clients.get_nova_client(self.os_data)
        self.keystoneclient = Clients.get_keystone_client(self.os_data)
        self.secure_group_name = 'mcv-special-group'
        self.server = None
        self.mcvgroup = None

    def get_os_data(self):

        base_data = self.os_data

        protocol = GET(self.config, 'auth_protocol')
        endpoint_ip = GET(self.config, 'auth_endpoint_ip', 'auth')
        auth_url_tpl = '{hprot}://{ip}:{port}/v{version}'
        tenant_name = GET(self.config, 'os_tenant_name', 'auth')
        password = GET(self.config, 'os_password', 'auth')
        insecure = (protocol == "https")
        # NOTE(albartash): port 8443 is not ready to use somehow
        nailgun_port = 8000

        os_data = {
                   'auth_fqdn': GET(self.config, 'auth_fqdn', 'auth'),

                   'ips': {
                       'controller': GET(self.config, 'controller_ip', 'auth'),
                       'endpoint': endpoint_ip},
                   'auth': {
                       'controller_uname': GET(self.config, 'controller_uname',
                                               'auth'),
                       'controller_pwd': GET(self.config, 'controller_pwd',
                                             'auth')},
                   'insecure': insecure,
                   'region_name': GET(self.config, 'region_name', 'auth'),
                   'public_endpoint_ip': endpoint_ip,

                   # NOTE(albartash): As in L1 endpoint is public,
                   # we will duplicate it here.
                   'public_auth_url': self.os_data['auth_url']
                   }

        full_data = copy.deepcopy(base_data)
        full_data.update(os_data)
        full_data['ips'].update(base_data['ips'])

        return full_data

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
        full_url = self.keystoneclient.service_catalog.get_endpoints(
            'identity')['identity'][0]['internalURL']
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
            self.novaclient.authenticate()
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

        ssh = client.SSHClient()
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
        ssh = client.SSHClient()
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
