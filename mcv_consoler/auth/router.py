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
import re
import socket
import subprocess
import time

import paramiko
from paramiko import client

from requests.exceptions import ConnectionError
from requests.exceptions import Timeout

from mcv_consoler.common import clients as Clients

from mcv_consoler.common.config import DEBUG
from mcv_consoler import utils
from mcv_consoler.utils import GET
from novaclient import exceptions as nexc

import traceback
from mcv_consoler.logger import LOG


LOG = LOG.getLogger(__name__)


class Router(object):
    """Defines base class for Routing."""

    def __init__(self, **kwargs):
        self.config = kwargs["config"]
        self.os_data = self.get_os_data()

    def get_os_data(self):
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
                   'auth_fqdn': GET(self.config, 'auth_fqdn', 'auth'),

                   'ips': {
                       'controller': GET(self.config, 'controller_ip', 'auth'),
                       'endpoint': endpoint_ip,
                       'instance': GET(self.config, 'instance_ip', 'shaker')},
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
                       'cert': GET(self.config, 'ssh_cert', 'fuel')},

                   'auth_url': auth_url_tpl.format(hprot=protocol,
                                                   ip=endpoint_ip,
                                                   port=5000,
                                                   version="2.0"),
                   'insecure': insecure,
                   'region_name': GET(self.config, 'region_name', 'auth'),
                   # nova tenant
                   'project_id': tenant_name,
                   # nova and cinder passwd
                   'api_key': password,
                   'debug': DEBUG
                   }

        return os_data

    def setup_connections(self):
        """Set up connections for routing requests."""
        raise NotImplementedError

    def cleanup(self):
        """Clean up routing rules if necessary."""
        raise NotImplementedError


class CRouter(Router):

    def __init__(self, **kwargs):
        super(CRouter, self).__init__(**kwargs)

    def setup_connections(self):
        pass

    def cleanup(self):
        pass


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

    def setup_connections(self):
        if not self.check_and_fix_access_data():
            self.restore_hosts_config()
            return False

        # TODO(albartash): This check will never happen. We should investigate
        # whether it's needed to be fixed.
        if self.check_mcv_secgroup() == -1:
            LOG.error('No MCV server found by ip for adding security group')
            return False

        if self.port_forwarding:
            LOG.info('Port forwarding will be done automatically')
            if self.check_and_fix_iptables_rule() == -1:
                LOG.error('Fail to check iptables rules')
                self.restore_hosts_config()
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
        a_fqdn = self.os_data["auth_fqdn"]
        if a_fqdn:
            LOG.debug("FQDN is specified. Value=%s" % a_fqdn)
            f = open('/etc/hosts', 'a+r')
            for line in f.readlines():
                if line.find(a_fqdn) != -1:
                    return
            f.write(' '.join([self.os_data['ips']['endpoint'],
                    self.os_data['auth_fqdn'], "\n"]))
            f.close()

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
        """Check if MCV image is running as an instance of a cloud that
        we are going to test.
        """

        all_floating_ips = self.novaclient.floating_ips.list()
        for ip_obj in all_floating_ips:
            if not ip_obj.instance_id:  # IP is not assigned to any instance
                continue
            if ip_obj.ip == self.os_data['ips']['instance']:
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
        LOG.debug("Removing created security group %s "
                  "from the server %s" % (self.secure_group_name, self.server.id))
        try:
            self.server.remove_security_group(self.mcvgroup.id)
        except nexc.NotFound:
            LOG.debug("Failed to remove security group. It's not associated with instance.")
            return
        self.novaclient.security_groups.delete(self.mcvgroup.id)

    def delete_floating_ips(self):
        LOG.info("Removing created floating IPs")
        for floating_ip in self.fresh_floating_ips:
            try:
                floating_ip.delete()
            except Exception as e:
                LOG.debug("Error removing floating IP: %s" % e.message)

    def restore_hosts_config(self):
        a_fqdn = self.os_data["auth_fqdn"]
        if a_fqdn:
            LOG.debug("Restoring hosts config")
            f = open("/etc/hosts", "r+")
            lines = f.readlines()
            f.seek(0)
            for line in lines:
                if line.find(a_fqdn) == -1:
                    f.write(line)
            f.truncate()
            f.close()

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
        LOG.info("Access data looks valid.")
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
        out = subprocess.call(
            "sudo iptables -L -n -t nat --line-numbers | grep MCV_instance",
            shell=True) == 1
        if out:
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
        LOG.info("Reverting changes needed for access to admin network")
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
        self.restore_hosts_config()
