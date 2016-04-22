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


from ConfigParser import NoOptionError
import operator
import re
import socket
import subprocess
import time

import paramiko
from paramiko import client

from requests.exceptions import ConnectionError
from requests.exceptions import Timeout

from novaclient import exceptions as nexc

from mcv_consoler.common import clients as Clients
from mcv_consoler.common.config import DEBUG
from mcv_consoler.logger import LOG
from mcv_consoler import utils


LOG = LOG.getLogger(__name__)

image_names = ("mcv-rally", "mcv-shaker", "mcv-ostf")

erepnotf = re.compile('ERROR \(EndpointNotFound\)')
ernotfou = re.compile('ERROR \(NotFound\)')


class AccessSteward(object):

    # This one is good at address validation.
    ipv4 = re.compile(r"""^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)
                          {3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$""",
                      re.X)

    # This one is useful for checking if a string contains any IPs in it.
    ips = re.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
                     "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
                     re.X)

    # Unassigned floating ip hack
    ips2 = re.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
                      "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\ \|\ -",
                      re.X)

    def __init__(self, config):
        self.config = config

        def _GET(key, section="basic"):
            try:
                value = self.config.get(section, key)
            except NoOptionError:
                LOG.warning('Option {opt} missed in configuration file. '
                            'It may be dangerous'.format(opt=key))
                value = None
            return value

        self.novaclient = None
        self.keystoneclient = None

        protocol = _GET('auth_protocol')
        endpoint_ip = _GET('auth_endpoint_ip')
        auth_url_tpl = '{hprot}://{ip}:{port}/v{version}'
        tenant_name = _GET('os_tenant_name')
        password = _GET('os_password')

        self.os_data = {'username': _GET('os_username'),
                        'password': password,
                        'tenant_name': tenant_name,
                        'auth_fqdn': _GET('auth_fqdn'),

                        'ips': {
                            'controller': _GET('controller_ip'),
                            'endpoint': endpoint_ip,
                            'instance': _GET('instance_ip')},

                        'fuel': {
                            'nailgun_host': _GET('nailgun_host'),
                            'nailgun_port': 8000,
                            'cluster_id': _GET('cluster_id')},

                        'auth_url': auth_url_tpl.format(hprot=protocol,
                                                        ip=endpoint_ip,
                                                        port=5000,
                                                        version="2.0"),
                        'insecure': protocol == "https",
                        'region_name': _GET('region_name'),
                        # nova tenant
                        'project_id': tenant_name,
                        # nova and cinder passwd
                        'api_key': password,
                        'debug': DEBUG
                        }
        self.fresh_floating_ips = []

    def _validate_ip(self, ip):
        match = re.match(self.ipv4, ip)
        return match is not None

    def _address_is_reachable(self, address):
        responce = subprocess.Popen(
            ["/bin/ping", "-c1", "-w30", address],
            stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint)

        responce.communicate()[0]
        if responce.returncode == 0:
            return True
        return False

    def _verify_access_data_is_set(self):
        access = True
        for key, value in self.os_data.iteritems():
            if value is None:
                LOG.error('Config value %s is not set, please provide '
                          'required data in /etc/mcv/mcv.conf' % key)
                access = False
        return access

    def _verify_shaker_container_is_up(self):
        self._verify_container_is_up("shaker")

    def _get_novaclient(self):
        if self.novaclient is None:
            self.novaclient = Clients.get_nova_client(self.os_data)
        return self.novaclient

    def _get_keystoneclient(self):
        if self.keystoneclient is None:
            self.keystoneclient = Clients.get_keystone_client(self.os_data)
        return self.keystoneclient

    def _get_private_endpoint_ip(self):
        """Get Private endpoint-ip from Keystone.
        (it is internalURL in Keystone)
        InternalURL - is always the same for any service.
        """
        full_url = self._get_keystoneclient().service_catalog.get_endpoints(
            'identity')['identity'][0]['internalURL']
        return str(full_url.split('/')[2].split(':')[0])

    def _make_sure_controller_name_could_be_resolved(self):
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

    def _restore_hosts_config(self):
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
        if not self._verify_access_data_is_set():
            return False

        LOG.debug("Trying to authenticate with OpenStack "
                  "using provided credentials...")
        self._make_sure_controller_name_could_be_resolved()
        try:
            self._get_novaclient().authenticate()
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

    def check_and_fix_floating_ips(self):
        res = self._get_novaclient().floating_ips.list()
        if len(res) >= 2:
            LOG.debug("Apparently there is enough floating ips")
        else:
            LOG.info("Need to create a floating ip")
            try:
                self.fresh_floating_ips.append(
                    self._get_novaclient().floating_ips.create())
            except Exception as ip_e:
                LOG.warning("Apparently the cloud is out of free floating ip. "
                            "You might experience problems "
                            "with running some tests")
                LOG.debug("Error creating floating IP - %s" % str(ip_e))

                return
            return self.check_and_fix_floating_ips()

    def _delete_floating_ips(self):
        LOG.info("Removing created floating IPs")
        for floating_ip in self.fresh_floating_ips:
            try:
                floating_ip.delete()
            except Exception as e:
                LOG.debug("Error removing floating IP: %s" % e.message)

    def check_docker_images(self):
        res = subprocess.Popen(
            ["docker", "images"],
            stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()
        flags = map(lambda x: re.search(x, res) is not None, image_names)
        if reduce(operator.mul, flags):
            LOG.debug("All images seem to be in place")
        else:
            LOG.warning("Some images are still not here. Waiting for them")
            time.sleep(300)
            self.check_docker_images()

    def _check_and_fix_iptables_rule(self):
        # TODO(aovchinnikov): divide this some day
        # TODO(aovchinnikov): this might change so it is much wiser
        # to do actual check
        keystone_private_endpoint_ip = self._get_private_endpoint_ip()
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
                        username=self.config.get('basic', 'controller_uname'),
                        password=self.config.get('basic', 'controller_pwd'),
                        timeout=10)
        except NoOptionError:
            LOG.critical("SSH authorization credentials "
                         "are not defined in the config")
            return -1
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
            res = subprocess.Popen(["sudo", "iptables", "-t", "nat", "-I",
                                    "PREROUTING", "1", "-d",
                                    self._get_private_endpoint_ip(), "-p",
                                    "tcp", "--dport", "35357", "-j", "DNAT",
                                    "--to-destination", destination,
                                    "-m", "comment", "--comment",
                                    "\'MCV_instance\'"],
                                   stdout=subprocess.PIPE,
                                   preexec_fn=utils.ignore_sigint
                                   ).stdout.read()
            LOG.debug("Now local iptables rule is set.")

    def _stop_forwarding(self):
        # TODO(mcv-team): do this in a separate method
        LOG.info("Reverting changes needed for access to admin network")
        ssh = client.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(hostname=self.os_data["ips"]["controller"],
                        username=self.config.get('basic', 'controller_uname'),
                        password=self.config.get('basic', 'controller_pwd'))
        except Exception:
            LOG.critical("Oh noes, ssh is broken")
            return
        ssh.exec_command("ps aux | grep '[s]sh -o Preferred' | "
                         "awk '{ print $2 }'| xargs kill")
        ssh.exec_command("iptables -L -n --line-numbers | grep MCV_tunnel | "
                         "awk '{print $1}' | xargs iptables -D INPUT")
        subprocess.call("sudo iptables -L -n -t nat --line-numbers | "
                        "grep MCV_instance | awk '{print $1}' | tac | "
                        "xargs -l sudo iptables -t nat -D PREROUTING",
                        shell=True)

    def check_computes(self):
        services = self._get_novaclient().services.list()
        self.compute = 0
        for service in services:
            if service.binary == 'nova-compute':
                self.compute += 1
        LOG.debug("Found " + str(self.compute) + " computes.")

    def _is_cloud_instance(self):
        """Check if MCV image is running as an instance of a cloud that
        we are going to test.
        """

        all_floating_ips = self._get_novaclient().floating_ips.list()
        for ip_obj in all_floating_ips:
            if not ip_obj.instance_id:  # IP is not assigned to any instance
                continue
            if ip_obj.ip == self.os_data['ips']['instance']:
                return True

    def check_mcv_secgroup(self):
        if not self._is_cloud_instance():
            LOG.debug("Looks like mcv image is not running as an instance "
                      "of a cloud. Skipping creation of 'mcv-special-group'")
            return

        LOG.debug("Checking for proper security group")
        res = self._get_novaclient().security_groups.list()
        for r in res:
            if r.name == 'mcv-special-group':
                LOG.debug("Has found one")
                # TODO(ogrytsenko): a group could exist while being
                # not attached
                return

        LOG.debug("Nope. Has to create one")
        mcvgroup = self._get_novaclient().security_groups.create(
            'mcv-special-group', 'mcvgroup')
        LOG.debug("Created new security group 'mcv-special-group'. "
                  "Group id: %s" % mcvgroup.id)
        self._get_novaclient().security_group_rules.create(
            parent_group_id=mcvgroup.id, ip_protocol='tcp', from_port=5999,
            to_port=6001, cidr='0.0.0.0/0')

        LOG.debug("Finished creating a group and adding rules")

        LOG.debug('Trying to attach our mcv-instance to created group')
        servers = self._get_novaclient().servers.list()
        for server in servers:
            addr = server.addresses
            for network, ifaces in addr.iteritems():
                for iface in ifaces:
                    if iface['addr'] == self.os_data["ips"]["instance"]:
                        server.add_security_group(mcvgroup.id)
                        LOG.debug("Added security group {gid} to an "
                                  "instance {sid}".
                                  format(gid=mcvgroup.id, sid=server.id))
        LOG.debug("Finished setting-up security groups")

    def cleanup(self):
        self._stop_forwarding()
        self._delete_floating_ips()
        self._restore_hosts_config()

    def check_and_fix_environment(self, no_tunneling=False):
        self.check_docker_images()
        if not self.check_and_fix_access_data():
            self._restore_hosts_config()
            return False
        if self.check_mcv_secgroup() == -1:
            LOG.error('Cannot find MCV server by ip to add security group')
            self._restore_hosts_config()
            return False
        if not no_tunneling:
            LOG.info("Port forwarding will be done automatically")
            if self._check_and_fix_iptables_rule() == -1:
                self._restore_hosts_config()
                return False
        else:
            LOG.info("Port forwarding will not be done")
        self.check_and_fix_floating_ips()
        return True
