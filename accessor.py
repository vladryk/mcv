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
from common.config import DEBUG
from common import clients as Clients
import operator
import re
import subprocess
import sys
import time
import paramiko
from paramiko import client

from novaclient import exceptions as nexc

import utils

from logger import LOG
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
    ips = re.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"\
                     "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
                     re.X)

    # Unassigned floating ip hack
    ips2 = re.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"\
                     "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\ \|\ -",
                     re.X)

    def __init__(self, config):
        self.access_data = {"controller_ip": None,
                            "instance_ip": None,
                            "os_username": None,
                            "os_tenant_name": None,
                            "os_password": None,
                            "auth_endpoint_ip": None,
                            "nailgun_host": None,
                            "region_name": None,
                            "cluster_id": None,
                            "auth_fqdn": None,}

        self.config = config
        for key in self.access_data.keys():
             try:
                 self.access_data[key] = self.config.get('basic', key)
             except NoOptionError:
                 LOG.warning('Option {opt} missed in config file. It may be dangerous'.format(
                     opt=key))

        self.novaclient = None
        self.keystoneclient = None

        #@albartash: hard hack
        self.os_data = {'username': self.access_data['os_username'],
                        'password': self.access_data['os_password'],
                        'tenant_name': self.access_data['os_tenant_name'],
                        'auth_url': self.config.get('basic', 'auth_protocol') +
                                    "://" +
                                    str(self.access_data['auth_endpoint_ip']) +
                                    ":5000/v2.0",
                        'insecure': True,
                        'region_name': self.access_data['region_name'],
                        'project_id': self.access_data['os_tenant_name'], # nova tenant
                        'api_key': self.access_data['os_password'] , # nova and cinder passwd
                        'debug': DEBUG
                       }


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
        for key, value in self.access_data.iteritems():
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
        """Get Private endpoint-ip from keystone (it is internalURL in keystone).
        InternalURL - is always the same for any service.
        """
        full_url = self._get_keystoneclient().service_catalog.get_endpoints('identity')['identity'][0]['internalURL']
        return str(full_url.split('/')[2].split(':')[0])

    def _make_sure_controller_name_could_be_resolved(self):
        a_fqdn = self.access_data["auth_fqdn"]
        if a_fqdn != "":
            LOG.debug("FQDN is specified.")
            f = open('/etc/hosts', 'a+r')
            for line in f.readlines():
                if line.find(a_fqdn) != -1:
                    return
            f.write(self.access_data['auth_endpoint_ip'] + ' ' + self.access_data['auth_fqdn'] +"\n")
            f.close()

    def check_and_fix_access_data(self):
        if not self._verify_access_data_is_set():
            return False

        LOG.debug("Trying to authenticate with OpenStack using provided credentials...")
        self._make_sure_controller_name_could_be_resolved()
        try:
            res = self._get_novaclient().servers.list()
        except nexc.ConnectionRefused:
            LOG.error("Apparently authentication endpoint address is not valid."
                      "Current value is %s" % self.access_data["auth endpoint"])
            return False
        except nexc.Unauthorized:
            LOG.error("Apparently OS user credentials are incorrect.\n"
                      "Current os-username is: %s\n"
                      "Current os-password is: %s \n"
                      "Current os-tenant is: %s \n"
                      % (self.access_data["os_username"],
                         self.access_data["os_password"],
                         self.access_data["os_tenant_name"]
                         ))
            return False
        LOG.info("Access data looks valid.")
        return True

    def check_and_fix_floating_ips(self):
        res = self._get_novaclient().floating_ips.list()
        if len(res) >= 2:
            LOG.debug( "Apparently there is enough floating ips")
        else:
            LOG.info( "Need to create a floating ip")
            try:
                fresh_floating_ip = self._get_novaclient().floating_ips.create()
            except Exception:
                LOG.warning( "Apparently the cloud is out of free floating ip. "
                             "You might experience problems with running some tests")

                return
            return self.check_and_fix_floating_ips()

    def check_docker_images(self):
        res = subprocess.Popen(
                ["docker", "images"],
                stdout=subprocess.PIPE,
                preexec_fn=utils.ignore_sigint).stdout.read()
        flags = map(lambda x: re.search(x, res) is not None, image_names)
        if reduce(operator.mul, flags):
            LOG.debug( "All images seem to be in place")
        else:
            LOG.warning( "Some images are still not here. Waiting for them")
            time.sleep(300)
            self.check_docker_images()

    def _check_and_fix_iptables_rule(self):
        # Since this is needed for both Rally and Shaker it is better to keep
        # it in accessor.
        # Let's patch cloud controller first. Be prepared to provide root
        # access to the controller. Mwa-ha-ha.
        # TODO: divide this some day
        # TODO: this might change so it is much wiser to do actual check
        keystone_private_endpoint_ip = self._get_private_endpoint_ip()
        port_substitution = {"cnt_ip": self.access_data["controller_ip"],
                             "kpeip": keystone_private_endpoint_ip,
                             }
        mk_rule = "iptables -I INPUT 1 -p tcp -m tcp --dport 7654 -j ACCEPT -m comment --comment \'MCV_tunnel\'"
        rkname = "remote_mcv_key"
        mk_port = "ssh -o PreferredAuthentications=publickey -o "\
                  "StrictHostKeyChecking=no -i " + rkname +" -f -N -L "\
                  "%(cnt_ip)s:7654:%(kpeip)s:35357 localhost" %\
                  port_substitution

        ssh = client.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(hostname="%(controller_ip)s" % self.access_data,
                        username=self.config.get('basic', 'controller_uname'),
                        password=self.config.get('basic', 'controller_pwd'))
        except NoOptionError:
            LOG.critical("SSH authorization credentials are not defined in the config")
            sys.exit(1)
        except paramiko.ssh_exception.AuthenticationException:
            LOG.critical("Can not access controller via ssh with provided credentials!")
            sys.exit(1)

        stdin, stdout, stderr = ssh.exec_command("ssh-keygen -f" + rkname + " -N '' > /dev/null 2>&1")
        # TODO: ok, this should not be done by sleeping
        time.sleep(3)
        stdin, stdout, stderr = ssh.exec_command("cat " + rkname + ".pub >> .ssh/authorized_keys")
        time.sleep(3)
        stdin, stdout, stderr = ssh.exec_command("iptables -L -n")
        if stdout.read().find("MCV_tunnel") == -1:
            LOG.debug("There is no rule in controller's iptables for proper forwarding! Have to add one")
            stdin, stdout, stderr = ssh.exec_command( mk_rule)
        else:
            LOG.debug("Controller's iptables rule seems to be in place")

        result = None
        while result is None:
            stdin, stdout, stderr = ssh.exec_command("ps aux")
            result = re.search("ssh.*35357", stdout.read())
            if result is None:
                LOG.debug("Apparently port forwarding on the conntroller is not set up properly")
                time.sleep(3)
                stdin, stdout, stderr = ssh.exec_command(mk_port)
                time.sleep(5)
            else:
                LOG.debug( "Apparently port forwarding on the conntroller is set")
        stdin, stdout, stderr = ssh.exec_command("rm " + rkname + "*")

        res = subprocess.Popen(["sudo", "iptables", "-t", "nat", "-L -n", ],
                                shell=False, stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                preexec_fn=utils.ignore_sigint).stdout.read()
        if re.search("DNAT.*7654\n", res) is not None:
            # leave slowly, don't wake it up
            LOG.debug("Local iptables rule is set.")
            return
        out = subprocess.call("sudo iptables -L -n -t nat --line-numbers | grep MCV_instance", shell=True) == 1
        if out:
            res = subprocess.Popen(["sudo", "iptables", "-t", "nat", "-I",
                                    "PREROUTING", "1", "-d", self._get_private_endpoint_ip(), "-p",
                                    "tcp", "--dport", "35357", "-j", "DNAT",
                                    "--to-destination", "%s:7654" %\
                                    self.access_data["controller_ip"],
                                    "-m", "comment", "--comment", "\'MCV_instance\'"],
                                    stdout=subprocess.PIPE,
                                    preexec_fn=utils.ignore_sigint).stdout.read()
            LOG.debug("Now local iptables rule is set.")

    def stop_forwarding(self):
        #TODO: do this in a separate method
        LOG.info("Reverting changes needed for access to admin network")
        ssh = client.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(hostname="%(controller_ip)s" % self.access_data,
                        username=self.config.get('basic', 'controller_uname'),
                        password=self.config.get('basic', 'controller_pwd'))#"r00tme")
        except:
            LOG.critical("Oh noes, ssh is broken")
            return
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep '[s]sh -o Preferred' | awk '{ print $2 }'| xargs kill")
        stdin, stdout, stderr = ssh.exec_command("iptables -L -n --line-numbers | grep MCV_tunnel | awk '{print $1}' | xargs iptables -D INPUT")
        out = subprocess.call("sudo iptables -L -n -t nat --line-numbers | grep MCV_instance | awk '{print $1}' | tac | xargs -l sudo iptables -t nat -D PREROUTING", shell=True)

    def check_computes(self):
        services = self._get_novaclient().services.list()
        self.compute = 0
        for service in services:
            if service.binary == 'nova-compute':
                self.compute += 1
        LOG.debug("Found " +  str(self.compute) + " computes.")

    def check_mcv_secgroup(self):
        LOG.debug("Checking for proper security group")
        res = self._get_novaclient().security_groups.list()
        for r in res:
            if r.name == 'mcv-special-group':
                LOG.debug("Has found one")
                # TODO: by the way, a group could exist while being not
                # attached. It is wise to check this.
                return
        LOG.debug("Nope. Has to create one")
        mcvgroup = self._get_novaclient().security_groups.\
                       create('mcv-special-group', 'mcvgroup')
        self._get_novaclient().security_group_rules.\
                       create(parent_group_id=mcvgroup.id, ip_protocol='tcp',
                              from_port=5999, to_port=5999, cidr='0.0.0.0/0')
        self._get_novaclient().security_group_rules.\
                       create(parent_group_id=mcvgroup.id, ip_protocol='tcp',
                              from_port=6000, to_port=6000, cidr='0.0.0.0/0')
        self._get_novaclient().security_group_rules.\
                       create(parent_group_id=mcvgroup.id, ip_protocol='tcp',
                              from_port=6001, to_port=6001, cidr='0.0.0.0/0')
        LOG.debug("Finished creating a group and adding rules")
        servers = self._get_novaclient().servers.list()
        # TODO: this better be made pretty
        for server in servers:
            addr = server.addresses
            for network, ifaces in addr.iteritems():
                for iface in ifaces:
                    if iface['addr'] == self.access_data["instance_ip"]:
                        LOG.debug("Found a server to attach the new group to")
                        server.add_security_group(mcvgroup.id)
        LOG.debug("And they lived happily ever after")

    def check_and_fix_environment(self, required_containers, no_tunneling=False):
        self.required_containers = required_containers
        self.check_docker_images()
        if not self.check_and_fix_access_data():
            return False
        self.check_mcv_secgroup()
        if not no_tunneling:
            LOG.info("Port forwarding will be done automatically")
            self._check_and_fix_iptables_rule()
        else:
            LOG.info("Port forwarding will not be done")
        self.check_and_fix_floating_ips()
        return True
