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


import ConfigParser
import operator
import logging
import re
import subprocess
import sys
import time
import paramiko
from paramiko import client

from novaclient import client as nova
from novaclient import exceptions as nexc


image_names = ("mcv-rally", "mcv-shaker", "mcv-ostf")

erepnotf = re.compile('ERROR \(EndpointNotFound\)')
ernotfou = re.compile('ERROR \(NotFound\)')


LOG = logging


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
                            "cluster_id": None,}
        self.config = config
        for key in self.access_data.keys():
             try:
                 self.access_data[key] = self.config.get('basic', key)
             except ConfigParser.NoOptionError:
                 pass
        self.novaclient = None

    def _validate_ip(self, ip):
        match = re.match(self.ipv4, ip)
        return match is not None

    def _address_is_reachable(self, address):
        responce = subprocess.Popen(["/bin/ping", "-c1", "-w30", address],
                                    stdout=subprocess.PIPE)
        responce.communicate()[0]
        if responce.returncode == 0:
            return True
        return False

    def _request_ip(self, message):
        address = ''
        msg = message
        while not self._validate_ip(address):
            address = raw_input(msg)
            if msg[0:4] != "This":
                msg = "This doesn't look like a valid IP address. " + msg
        if not self._address_is_reachable(address):
            LOG.warning("Address "+ address+ " is unreachable.")
            return self._request_ip(message)
        return address

    def _request_instance_ip(self):
        msg = "Please enter the IP address of MCV instance: "
        instance_address = self._request_ip(msg)
        self.access_data["instance_ip"] = instance_address

    def _request_nailgun_host(self):
        msg = "Please enter the IP address of nailgun host: "
        instance_address = self._request_ip(msg)
        self.access_data["nailgun_host"] = instance_address

    def _request_controller_ip(self):
        msg = "Please enter the IP address of cloud controller: "
        controller_address = self._request_ip(msg)
        self.access_data["controller_ip"] = controller_address

    def _request_auth_endpoint_ip(self):
        msg = "Please enter the IP address of auth endpoint: "
        controller_address = self._request_ip(msg)
        self.access_data["auth_endpoint_ip"] = controller_address

    def _request_os_username(self):
        username = raw_input("Please provide administrator username: ")
        self.access_data["os_username"] = username

    def _request_os_password(self):
        password = raw_input("Please provide administrator password: ")
        self.access_data["os_password"] = password

    def _request_os_tenant_name(self):
        tenant = raw_input("Please provide tenant name: ")
        self.access_data["os_tenant_name"] = tenant

    def _request_cluster_id(self):
        cluster_id = raw_input("Please provide cluster ID [1]: ")
        if cluster_id == "":
            cluster_id = "1"
        self.access_data["cluster_id"] = cluster_id

    def _verify_access_data_is_set(self):
        for key, value in self.access_data.iteritems():
            if value is None:
                getattr(self, "_request_" + key)()

    def _verify_shaker_container_is_up(self):
        self._verify_container_is_up("shaker")

    def _get_novaclient(self):
        # TODO: fix hardcoded nova API-version
        if self.novaclient is None:
            client = nova.Client(
                '2', username=self.access_data["os_username"],
                auth_url=self.config.get('basic', 'auth_protocol')+"://" + self.access_data["auth_endpoint_ip"] +
                         ":5000/v2.0/",
                api_key=self.access_data["os_password"],
                project_id=self.access_data["os_tenant_name"]
            )
            self.novaclient = client
        return self.novaclient

    def check_and_fix_access_data(self):
        def trap():
            print "This doesn\'t look like a valid option."\
                  " Let\'s try once again."
        self._verify_access_data_is_set()

        LOG.debug("Trying to authenticate with OpenStack using provided credentials...")
        try:
            res = self._get_novaclient().servers.list()
        except nexc.ConnectionRefused:
            print "Apparently authentication endpoint address is not valid."
            print "Curent value is", self.access_data["auth endpoint"]
            self._request_auth_endpoint_ip()
            return self.check_and_fix_access_data()
        except nexc.Unauthorized:
            print "Apparently user credentails are incorrect."
            print "Current os-username is:", self.access_data["os_username"]
            print "Current os-password is:", self.access_data["os_password"]
            print "Current os-tenant is:", self.access_data["os_tenant_name"]
            print "Please select which one you would like to change:"
            print "1) os-username,"
            print "2) os-password,"
            print "3) os-tenant."
            decision = raw_input()
            ddispatcher = {'1': self._request_os_username,
                           '2': self._request_os_password,
                           '3': self._request_os_tenant_name}
            ddispatcher.get(decision, trap)()
            return self.check_and_fix_access_data()
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
        res = subprocess.Popen(["docker", "images"],
            stdout=subprocess.PIPE).stdout.read()
        flags = map(lambda x: re.search(x, res) is not None, image_names)
        if reduce(operator.mul, flags):
            LOG.debug( "All images seem to be in place")
        else:
            LOG.warning( "Some images are still not here. Waiting for them")
            time.sleep(300)
            self.check_docker_images()


    def _fake_creds(self):
        self.access_data = {"controller_ip": '172.16.57.37',
                            "instance_ip": '172.16.57.42',
                            "os_username": 'admin',
                            "os_tenant_name": 'admin',
                            "os_password": 'admin',
                            "auth_endpoint_ip": '172.16.57.35',
                            "nailgun_host": '172.16.57.34',
                            "cluster_id": "2",
                           }

    def _check_and_fix_iptables_rule(self):
        # Since this is needed for both Rally and Shaker it is better to keep
        # it in accessor.
        # Let's patch cloud controller first. Be prepared to provide root
        # access to the controller. Mwa-ha-ha.
        # TODO: divide this some day
        # TODO: this might change so it is much wiser to do actual check
        keystone_private_endpoint_ip = "192.168.0.2"
        port_substitution = {"cnt_ip": self.access_data["controller_ip"],
                             "kpeip": keystone_private_endpoint_ip,
                             }
        mk_rule = "iptables -I INPUT 1 -p tcp -m tcp --dport 7654 -j ACCEPT"
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
        except ConfigParser.NoOptionError:
            LOG.critical("SSH authorization credentials are not defined in the config")
            sys.exit(1)
        except paramiko.ssh_exception.AuthenticationException:
            LOG.critical("Can not access controller via ssh with pro vided credentials!")
            sys.exit(1)
            pwd = raw_input("Please enter password for root@%(controller_ip)s"\
                            % self.access_data)
            # TODO: do this in a smart way
            try:
                ssh.connect(hostname="%(controller_ip)s" % self.access_data,
                            username="root", password=pwd)
                # TODO: add check for allowed methods
            except:
                LOG.error("Oh noes! Contoller authentication failure! Out of"\
                          " this Universe!")
                sys.exit(1)

        stdin, stdout, stderr = ssh.exec_command("ssh-keygen -f" + rkname + " -N '' > /dev/null 2>&1")
        # TODO: ok, this should not be done by sleeping
        time.sleep(3)
        stdin, stdout, stderr = ssh.exec_command("cat " + rkname + ".pub >> .ssh/authorized_keys")
        time.sleep(3)
        stdin, stdout, stderr = ssh.exec_command("iptables -L")
        if stdout.read().find("7654") == -1:
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

        res = subprocess.Popen(["sudo", "iptables", "-t", "nat", "-L", ],
                                shell=False, stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE).stdout.read()
        if re.search("DNAT.*7654\n", res) is not None:
            # leave slowly, don't wake it up
            LOG.debug("Local iptables rule is set.")
            return
        res = subprocess.Popen(["sudo", "iptables", "-t", "nat", "-I",
                                "PREROUTING", "1", "-d", "192.168.0.2", "-p",
                                "tcp", "--dport", "35357", "-j", "DNAT",
                                "--to-destination", "%s:7654" %\
                                self.access_data["controller_ip"]],
                                stdout=subprocess.PIPE).stdout.read()
        LOG.debug("Now local iptables rule is set.")

    def stop_forwarding(self):
        #TODO: do this in a separate m ethd
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
        stdin, stdout, stderr = ssh.exec_command("iptables -L --line-numbers | grep 7654 | awk '{print $1}' | xargs iptables -D INPUT")

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
        self.check_and_fix_access_data()
        self.check_mcv_secgroup()
        if not no_tunneling:
            LOG.info("Port forwarding will be done automatically")
            self._check_and_fix_iptables_rule()
        else:
            LOG.info("Port forwarding will not be done")
        self.check_and_fix_floating_ips()
