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


import operator
import os
import re
import subprocess
import time

rally_json_template = """{
"type": "ExistingCloud",
"auth_url": "http://%(ip_address)s:5000/v2.0/",
"region_name": "RegionOne",
"endpoint_type": "public",
"admin": {
    "username": "%(uname)s",
    "password": "%(upass)s",
    "tenant_name": "%(uten)s"
    },
"https_insecure": False,
"https_cacert": "",
}"""

image_names = ("mcv-rally", "mcv-shaker", "mcv-ostf")

erconref = re.compile('ERROR \(ConnectionRefused\)')
erepnotf = re.compile('ERROR \(EndpointNotFound\)')
erecreds = re.compile('ERROR \(Unauthorized\)')
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

    def __init__(self):
        self.access_data = {"controller_ip": None,
                            "instance_ip": None,
                            "os_username": None,
                            "os_tenant_name": None,
                            "os_password": None,
                            "auth_endpoint_ip": None,
                            "nailgun_host": None,}

    def _validate_ip(self, ip):
        match = re.match(self.ipv4, ip)
        return  match is not None

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
            print "Address", address, "is unreachable."
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

    def _verify_access_data_is_set(self):
        for key, value in self.access_data.iteritems():
            if value is None:
                getattr(self, "_request_" + key)()

    def _extract_container_id(self, container_name, output):
        output = output.split('\n')
        container_name = "mcv-" + container_name
        for line in output:
            if re.search(container_name, line) is not None:
                container_id = line[0:12]
        return container_id

    def extract_rally_container_id(self, output):
        self.rally_container_id = self._extract_container_id("rally", output)

    def extract_shaker_container_id(self, output):
        self.shaker_container_id = self._extract_container_id("shaker", output)

    def extract_ostf_container_id(self, output):
        self.ostf_container_id = self._extract_container_id("ostf", output)

    def stop_rally_container(self):
        print "Bringing down container with rally"
        res = subprocess.Popen(["docker", "stop", self.rally_container_id],
                               stdout=subprocess.PIPE).stdout.read()
        return res

    def start_rally_container_(self):
        print "Bringing up Rally container with credentials"
        res = subprocess.Popen(["docker", "run", "-d", "-P=true",
            "-p", "6000:6000", "-e", "OS_AUTH_URL=http://" +
            self.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
            "-e", "OS_TENANT_NAME=" +
            self.access_data["os_tenant_name"],
            "-e", "OS_USERNAME=" + self.access_data["os_username"],
            "-e", "OS_PASSWORD=" + self.access_data["os_password"],
            "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
            "-it", "mcv-rally"], stdout=subprocess.PIPE).stdout.read()
        self._check_and_fix_iptables_rule()

    def start_shaker_container(self):
        print "Bringing up Shaker container with credentials"
        res = subprocess.Popen(["docker", "run", "-d", "-P=true",
            "-p", "5999:5999", "-e", "OS_AUTH_URL=http://" +
            self.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
            "-e", "OS_TENANT_NAME=" +
            self.access_data["os_tenant_name"],
            "-e", "OS_USERNAME=" + self.access_data["os_username"],
            "-e", "OS_PASSWORD=" + self.access_data["os_password"],
            "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
            "-it", "mcv-shaker"], stdout=subprocess.PIPE).stdout.read()

    def start_ostf_container(self):
        print "Bringing up OSTF container with credentials"
        res = subprocess.Popen(["docker", "run", "-d", "-P=true",
            "-p", "8080:8080", #"-e", "OS_AUTH_URL=http://" +
            #self.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
            "-e", "OS_TENANT_NAME=" +
            self.access_data["os_tenant_name"],
            "-e", "OS_USERNAME=" + self.access_data["os_username"],
            "-e", "OS_PASSWORD=" + self.access_data["os_password"],
            "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
            "-e", "NAILGUN_HOST=" + self.access_data["nailgun_host"],
            "-e", "NAILGUN_PORT=8000",
            "-e", "CLUSTER_ID=1",
            "-e", "OS_REGION_NAME=RegionOne",
            "-it", "mcv-ostf"], stdout=subprocess.PIPE).stdout.read()

    def start_rally_container(self):
        print "Bringing up Rally container"
        res = subprocess.Popen(["docker", "run", "-d", "-P=true",
            "-p", "6000:6000", "-it", "mcv-rally"],
            stdout=subprocess.PIPE).stdout.read()

    def _verify_container_is_up(self, container_name, extra=""):
        # container_name == rally, shaker, ostf
        print "Checking %s container..." % container_name,
        res = subprocess.Popen(["docker", "ps"],
            stdout=subprocess.PIPE).stdout.read()
        detector = re.compile("mcv-" + container_name)
        if re.search(detector, res) is not None:
            # This does not relly belongs here, better be moved someplace
            getattr(self, "extract_" + container_name + "_container_id")(res)
            print "ok"
        else:
            print "It has to be started.", extra
            getattr(self, "start_" + container_name + "_container")()
            time.sleep(10)  # we are in no hurry today
            return getattr(self, "_verify_" + container_name +
                           "_container_is_up")()

    def _verify_rally_container_is_up(self):
        self._verify_container_is_up("rally")

    def _verify_shaker_container_is_up(self):
        self._verify_container_is_up("shaker")

    def _verify_ostf_container_is_up(self):
        self._verify_container_is_up("ostf")

    def check_containers_are_up(self):
        self._verify_rally_container_is_up()
        self._verify_shaker_container_is_up()
        self._verify_ostf_container_is_up()

    def _run_os_command_in_container(self, command):
        # TODO: this cludge should be replaced with something more appropriate
        # in the future. Like actually packing some OS clients in our image.
        prelude = ["docker", "exec", "-it", self.rally_container_id]
        cmd_to_run = command.split(' ')
        authentication_stuff = [
               "--os-username=" + self.access_data["os_username"],
               "--os-tenant-name=" + self.access_data["os_tenant_name"],
               "--os-password=" + self.access_data["os_password"],
               "--os-auth-url=http://" + self.access_data["auth_endpoint_ip"] +
               ":5000/v2.0/", ]
        thing_to_do = (prelude + [cmd_to_run[0]] + authentication_stuff
                       + cmd_to_run[1:])
        res = subprocess.Popen(thing_to_do,
            stdout=subprocess.PIPE).stdout.read()
        return res

    def check_and_fix_access_data(self):
        def trap():
            print "This doesn\'t look like a valid option."\
                  " Let\'s try once again."
        self._verify_rally_container_is_up()
        self._verify_access_data_is_set()
        print "Trying to authenticate with OpenStack using provided"\
              " credentials..."
        res = self._run_os_command_in_container("nova list")
        if re.search(erconref, res) is not None or re.search(erepnotf, res)\
                is not None:
            print "Apparently authentication endpoint address is not valid."
            print "Curent value is", self.access_data["auth endpoint"]
            self._request_auth_endpoint_ip()
            return self.check_and_fix_access_data()
        if re.search(erecreds, res) is not None:
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
                           '2': self.request_os_password,
                           '3': self._request_os_tenant}
            ddispatcher.get(decision, trap)()
            return self.check_and_fix_access_data()
        print "Access data looks valid."
        return True

    def check_and_fix_floating_ips(self):
        res = self._run_os_command_in_container("nova floating-ip-list")
        if len(re.findall(self.ips2, res)) >= 2:
            print "Apparently there is enough floating ips"
        else:
            print "Need to create a floating ip"
            fresh_floating_ip = self._run_os_command_in_container(
                                    "nova floating-ip-create")
            if re.search(ernotfou, fresh_floating_ip) is not None:
                print "Apparently the cloud is out of free floating ip"
                print "You might experience problems with running some tests"
                return
            return self.check_and_fix_floating_ips()

    def check_docker_images(self):
        res = subprocess.Popen(["docker", "images"],
            stdout=subprocess.PIPE).stdout.read()
        flags = map(lambda x: re.search(x, res) is not None, image_names)
        if reduce(operator.mul, flags):
            print "All images seem to be in place"
        else:
            print "Some images are still not here. Waiting for them"
            time.sleep(300)
            self.check_docker_images()

    def _check_and_fix_flavor(self):
        res = self._run_os_command_in_container("nova flavor-list")
        if len(re.findall("m1.nano", res)) != 0:
            print "Proper flavor for rally has been found"
            return
        print "Apparently there is no flavor suitable for running rally."\
              " Creating one..."
        self._run_os_command_in_container(
            "nova flavor-create m1.nano 42 128 0 1")
        time.sleep(3)
        return self._check_and_fix_flavor()

    def _rally_deployment_check(self):
        res = subprocess.Popen(["docker", "exec", "-it",
                                self.rally_container_id,
                                "rally", "deployment", "check"],
                               stdout=subprocess.PIPE).stdout.read()
        if res.startswith("There is no"):
            print "Trying to set up rally deployment"
            cmd = "docker inspect -f '{{.Id}}' %s" % self.rally_container_id
            long_id = subprocess.check_output(cmd, shell=True,
                                        stderr=subprocess.STDOUT)
            rally_config_json_location = "existing.json"
            cmd = r"cp " + rally_config_json_location +\
                " /var/lib/docker/aufs/mnt/%s/home/rally" %\
                long_id.rstrip('\n')
            try:
                p = subprocess.check_output(cmd, shell=True,
                                            stderr=subprocess.STDOUT)
            except:
                print "Failed to copy"
            res = subprocess.Popen(["docker", "exec", "-it",
                                   self.rally_container_id, "rally",
                                   "deployment", "create",
                                   "--file=existing.json",
                                   "--name=existing"],
                                   stdout=subprocess.PIPE).stdout.read()

    def check_mcv_secgroup(self):
        res = self._run_os_command_in_container("nova secgroup-list")
        if re.search('mcv-special-group', res) is not None:
            return
        self._run_os_command_in_container(
            "nova secgroup-create mcv-special-group mcvgroup")
        self._run_os_command_in_container(
            "nova secgroup-add-rule mcv-special-group tcp 5999 5999 0.0.0.0/0")
        self._run_os_command_in_container(
            "nova secgroup-add-rule mcv-special-group tcp 6000 6000 0.0.0.0/0")

        res = self._run_os_command_in_container("nova list").split('\r\n')[3:-2]
        for vm in res:
            vm = vm.replace(' ', '').split('|')
            if vm[-2].find(self.access_data["instance_ip"]) > -1:
                instance_name = vm[2]
        self._run_os_command_in_container(
            "nova add-secgroup " + instance_name + " mcv-special-group")

    def _check_rally_setup(self):
        self._check_and_fix_flavor()
        self._rally_deployment_check()

    def _check_shaker_setup(self):
        print "Checking Shaker setup. If this is the first run of mcvconsoler"
        print "on this cloud go grab some coffee, it will take a while."
        res = subprocess.Popen(["docker", "exec", "-it",
                self.shaker_container_id, "shaker-image-builder",
                "--image-builder-template",
                "/etc/shaker/shaker/resources/image_builder_template.yaml"],
                stdout=subprocess.PIPE).stdout.read()

    def _do_config_extraction(self):
        print "Preparing OSTF"
        res = subprocess.Popen(["docker", "exec", "-it",
                self.ostf_container_id, "ostf-config-extractor", "-o", "ostfcfg.conf"],
                stdout=subprocess.PIPE).stdout.read()

    def _move_config_to_container(self):
        cmd = "docker inspect -f '{{.Id}}' %s" % self.ostf_container_id
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        to_move = "ostfcfg.conf"
        cmd = r"cp " + to_move +\
              " /var/lib/docker/aufs/mnt/%s/tmp/ostfcfg.conf" %\
              p.rstrip('\n')
        try:
            p = subprocess.check_output(cmd, shell=True,
                                        stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            if e.output.find('Permission denied') != -1:
                print " Got an access issue, you might want to run this "\
                      "as root ",
            return False
        else:
            return True

    def _check_ostf_setup(self):
        self._do_config_extraction()

    def check_containers_set_up_properly(self):
        self._check_rally_setup()
        self._check_shaker_setup()
        self._check_ostf_setup()

    def _fake_creds(self):
        self.access_data = {"controller_ip": '172.16.57.37',
                            "instance_ip": '172.16.57.41',
                            "os_username": 'admin',
                            "os_tenant_name": 'admin',
                            "os_password": 'admin',
                            "auth_endpoint_ip": '172.16.57.35',
                            "nailgun_host": '172.16.57.34',
                           }

    def _check_and_fix_iptables_rule(self):
        print "Make sure your controller is set up properly. Like this:"
        print "ssh -f -N -L ${controller_ip}:7654:${keystone_private_endpoint"\
              "_ip}:35357 localhost"
        print "iptables -I INPUT 1 -p tcp -m tcp --dport 7654 -j ACCEPT"
        raw_input("(Press enter when you are sure)")
        res = subprocess.Popen(["sudo", "iptables", "-t", "nat", "-I",
                                "PREROUTING", "1", "-d", "192.168.0.2", "-p",
                                "tcp", "--dport", "35357", "-j", "DNAT",
                                "--to-destination", "%s:7654" % self.access_data["controller_ip"]],
                               stdout=subprocess.PIPE).stdout.read()

    def create_rally_json(self):
        credentials = {"ip_address": self.access_data["auth_endpoint_ip"],
                       "uname": self.access_data["os_username"],
                       "upass": self.access_data["os_password"],
                       "uten": self.access_data["os_tenant_name"]}
        f = open("existing.json", "w")
        f.write(rally_json_template % credentials)
        f.close()

    def check_and_fix_environment(self):
        self.check_docker_images()
        self.check_and_fix_access_data()
        self.create_rally_json()
        self.check_mcv_secgroup()
        self.stop_rally_container()
        self.start_rally_container_()
        self.check_containers_are_up()
        self.check_containers_set_up_properly()
        self.check_and_fix_floating_ips()
