import re
import subprocess
import time


class AccessSteward(object):

    ipv4 = re.compile(r"""^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)
                          {3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$""",
                      re.X)

    def __init__(self):
        self.access_data = {"controller_ip": None,
                            "instance_ip": None,
                            "os_username": None,
                            "os_tenant_name": None,
                            "os_password": None,
                            "auth_endpoint_ip": None,
    }

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

    def _request_controller_ip(self):
        msg = "Please enter the IP address of cloud controller: "
        controller_address = self._request_ip(msg)
        self.access_data["controller_ip"] = controller_address

    def _request_auth_endpoint_ip(self):
        msg = "Please enter the IP address of auth endpoint: "
        controller_address = self._request_ip(msg)
        self.access_data["auth_endpoint_ip"] = controller_address

    def _request_cloud_credentials(self):
        username = raw_input("Please provide administrator username: ")
        self.access_data["os_username"] = username
        password = raw_input("Please provide administrator password: ")
        self.access_data["os_password"] = password
        tenant = raw_input("Please provide tenant name: ")
        self.access_data["os_tenant_name"] = tenant

    def set_access_data(self):
        self._request_instance_ip()
        self._request_controller_ip()
        self._request_auth_endpoint_ip()
        self._request_cloud_credentials()

    def _check_docker_images(self):
        res = subprocess.Popen(["docker", "ps"],
                               stdout=subprocess.PIPE).stdout.read()
        if res.count('\n') < 2:
            answer = raw_input("Looks like the containers are not ready."
                " Please choose between 1) waiting on containers setup"
                " 2) aborting action: ")
            if answer == '1':
                time.sleep(30)  # magic, yet I'd rather have kept it
                return self._check_docker_images()
            else:
                return False
        return True

    def _verify_access_data_is_set(self):
        for key, value in self.access_data.iteritems():
            if value is None:
                getattr(self, "_request_" + key)()

    def _request_os_username(self):
        username = raw_input("Please provide administrator username: ")
        self.access_data["os_username"] = username

    def _request_os_password(self):
        password = raw_input("Please provide administrator password: ")
        self.access_data["os_password"] = password

    def _request_os_tenant_name(self):
        tenant = raw_input("Please provide tenant name: ")
        self.access_data["os_tenant_name"] = tenant

    def _extract_rally_container_id(self, output):
        output = output.split('\n')
        for line in output:
            if re.search('mcv-rally', line) is not None:
                self.rally_container_id = line[0:12]
                return

    def _extract_shaker_container_id(self, output):
        output = output.split('\n')
        for line in output:
            if re.search('mcv-shaker', line) is not None:
                self.shaker_container_id = line[0:12]
                return

    def _stop_rally_container(self):
        print "Bringing down container with rally"
        res = subprocess.Popen(["docker", "stop", self.rally_container_id],
                               stdout=subprocess.PIPE).stdout.read()
        return res

    def _start_rally_container_(self):
        print "Bringing up rally container with credentials"
        images = subprocess.Popen(["docker", "images"],
            stdout=subprocess.PIPE).stdout.read().split('\n')
        for line in images:
            if re.search('mcv-rally', line) is not None:
                res = subprocess.Popen(["docker", "run", "-d", "-P=true",
                    "-p", "6000:6000", "-e", "OS_AUTH_URL=http://" +
                    self.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
                    "-e", "OS_TENANT_NAME=" +
                    self.access_data["os_tenant_name"],
                    "-e", "OS_USERNAME=" + self.access_data["os_username"],
                    "-e", "OS_PASSWORD=" + self.access_data["os_password"],
                    "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
                    "-it", "mcv-rally"], stdout=subprocess.PIPE).stdout.read()
                return
        self._check_and_fix_iptables_rule()

    def _start_shaker_container(self):
        images = subprocess.Popen(["docker", "images"],
            stdout=subprocess.PIPE).stdout.read().split('\n')
        for line in images:
            if re.search('mcv-shaker', line) is not None:
                res = subprocess.Popen(["docker", "run", "-d", "-P=true",
                    "-p", "5999:5999", "-e", "OS_AUTH_URL=http://" +
                    self.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
                    "-e", "OS_TENANT_NAME=" +
                    self.access_data["os_tenant_name"],
                    "-e", "OS_USERNAME=" + self.access_data["os_username"],
                    "-e", "OS_PASSWORD=" + self.access_data["os_password"],
                    "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
                    "-it", "mcv-shaker"], stdout=subprocess.PIPE).stdout.read()
                return

    def _start_rally_container(self):
        images = subprocess.Popen(["docker", "images"],
            stdout=subprocess.PIPE).stdout.read().split('\n')
        for line in images:
            if re.search('mcv-rally', line) is not None:
                res = subprocess.Popen(["docker", "run", "-d", "-P=true",
                    "-p", "6000:6000", "-it", "mcv-rally"],
                    stdout=subprocess.PIPE).stdout.read()
                return

    def _verify_rally_container_is_up(self):
        res = subprocess.Popen(["docker", "ps"],
            stdout=subprocess.PIPE).stdout.read()
        rally_detector = re.compile("mcv-rally")
        if re.search(rally_detector, res) is not None:
            self._extract_rally_container_id(res)
        else:
            self._start_rally_container()
            time.sleep(10)  # we are in no hurry today
            return self._verify_rally_container_is_up()

    def _verify_shaker_container_is_up(self):
        res = subprocess.Popen(["docker", "ps"],
            stdout=subprocess.PIPE).stdout.read()
        shaker_detector = re.compile("mcv-shaker")
        if re.search(shaker_detector, res) is not None:
            self._extract_shaker_container_id(res)
        else:
            self._start_shaker_container()
            time.sleep(10)  # no, we are not in a hurry today
            return self._verify_shaker_container_is_up()

    def check_containers_are_up(self):
        self._verify_rally_container_is_up()
        self._verify_shaker_container_is_up()

    def _run_nova_command_in_container(self, command):
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
        self._verify_rally_container_is_up()
        self._verify_access_data_is_set()
        print "Trying to authenticate with OpenStack using provided"\
              " credentials..."
        res = self._run_nova_command_in_container("nova list")
        erconref = re.compile('ERROR \(ConnectionRefused\)')
        erepnotf = re.compile('ERROR \(EndpointNotFound\)')
        erecreds = re.compile('ERROR \(Unauthorized\)')
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
            if decision == '1':
                self._request_os_username()
            elif decision == '2':
                self._request_os_password()
            elif decision == '3':
                self._request_os_tenant()
            else:
                print "This doesn\'t look like a valid option."\
                      " Let\'s try once again."
            return self.check_and_fix_access_data()
        print "Access data looks valid."
        return True

    def check_and_fix_floating_ips(self):
        res = self._run_nova_command_in_container("nova floating-ip-list")
        res = res.split('\r\n')[3:-2]
        free_addresses_counter = 0
        for resource in res:
            resource = resource.replace(' ', '')
            resource = resource.split('|')
            if resource[3] == '-':
                free_addresses_counter += 1
        if free_addresses_counter >= 2:
            print "Apparently there is enough floating ips"
            return
        else:
            fresh_floating_ip = self._run_nova_command_in_container(
                                    "nova floating-ip-create")
            ernotfound = re.compile('ERROR \(NotFound\)')
            if re.search(ernotfound, fresh_floating_ip) is not None:
                print "Apparently the cloud is out of free floating ip"
                print "You might experience problems with running some tests"
                return
            return self.check_and_fix_floating_ips()
        return res

    def check_docker_images(self):
        res = subprocess.Popen(["docker", "images"],
            stdout=subprocess.PIPE).stdout.read()
        res = res.split('\n')
        valid_containers = 0
        for r in res:
            if re.search('mcv-rally', r) is not None or\
                    re.search('mcv-shaker', r) is not None:
                valid_containers += 1
        if valid_containers == 2:
            print "All images seem to be in place"
        else:
            print "Some images are still not here. Waiting for them"
            time.sleep(300)
            self.check_docker_images()

    def _check_and_fix_flavor(self):
        res = self._run_nova_command_in_container("nova flavor-list")
        res = res.split('\r\n')[3:-2]
        for flavor in res:
            flavor = flavor.replace(' ', '').split('|')
            if flavor[2] == 'm1.nano':
                print "Proper flavor for rally has been found"
                return
        print "Apparently there is no flavor suitable for running rally"
        self._run_nova_command_in_container(
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
            cmd  = "docker inspect -f '{{.Id}}' %s" % self.rally_container_id
            p = subprocess.check_output(cmd, shell=True,
                                        stderr=subprocess.STDOUT)
            test_location = "existing.json"
            cmd = r"cp "+test_location+\
            " /var/lib/docker/aufs/mnt/%s/home/rally" %\
            p.rstrip('\n')
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

    def _check_mcv_secgroup(self):
        res = self._run_nova_command_in_container(
                  "nova secgroup-list").split('\r\n')[3:-2]
        for group in res:
            group = group.replace(' ', '').split('|')
            if group[2] == 'mcv-special-group':
                return
        self._run_nova_command_in_container(
            "nova secgroup-create mcv-special-group mcvgroup")
        self._run_nova_command_in_container(
            "nova secgroup-add-rule mcv-special-group tcp 5999 5999 0.0.0.0/0")
        self._run_nova_command_in_container(
            "nova secgroup-add-rule mcv-special-group tcp 6000 6000 0.0.0.0/0")
        res = self._run_nova_command_in_container(
            "nova list").split('\r\n')[3:-2]
        for vm in res:
            vm = vm.replace(' ', '').split('|')
            if vm[-2].find(self.access_data["instance_ip"]) > -1:
                instance_name = vm[2]
        self._run_nova_command_in_container(
            "nova add-secgroup " + instance_name + " mcv-special-group")

    def _check_rally_setup(self):
        self._check_and_fix_flavor()
        self._rally_deployment_check()

    def _check_shaker_setup(self):
        res = subprocess.Popen(["docker", "exec", "-it",
                self.shaker_container_id, "shaker-image-builder",
                "--image-builder-template",
                "/etc/shaker/shaker/resources/image_builder_template.yaml"],
                stdout=subprocess.PIPE).stdout.read()

    def check_containers_set_up_properly(self):
        self._check_rally_setup()
        self._check_shaker_setup()

    def _fake_creds(self):
        self.access_data = {"controller_ip": '172.16.57.37',
                            "instance_ip": '172.16.57.41',
                            "os_username": 'admin',
                            "os_tenant_name": 'admin',
                            "os_password": 'admin',
                            "auth_endpoint_ip": '172.16.57.35',
    }

    def _check_and_fix_iptables_rule(self):
        print "Make sure your controller is set up properly. Like this:"
        print "ssh -f -N -L ${controller_ip}:7654:${keystone_private_endpoint_ip}:35357 localhost"
        print "iptables -I INPUT 1 -p tcp -m tcp --dport 7654 -j ACCEPT"
        raw_input("(Press enter when you are sure)")
        res = subprocess.Popen(["sudo", "iptables", "-t", "nat", "-I",
                                "PREROUTING", "1", "-d", "192.168.0.2", "-p",
                                "tcp", "--dport", "35357", "-j", "DNAT",
                                "--to-destination", "172.16.57.37:7654"],
                               stdout=subprocess.PIPE).stdout.read()

    def create_rally_json(self):
        template = """ {
            "type": "ExistingCloud",
            "auth_url": "http://%s:5000/v2.0/",
            "region_name": "RegionOne",
            "endpoint_type": "public",
            "admin": {
                "username": "%s",
                "password": "%s",
                "tenant_name": "%s"
                },
            "https_insecure": False,
            "https_cacert": "",
            }""" % (self.access_data["auth_endpoint_ip"],
                    self.access_data["os_username"],
                    self.access_data["os_password"],
                    self.access_data["os_tenant_name"])
        f = open("existing.json", "w")
        f.write(template)
        f.close()

    def check_and_fix_environment(self):
        self.check_docker_images()
        self.check_and_fix_access_data()
        self.create_rally_json()
        self._check_mcv_secgroup()
        self._stop_rally_container()
        self._start_rally_container_()
        self.check_containers_are_up()
        self.check_containers_set_up_properly()
        self.check_and_fix_floating_ips()
