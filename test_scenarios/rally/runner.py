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
import logging
import re
import subprocess
import sys
import time
from test_scenarios import runner
try:
    import json
except:
    import simplejson as json

import utils

# Needed for Rally. Whoever finds this after Rally is fixed please don't
# hesitate to remove
from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import threading

nevermind = None

config = ConfigParser.ConfigParser()
default_config = "etc/mcv.conf"
LOG = logging

rally_json_template = """{
"type": "ExistingCloud",
"auth_url": "%(auth_protocol)s://%(ip_address)s:5000/v2.0/",
"region_name": "%(region)s",
"endpoint_type": "public",
"admin": {
    "username": "%(uname)s",
    "password": "%(upass)s",
    "tenant_name": "%(uten)s"
    },
"https_insecure": %(insecure)s,
"https_cacert": "",
}"""


class RallyRunner(runner.Runner):

    valid_staarten = ("yaml", "json")

    def __init__(self, config_location=None, *args, **kwargs):
        super(RallyRunner, self).__init__()
        self.config = kwargs["config"]
        self.identity = "rally"
        self.config_section = "rally"
        self.test_failures = []  # this object is supposed to live for one run
                                 # so let's leave it as is for now.

    def _it_ends_well(self, something):
        if something.split('.')[-1] in self.valid_staarten:
            return True
        return False

    def _setup_rally(self):
        # since it is assumed that we are running a preconfigured rally
        # nothing is done here.
        # However one might face a situation when rally is not configured.
        # the easiest way to configure it is to execute the following commands:
        # > source openrc admin admin
        # > rally deployment create --fromenv --name=existing
        # As this might not work all the time it is advised to consider another
        # option namely setting up rally environment from a json file with
        # appropriate credentials:
        # > rally deployment create --file=existing.json --name=existing
        # Corresponding json file with credentials should look like this:
        # {
        #   "type": "ExistingCloud",
        #   "auth_url": "http://example.net:5000/v2.0/",
        #   "region_name": "RegionOne",
        #   "endpoint_type": "public",
        #   "admin": {
        #     "username": "admin",
        #     "password": "myadminpass",
        #     "tenant_name": "demo"
        #   }
        #}
        pass

    def _evaluate_task_result(self, task, resulting_dict):
        # logs both success and problems in an uniformely manner.
        if resulting_dict['sla'][0]['success'] == True:
            LOG.info("Task %s has completed successfully." % task)
        else:
            LOG.warning("Task %s has failed with the following error: %s" % (task, resulting_dict['result']))
            return False
        return True

    def _get_task_path(self, task):
        # a quick and dirty way to find a task
        return 'test_scenarios/rally/tests/%s' % task

    def _run_rally(self, task):
        LOG.debug("Running task %s" % task)
        # important: at this point task must be transformed to a full path
        path_to_task = self._get_task_path(task)
        cmd = "rally task start %s" % path_to_task
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        # here out is in fact a command which can be run to obtain task resuls
        # thus it is returned directly.
        out = p.split('\n')[-4].lstrip('\t')
        return out

    def _get_task_result(self, task_id):
        # this function is not using task id contrary to what it says,  but in
        # current state of affair direct command produced by rally. task_id
        # is left as is for now, but will be moved in future.
        # if asked kindly rally just spits resulting json directly to stdout
        p = subprocess.check_output(task_id, shell=True,
                                    stderr=subprocess.STDOUT,
                                    preexec_fn=utils.ignore_sigint)
        res = json.loads(p)[0]  # actual test result as a dictionary
        return res

    def run_batch(self, tasks, *args, **kwargs):
        self._setup_rally()
        return super(RallyRunner, self).run_batch(tasks, *args, **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
        # runs a set of commands
        task_id = self._run_rally(task)
        task_result = self._get_task_result(task_id)
        if self._evaluate_task_result(task, task_result):
            return True
        else:
            self.test_failures.append(task)
            return False

class RallyOnDockerRunner(RallyRunner):

    def __init__(self, accessor, path, *args, **kwargs):
        self.config = kwargs["config"]
        self.path =  path
        self.container = None
        self.accessor = accessor
        self.test_storage_place = "/tmp/rally_tests"
        # Apparently rally can't use any images other than accessible via a url
        # Ok, then dumb-n-dumber game is on!
        LOG.debug("Now the part with the server")
        server = HTTPServer(('', 6666), SimpleHTTPRequestHandler)
        thread = threading.Thread(target = server.serve_forever)
        thread.daemon = True
        thread.start()
        # whoever reads this please remove this ^^^^ abomination at first
        # chance.
        super(RallyOnDockerRunner, self).__init__(*args, **kwargs)
        self.failure_indicator = 50

    def start_rally_container(self):
        LOG.debug( "Bringing up Rally container with credentials")
        protocol = self.config.get('basic', 'auth_protocol')
        add_host = ""
        if self.config.get("basic", "auth_fqdn") != '':
            add_host = "--add-host="+self.config.get("basic", "auth_fqdn") +":" + self.accessor.access_data["auth_endpoint_ip"]
        res = subprocess.Popen(["docker", "run", "-d", "-P=true",] +
            [add_host]*(add_host != "") +
            ["-p", "6000:6000", "-e", "OS_AUTH_URL=" + protocol +"://" +
            self.accessor.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
            "-e", "OS_TENANT_NAME=" +
            self.accessor.access_data["os_tenant_name"],
            "-e", "OS_USERNAME=" + self.accessor.access_data["os_username"],
            "-e", "OS_PASSWORD=" + self.accessor.access_data["os_password"],
            "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
            "-e", "OS_REGION_NAME=" + self.accessor.access_data["region_name"],
            "-t", "mcv-rally"], stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()
        self._verify_rally_container_is_up()
        # Since noone is actually giving a number two to how this is done
        # and some people actively deny the logic arrangement I'll do it this
        # dumb way.
        cmd = "docker inspect -f '{{.Id}}' %s" % self.container_id
        long_id = subprocess.check_output(
                cmd, shell=True,
                stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint).rstrip('\n')
        subprocess.Popen(["sudo", "cp", "-r",
                          "/etc/toolbox/rally/mcv/scenarios.consoler",
                          "/var/lib/docker/aufs/mnt/%(id)s/%(place)s"\
                          % {"id": long_id,
                          "place": self.test_storage_place}],\
                          stdout=subprocess.PIPE,
                          preexec_fn=utils.ignore_sigint).stdout.read()
        # here we fix glance image issues
        subprocess.Popen(["sudo", "chmod", "a+r",
                          "/etc/toolbox/rally/cirros-0.3.1-x86_64-disk.img"],
                         stdout=subprocess.PIPE,
                         preexec_fn=utils.ignore_sigint).stdout.read()

        subprocess.Popen(["sudo", "cp",
                          "/etc/toolbox/rally/cirros-0.3.1-x86_64-disk.img",
                          "/var/lib/docker/aufs/mnt/%(id)s/home/rally"\
                          % {"id": long_id, }],\
                          stdout=subprocess.PIPE,
                          preexec_fn=utils.ignore_sigint).stdout.read()

    def _verify_rally_container_is_up(self):
        self.verify_container_is_up("rally")

    def _check_and_fix_flavor(self):
        LOG.debug("Searching for proper flavor.")
        # Novaclient can't search flavours by name so manually search in list.
        res = self.accessor._get_novaclient().flavors.list()
        for f in res:
            if f.name == 'm1.nano':
                LOG.debug("Proper flavor for rally has been found")
                return
        LOG.debug("Apparently there is no flavor suitable for running rally. "\
                  "Creating one...")
        self.accessor._get_novaclient().flavors.create(name='m1.nano', ram=128,
                                                       vcpus=1, disk=1,
                                                       flavorid=42)
        time.sleep(3)
        return self._check_and_fix_flavor()

    def create_rally_json(self):
        auth_protocol = self.config.get("basic", "auth_protocol")
        credentials = {"ip_address": self.accessor.access_data["auth_endpoint_ip"],
                       "region": self.accessor.access_data["region_name"],
                       "uname": self.accessor.access_data["os_username"],
                       "upass": self.accessor.access_data["os_password"],
                       "uten": self.accessor.access_data["os_tenant_name"],
                       "auth_protocol": auth_protocol,
                       "insecure": "true" if auth_protocol == "https" else "false"}
        f = open("existing.json", "w")
        f.write(rally_json_template % credentials)
        f.close()

    def _rally_deployment_check(self):
        LOG.debug("Checking if Rally deployment is present.")
        res = subprocess.Popen(["docker", "exec", "-t",
                                self.container_id,
                                "rally", "deployment", "check"],
                               stdout=subprocess.PIPE,
                               preexec_fn=utils.ignore_sigint).stdout.read()
        if res.startswith("There is no"):
            LOG.debug("It is not. Trying to set up rally deployment.")
            cmd = "docker inspect -f '{{.Id}}' %s" % self.container_id
            long_id = subprocess.check_output(
                    cmd, shell=True,
                    stderr=subprocess.STDOUT,
                    preexec_fn=utils.ignore_sigint)
            self.create_rally_json()
            rally_config_json_location = "existing.json"
            cmd = r"cp " + rally_config_json_location +\
                " /var/lib/docker/aufs/mnt/%s/home/rally" %\
                long_id.rstrip('\n')
            try:
                p = subprocess.check_output(cmd, shell=True,
                                            stderr=subprocess.STDOUT,
                                            preexec_fn=utils.ignore_sigint)
            except:
                LOG.warning( "Failed to copy Rally setup  json.")
                sys.exit(1)
            res = subprocess.Popen(["docker", "exec", "-t",
                                   self.container_id, "rally",
                                   "deployment", "create",
                                   "--file=existing.json",
                                  # "--fromenv",
                                   "--name=existing"],
                                   stdout=subprocess.PIPE,
                                   preexec_fn=utils.ignore_sigint).stdout.read()
        else:
            LOG.debug("Seems like it is present.")

    def _check_rally_setup(self):
        self._check_and_fix_flavor()
        self._rally_deployment_check()

    def _setup_rally_on_docker(self):
        self.accessor.check_computes()
        self._verify_rally_container_is_up()
        self._check_rally_setup()

    def _prepare_certification_task_args(self):
        args = {}

        def _ADD(argname):
            args[argname] = self.config.get('certification', argname)

        _ADD("tenants_amount")
        _ADD("users_amount")
        _ADD("storage_amount")
        _ADD("computes_amount")
        _ADD("controllers_amount")
        _ADD("network_amount")

        args["smoke"] = True
        args["use_existing_users"] = False
        args["flavor_name"] = "m1.tiny"
        args["image_name"] = "^(cirros.*uec|TestVM)$"
        args["glance_image_location"] = ""
        args["service_list"] = self.config.get('certification', 'services'
                                              ).split(',')
        return args


    def _run_rally_on_docker(self, task, *args, **kwargs):
        if task == 'certification':
            # Certification Task requires another way to run
            LOG.info("Starting Rally Certification Task")
            task_args = self._prepare_certification_task_args()

            cmd = ("docker exec -t {container} rally task start"
                  " {location}/certification/openstack/task.yaml"
                  " --task-args '{task_args}'").format(
                      container = self.container_id,
                      location = self.test_storage_place,
                      task_args = json.dumps(task_args))
        else:
            LOG.info("Starting task %s" % task)
            cmd = "docker exec -t %(container)s rally task start"\
                  " %(location)s/%(task)s --task-args '{\"compute\":"\
                  "%(compute)s, \"concurrency\":%(concurrency)s,"\
                 "\"current_path\": %(location)s, \"gre_enabled\":%(gre_enabled)s,"\
                  "\"vlan_amount\":%(vlan_amount)s}'" %\
                  {"container": self.container_id,
                   "compute": kwargs["compute"],
                   "concurrency": kwargs["concurrency"],
                   "gre_enabled": kwargs["gre_enabled"],
                   "vlan_amount": kwargs["vlan_amount"],
                   "task": task,
                   "location": self.test_storage_place}

        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        original_output = p
        # here out is in fact a command which can be run to obtain task resuls
        # thus it is returned directly.
        out = p.split('\n')[-3].lstrip('\t')
        result_candidates = ('rally task results [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                             'rally -vd task detailed [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
        ret_val = None
        failed = False
        # ok, this has to be recosidered to make it less ugly
        for candidate in result_candidates:
            m = re.search(candidate, p)
            if m is not None:
                ret_val = m.group(0)
                if ret_val.find('detailed') != -1:
                    failed = True

        if out.startswith("For"):
            out = p.split('\n')[-3].lstrip('\t')
        LOG.debug("Received results for a task %s, those are '%s'" % (task,
                          out.rstrip('\r')))
        cmd = "docker exec -t %(container)s rally task report --out=%(task)s.html" \
              % {"container": self.container_id, "task": task}
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        cmd = "sudo cp /var/lib/docker/aufs/mnt/%(id)s/home/rally/%(task)s.html %(pth)s" \
              % {"id": p.rstrip('\n'), 'task': task, "pth": self.path}
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        return {'next_command': ret_val,
                'original output': original_output,
                'failed': failed}

    def _get_task_result_from_docker(self, task_id):
        LOG.debug("Retrieving task results for %s" % task_id)
        cmd = "docker exec -t %s %s" % (self.container_id, task_id)
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        if task_id.find("detailed") ==-1:
            res = json.loads(p)[0]  # actual test result as a dictionary
            return res
        else:
            return p.split('\n')[-4:-1]

    def run_batch(self, tasks, *args, **kwargs):
        self._setup_rally_on_docker()
        return super(RallyRunner, self).run_batch(tasks, *args,  **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
        # here be the fix for running rally in a docker container.
        # apparently we'll need something to set up rally inside docker.
        try:
            task_id = self._run_rally_on_docker(task, *args, **kwargs)
            if task_id['failed'] and len(task_id.keys()) == 1:
                LOG.warning("Task %s has failed for some instrumental issues" % (task))
                self.test_failures.append(task)
                return False
        except subprocess.CalledProcessError:
            LOG.error("Task %s has failed with: " % task, exc_info=True)
            self.test_failures.append(task)
            return False
        else:
            task_result = self._get_task_result_from_docker(task_id['next_command'])

            if type(task_result) == dict and\
                    self._evaluate_task_result(task, task_result):
                return True
            else:
                LOG.warning("Task %s has failed with %s" % (task, task_result))
                self.test_failures.append(task)
