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

from common import clients as Clients
from common.errors import RallyError
import ConfigParser
import json
import logging
import os.path
import re
import subprocess
from plugins import runner
import time
import utils

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
        # this object is supposed to live for one run
        # so let's leave it as is for now.
        # TODO(albartash): todo smth with this property
        self.test_failures = []

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
        # }
        pass

    def _evaluate_task_result(self, task, resulting_dict):
        # logs both success and problems in an uniformely manner.
        if type(resulting_dict) != dict:
            LOG.debug(("Task {task} has failed with the following error: "
                      "{err}").format(task=task, err=resulting_dict))
            return False

        if not resulting_dict['sla']:
            err = resulting_dict['result'][0]['error']
            if err:
                LOG.warning(("Task {task} has failed with the error: "
                             "{err}").format(task=task,
                                             err=resulting_dict['result']))
                return False
            return True

        if resulting_dict['sla'][0]['success'] is True:
            LOG.info("Task %s has completed successfully." % task)
        else:
            LOG.warning(("Task {task} has failed with the following error: "
                         "{err}").format(task=task,
                                         err=resulting_dict['result']))
            return False
        return True

    def _get_task_path(self, task):
        # a quick and dirty way to find a task
        # TODO(albartash): refactor this damn
        return 'plugins/rally/tests/%s' % task

    def _run_rally(self, task):
        LOG.debug("Running task %s" % task)
        # important: at this point task must be transformed to a full path
        path_to_task = self._get_task_path(task)
        p = utils.run_cmd("rally task start " + path_to_task)

        # here out is in fact a command which can be run to obtain task resuls
        # thus it is returned directly.
        out = p.split('\n')[-4].lstrip('\t')
        return out

    def _get_task_result(self, task_id):
        # this function is not using task id contrary to what it says,  but in
        # current state of affair direct command produced by rally. task_id
        # is left as is for now, but will be moved in future.
        # if asked kindly rally just spits resulting json directly to stdout
        p = utils.run_cmd(task_id)
        try:
            res = json.loads(p)[0]  # actual test result as a dictionary
            return res
        except ValueError:
            LOG.error("Gotten not-JSON object. Please see mcv-log")
            LOG.debug("Not-JSON object: %s", p)
            return "Not-JSON object"

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
        self.path = path
        self.container = None
        self.accessor = accessor
        self.homedir = "/home/mcv/toolbox/rally"
        self.home = "/mcv"

        super(RallyOnDockerRunner, self).__init__(*args, **kwargs)
        self.failure_indicator = RallyError.NO_RUNNER_ERROR

        self.glanceclient = Clients.get_glance_client(accessor.os_data)
        self.neutronclient = Clients.get_neutron_client(accessor.os_data)

    def create_fedora_image(self):
        path = os.path.join(os.path.join(self.homedir, "images"),
                            'Fedora-Cloud-Base-23-20151030.x86_64.qcow2')
        i_list = self.glanceclient.images.list()
        image = False
        for im in i_list:
            if im.name == 'fedora':
                image = True
        if not image:
            self.glanceclient.images.create(name='fedora',
                                            disk_format="qcow2",
                                            is_public=True,
                                            container_format="bare",
                                            data=open(path))

    def get_network_router_id(self):
        networks = self.neutronclient.list_networks(
            **{'router:external': True})['networks']

        net_id = networks[0].get('id')
        routers = self.neutronclient.list_routers()['routers']
        rou_id = routers[0].get('id')
        return (net_id, rou_id)

    def start_container(self):
        LOG.debug("Starting Rally container")
        protocol = self.config.get('basic', 'auth_protocol')
        add_host = ""
        if self.config.get("basic", "auth_fqdn") != '':
            add_host = "--add-host=" + self.config.get("basic", "auth_fqdn")\
                       + ":" + self.accessor.access_data["auth_endpoint_ip"]

        res = subprocess.Popen(["docker", "run", "-d", "-P=true"] +
            [add_host]*(add_host != "") +
            ["-p", "6000:6000", "-e", "OS_AUTH_URL=" + protocol +"://" +
            self.accessor.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
            "-e", "OS_TENANT_NAME=" +
            self.accessor.access_data["os_tenant_name"],
            "-e", "OS_USERNAME=" + self.accessor.access_data["os_username"],
            "-e", "OS_PASSWORD=" + self.accessor.access_data["os_password"],
            "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
            "-e", "OS_REGION_NAME=" + self.accessor.access_data["region_name"],
            "-v", self.homedir+":"+self.home, "-w", self.home,
            "-t", "mcv-rally"], stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()

        LOG.debug('Finish starting Rally container. Result: {result}'.format(
                  result=str(res)))

        self._verify_rally_container_is_up()

        # here we fix glance image issues
        subprocess.Popen(["sudo", "chmod", "a+r",
                         self.homedir+"/images/cirros-0.3.1-x86_64-disk.img"],
                         stdout=subprocess.PIPE,
                         preexec_fn=utils.ignore_sigint).stdout.read()

    def _patch_rally(self):
        # Fix hardcoded timeout and siege regex
        # TODO(who posted?): Remove it with newest rally version (which??)
        rally_path = ('/usr/local/lib/python2.7/dist-packages/rally/plugins'
                      '/openstack/services/heat/main.py')
        cmd = ("docker exec -t {cid} sudo sed -i "
               "'53s/.*/            timeout=10000,/' {path}").format(
                   cid=self.container_id, path=rally_path)

        res = utils.run_cmd(cmd)
        siege_path = ('/usr/local/lib/python2.7/dist-packages/rally/plugins/'
                      'workload/siege.py')
        cmd = """docker exec -t %s sudo sed -i '26s/.*/SIEGE_RE = re.compile(r"^(Throughput|Transaction rate|Failed transactions|Successful transactions):\s+(\d+\.?\d*).*")' %s"""\
              % (self.container_id, siege_path)
        # TODO(who?): Found out how to pass re through sed
        template_path = os.path.join(self.home,
                                     '/tests/templates/wp_instances.yaml')

        LOG.debug('Start patching hosts')
        cmd = """docker exec -t %s sudo sed -i "61s/.*/            sudo sh -c 'echo %s %s >> \/etc\/hosts'/" %s""" % \
              (self.container_id,
               self.config.get("basic", 'auth_endpoint_ip'),
               self.config.get("basic", 'auth_fqdn'),
               template_path)

        res = utils.run_cmd(cmd)
        LOG.debug('Finish patching hosts. Result: {res}'.format(res=res))
        return

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
        LOG.debug("Apparently there is no flavor suitable for running rally. "
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
        f = open(os.path.join(self.homedir, "conf", "existing.json"), "w")
        f.write(rally_json_template % credentials)
        f.close()

    def _rally_deployment_check(self):
        LOG.debug("Checking if Rally deployment is present.")
        res = subprocess.Popen(["docker", "exec", "-t",
                                self.container_id,
                                "rally", "deployment", "check"],
                               stdout=subprocess.PIPE,
                               preexec_fn=utils.ignore_sigint).stdout.read()
        if res.startswith("There is no") or res.startswith('Deployment'):
            LOG.debug("It is not. Trying to set up rally deployment.")
            self.create_rally_json()
            res = subprocess.Popen(["docker", "exec", "-t",
                                    self.container_id, "rally",
                                    "deployment", "create",
                                    "--file="+os.path.join(self.home,
                                                           "conf",
                                                           "existing.json"),
                                    # "--fromenv",
                                    "--name=existing"],
                                   stdout=subprocess.PIPE,
                                   preexec_fn=utils.ignore_sigint
                                  ).stdout.read()
        else:
            LOG.debug("Seems like it is present.")

        LOG.debug('Trying to use Rally deployment')
        cmd = ("docker exec -t {cid} "
               "sudo rally deployment use existing").format(
               cid=self.container_id)
        LOG.debug('Run "{cmd}"'.format(cmd=cmd))
        p = utils.run_cmd(cmd)
        LOG.debug('Result: {res}'.format(res=p))

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

    def prepare_workload_task(self):
        self._patch_rally()
        self.create_fedora_image()
        net, rou = self.get_network_router_id()
        concurrency = self.config.get('workload', 'concurrency')
        instance_count = self.config.get('workload', 'instance_count')
        task_args = {
            'network_id': net,
            'router_id': rou,
            'concurrency': concurrency,
            'instance_count': instance_count
        }

        return task_args

    def _run_rally_on_docker(self, task, *args, **kwargs):
        if task == 'certification':
            # Certification Task requires another way to run
            LOG.info("Starting Rally Certification Task")
            task_args = self._prepare_certification_task_args()

            cmd = ("docker exec -t {container} sudo rally"
                   " --log-file {home}/log/rally.log --rally-debug"
                   " task start"
                   " {location}/certification/openstack/task.yaml"
                   " --task-args '{task_args}'").format(
                       home=self.home,
                       container=self.container_id,
                       location=os.path.join(self.home, "tests"),
                       task_args=json.dumps(task_args))

        elif task == 'workload.yaml':
            task_args = self.prepare_workload_task()

            cmd = ("docker exec -t {container} sudo rally"
                   " --log-file {home}/log/rally.log --rally-debug"
                   " task start"
                   " {location}/workload.yaml"
                   " --task-args '{task_args}'").format(
                      home = self.home,
                      container=self.container_id,
                      location=os.path.join(self.home, "tests"),
                      task_args=json.dumps(task_args))
        else:
            LOG.info("Starting task %s" % task)
            cmd = "docker exec -t %(container)s sudo rally"\
                  " --log-file %(home)s/log/rally.log --rally-debug"\
                  " task start"\
                  " %(location)s/%(task)s --task-args '{\"compute\":"\
                  "%(compute)s, \"concurrency\":%(concurrency)s,"\
                  "\"current_path\": %(location)s, \"gre_enabled\":%(gre_enabled)s,"\
                  "\"vlan_amount\":%(vlan_amount)s}'" %\
                  {"home": self.home,
                   "container": self.container_id,
                   "compute": kwargs["compute"],
                   "concurrency": kwargs["concurrency"],
                   "gre_enabled": kwargs["gre_enabled"],
                   "vlan_amount": kwargs["vlan_amount"],
                   "task": task,
                   "location": os.path.join(self.home, 'tests')}

        p = utils.run_cmd(cmd)
        original_output = p

        # here out is in fact a command which can be run to obtain task resuls
        # thus it is returned directly.
        failed = False
        if task == 'workload.yaml':
            cmd = "docker exec -t %(container)s rally task results" \
              % {"container": self.container_id}
            p = utils.run_cmd(cmd)
            try:
                res = json.loads(p)
            except ValueError:
                LOG.error("Gotten not-JSON object. Please see mcv-log")
                LOG.debug("Not-JSON object: %s, After command: %s", p, cmd)
                res = False
            if not res:
                LOG.info('Workload test failed')
                failed = True
            elif not res[0]['result'][0]['output']['complete']:
                LOG.info('Workload test failed')
                failed = True
            else:
                a = res[0]['result'][0]['output']['complete'][0]['data']['rows']
                LOG.info('Workload results:')
                for row in a:
                    LOG.info("%s: %s" % (row[0], row[1]))
        p = original_output
        out = p.split('\n')[-3].lstrip('\t')
        result_candidates = ('rally task results [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                             'rally -vd task detailed [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
        ret_val = None

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
        cmd = ("docker exec -t {container} sudo rally task report"
               " --out={home}/reports/{task}.html").format(
                   home=self.home,
                   container=self.container_id,
                   task=task)

        p = utils.run_cmd(cmd)

        cmd = "sudo cp {fld}/reports/{task}.html {pth}".format(
                  fld=self.homedir, task=task, pth=self.path)

        p = utils.run_cmd(cmd)

        return {'next_command': ret_val,
                'original output': original_output,
                'failed': failed}

    def _get_task_result_from_docker(self, task_id):
        LOG.debug("Retrieving task results for %s" % task_id)
        cmd = "docker exec -t %s %s" % (self.container_id, task_id)
        p = utils.run_cmd(cmd)

        if task_id.find("detailed") ==-1:
            try:
                res = json.loads(p)[0]  # actual test result as a dictionary
                return res
            except ValueError:
                LOG.error("Gotten not-JSON object. Please see mcv-log")
                LOG.debug("Not-JSON object: %s, After command: %s", p, cmd)
                return "Not-JSON object"
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
        except subprocess.CalledProcessError as e:
            LOG.error("Task %s has failed with: %s" % (task, e))
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
