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

import json
import os.path
import subprocess
import time
import datetime

from keystoneclient import exceptions as k_exc
from glanceclient import exc as g_exc
from neutronclient.common import exceptions as n_exc
from novaclient import exceptions as no_exc

from mcv_consoler.common.cfgparser import config_parser
from mcv_consoler.common import clients as Clients
from mcv_consoler.common.config import FEDORA_IMAGE_PATH
from mcv_consoler.common.config import MOS_HADOOP_MAP
from mcv_consoler.common.config import SAHARA_IMAGE_PATH80
from mcv_consoler.common.config import SAHARA_IMAGE_PATH70
from mcv_consoler.common.config import TERASORT_JAR_PATH
from mcv_consoler.common.errors import RallyError
from mcv_consoler.logger import LOG
from mcv_consoler.plugins import runner
from mcv_consoler import utils


config = config_parser
LOG = LOG.getLogger(__name__)

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

    def __init__(self, config_location=None, *args, **kwargs):
        super(RallyRunner, self).__init__()
        self.config = kwargs["config"]
        self.identity = "rally"
        self.config_section = "rally"
        # this object is supposed to live for one run
        # so let's leave it as is for now.
        # TODO(albartash): todo smth with this property
        self.test_failures = []

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
        time_of_tests = resulting_dict.get('full_duration', None)
        if time_of_tests:
            time_of_tests = str(round(time_of_tests, 3)) + 's'
        else:
            time_of_tests = '0s'
        self.time_of_tests[task] = {'duration': time_of_tests}
        if type(resulting_dict) != dict:
            LOG.debug(("Task {task} has failed with the following error: "
                      "{err}").format(task=task, err=resulting_dict))
            self.test_failures.append(task)
            LOG.info(" * FAILED")
            return False

        if not resulting_dict['sla']:
            err = resulting_dict['result'][0]['error']
            if err:
                LOG.debug(("Task {task} has failed with the error: "
                           "{err}").format(task=task,
                                           err=resulting_dict['result']))
                self.test_failures.append(task)
                LOG.info(" * FAILED")
                return False
            LOG.info(" * PASSED")
            return True

        if resulting_dict['sla'][0]['success'] is True:
            LOG.debug("Task %s has completed successfully." % task)
        else:
            LOG.debug(("Task {task} has failed with the following error: "
                       "{err}").format(task=task,
                                       err=resulting_dict['result']))
            self.test_failures.append(task)
            LOG.info(" * FAILED")
            return False
        LOG.info(" * PASSED")
        return True

    def _get_task_path(self, task):
        # TODO(albartash): refactor this damn
        return 'plugins/rally/tests/%s' % task

    def _run_rally(self, task):
        LOG.debug("Running task %s" % task)
        # warning: at this point task must be transformed to a full path
        path_to_task = self._get_task_path(task)
        p = utils.run_cmd("rally task start " + path_to_task)

        out = p.split('\n')[-4].lstrip('\t')
        return out

    def _get_task_result(self, task_id):

        # TODO(albartash): Fix the problem mentioned below:

        # this function is not using task id contrary to what it says,  but in
        # current state of affair direct command produced by rally. task_id
        # is left as is for now, but will be moved in future.
        # if asked kindly rally just spits resulting json directly to stdout

        p = utils.run_cmd(task_id)
        try:
            res = json.loads(p)[0]
            return res
        except ValueError:
            LOG.error("Gotten not-JSON object. Please see mcv-log")
            LOG.debug("Not-JSON object: %s", p)
            return "Not-JSON object"

    def run_batch(self, tasks, *args, **kwargs):
        self._setup_rally()
        return super(RallyRunner, self).run_batch(tasks, *args, **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
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
        self.access_data = accessor.os_data
        self.skip = False
        self.homedir = "/home/mcv/toolbox/rally"
        self.home = "/mcv"

        super(RallyOnDockerRunner, self).__init__(*args, **kwargs)
        self.failure_indicator = RallyError.NO_RUNNER_ERROR

        self.glanceclient = Clients.get_glance_client(self.access_data)
        self.neutronclient = Clients.get_neutron_client(self.access_data)
        self.novaclient = Clients.get_nova_client(self.access_data)
        self.net_id = None

    def check_computes(self):
        # TODO(albartash): Do we really need this method?
        services = self.novaclient.services.list()
        self.compute = 0
        for service in services:
            if service.binary == 'nova-compute':
                self.compute += 1
        LOG.debug("Found " + str(self.compute) + " computes.")

    def create_fedora_image(self):
        i_list = self.glanceclient.images.list()
        for im in i_list:
            if im.name == 'mcv-test-fedora':
                return im.id
        im = self.glanceclient.images.create(name='mcv-test-fedora',
                                             disk_format="qcow2",
                                             is_public=True,
                                             container_format="bare",
                                             data=open(FEDORA_IMAGE_PATH))
        return im.id

    def cleanup_image(self, name):
        LOG.debug('Cleaning up test image')
        try:
            i_list = self.glanceclient.images.list()
        except g_exc.HTTPUnauthorized:
            # Exception means that token expired, so we need to refresh client
            self.glanceclient = Clients.get_glance_client(self.access_data)
            i_list = self.glanceclient.images.list()
        for im in i_list:
            if im.name == name:
                self.glanceclient.images.delete(im.id)

    def cleanup_fedora_image(self):
        self.cleanup_image('mcv-test-fedora')

    def cleanup_sahara_image(self):
        self.cleanup_image('mcv-workload-sahara')

    def create_sahara_image(self, mos_version):
        try:
            sahara = Clients.get_sahara_client(self.access_data)
        except k_exc.EndpointNotFound:
            LOG.warning("Can't run BigData workload task without installed sahara")
            self.skip = True
            return
        i_list = self.glanceclient.images.list()
        for im in i_list:
            if im.name == 'mcv-workload-sahara':
                return im.id
        if mos_version == '8.0':
            sahara_image_path = SAHARA_IMAGE_PATH80
        else:
            sahara_image_path = SAHARA_IMAGE_PATH70
        im = self.glanceclient.images.create(name='mcv-workload-sahara',
                                             disk_format="qcow2",
                                             is_public=True,
                                             container_format="bare",
                                             data=open(sahara_image_path))
        sahara.images.update_image(
            image_id=im.id, user_name='ubuntu', desc="")
        if mos_version == '8.0':
            sahara.images.update_tags(
                image_id=im.id, new_tags=["vanilla", "2.7.1"])
        else:
            sahara.images.update_tags(
                image_id=im.id, new_tags=["vanilla", "2.6.0"])

        return im.id

    def create_or_get_flavor(self):
        flavors = self.novaclient.flavors.list()
        for flav in flavors:
            if flav.name == 'mcv-workload-test-flavor':
                return flav.id
        ram = utils.GET(self.config, 'ram', 'workload')
        disc = utils.GET(self.config, 'disc', 'workload')
        vcpu = utils.GET(self.config, 'vcpu', 'workload')
        flavor = self.novaclient.flavors.create('mcv-workload-test-flavor',
                                                ram, vcpu, disc, 'auto')
        return flavor.id

    def cleanup_test_flavor(self):
        LOG.debug('Cleaning up test flavor')
        try:
            flavors = self.novaclient.flavors.list()
        except no_exc.Unauthorized:
            # Exception means that token expired, so we need to refresh client
            self.novaclient = Clients.get_nova_client(self.access_data)
            flavors = self.novaclient.flavors.list()
        for flav in flavors:
            if flav.name == 'mcv-workload-test-flavor':
                self.novaclient.flavors.delete(flav.id)

    def get_network_router_id(self):
        networks = self.neutronclient.list_networks(
            **{'router:external': True})['networks']

        net_id = networks[0].get('id')
        routers = self.neutronclient.list_routers()['routers']
        rou_id = routers[0].get('id')
        return (net_id, rou_id)

    def create_test_network(self):
        if self.net_id:
            return self.net_id
        net = self.neutronclient.create_network(
            body={'network': {'name': 'mcv-test-network'}})
        self.net_id = net['network']['id']
        self.neutronclient.create_subnet(
            body={'subnet':
                      {'network_id': self.net_id,
                       'cidr': '10.5.0.0/24',
                       'name': 'mcv-test-subnet',
                       'ip_version': 4}})
        return self.net_id

    def cleanup_network(self):
        if self.net_id is not None:
            LOG.debug('Removing previously created network: %s' % self.net_id)
            try:
                self.neutronclient.delete_network(self.net_id)
            except n_exc.Unauthorized:
                # Exception means that token expired, so we need to refresh client
                self.neutronclient = Clients.get_neutron_client(self.access_data)
                self.neutronclient.delete_network(self.net_id)

    def start_container(self):
        LOG.debug("Starting Rally container")
        add_host = ""
        if self.access_data["auth_fqdn"] != '':
            add_host = "--add-host={fqdn}:{endpoint}".format(
                fqdn=self.access_data["auth_fqdn"],
                endpoint=self.access_data["ips"]["endpoint"])

        res = subprocess.Popen(
            ["docker", "run", "-d", "-P=true"] +
            [add_host] * (add_host != "") +
            ["-p", "6000:6000",
             "-e", "OS_AUTH_URL=" + self.access_data['auth_url'],
             "-e", "OS_TENANT_NAME=" + self.access_data["tenant_name"],
             "-e", "OS_USERNAME=" + self.access_data["username"],
             "-e", "OS_PASSWORD=" + self.access_data["password"],
             "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
             "-e", "OS_REGION_NAME=" + self.access_data["region_name"],
             "-v", ':'.join([self.homedir, self.home]), "-w", self.home,
             "-t", "mcv-rally"],
            stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()

        LOG.debug('Finish starting Rally container. Result: {result}'.format(
                  result=str(res)))

        self._verify_rally_container_is_up()

        cmd = "chmod a+r %s/images/cirros-0.3.1-x86_64-disk.img" % self.homedir
        utils.run_cmd(cmd)
        self._patch_rally()
        self.copy_config()

    def copy_config(self):
        cmd = 'docker exec -t %s sudo mkdir -p /etc/rally' % self.container_id
        utils.run_cmd(cmd)
        cmd = 'docker exec -t %s sudo cp %s/rally.conf /etc/rally/rally.conf' % (self.container_id,
                                                                                 self.home)
        utils.run_cmd(cmd)

    @staticmethod
    def _os_patch(target, patch, container_id=None):
        """
        Silently patch a file. Errors are ignored
        params:
         'target' - absolute system path to a file that needs to be changed
         'patch' - absolute system path to a .patch file
         'container_id' (optional). If provided - perform an operation
        inside a docker container
        """
        tmp = 'sudo patch --dry-run {target} -i {patch} && ' \
              'sudo patch {target} -i {patch}'
        if container_id:
            tmp = 'docker exec -t {cid} /bin/sh -c \"' + tmp + '\"'
        cmd = tmp.format(cid=container_id, target=target, patch=patch)
        try:
            return utils.run_cmd(cmd)
        except subprocess.CalledProcessError:
            pass

    def _patch_rally(self):
        from os.path import join

        dist = '/usr/local/lib/python2.7/dist-packages/'

        LOG.debug('Patching rally.siege regex')
        siege = join(dist, 'rally/plugins/workload/siege.py')
        siege_patch = '/mcv/custom_patches/rally_siege_regex.patch'
        self._os_patch(siege, siege_patch, self.container_id)

        LOG.debug('Patching sahara_job_binaries.py for rally')
        sahara_job = join(
            dist,
            'rally/plugins/openstack/context/sahara/sahara_job_binaries.py'
        )
        sahara_patch = '/mcv/custom_patches/rally_sahara_job_binaries.patch'
        self._os_patch(sahara_job, sahara_patch, self.container_id)

        LOG.debug('Start patching hosts')
        template_path = join(self.home, 'tests/templates/wp_instances.yaml')
        cmd = ("""docker exec -t %s """
               """sed -i "61s/.*/"""
               """            sudo sh -c 'echo %s %s >> """
               """\/etc\/hosts'/" %s""") % (
            self.container_id,
            self.access_data['ips']['endpoint'],
            self.access_data['auth_fqdn'],
            template_path)

        res = utils.run_cmd(cmd)
        LOG.debug('Finish patching hosts. Result: {res}'.format(res=res))

    def _verify_rally_container_is_up(self):
        self.verify_container_is_up("rally")

    def _check_and_fix_flavor(self):
        LOG.debug("Searching for proper flavor.")

        # Note: Nova client can't search flavours by name,
        # so manually search in list.
        res = self.novaclient.flavors.list()
        for f in res:
            if f.name == 'm1.nano':
                LOG.debug("Proper flavor for rally has been found")
                return
        LOG.debug("Apparently there is no flavor suitable for running rally. "
                  "Creating one...")

        self.novaclient.flavors.create(name='m1.nano', ram=128, vcpus=1,
                                       disk=1, flavorid=42)

        time.sleep(3)
        return self._check_and_fix_flavor()

    def create_rally_json(self):
        auth_protocol = 'https' if self.access_data['insecure'] else 'http'

        credentials = {"ip_address": self.access_data["ips"]["endpoint"],
                       "region": self.access_data["region_name"],
                       "uname": self.access_data["username"],
                       "upass": self.access_data["password"],
                       "uten": self.access_data["tenant_name"],
                       "auth_protocol": auth_protocol,
                       "insecure": str(self.access_data['insecure']).lower()}

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
        if "There is no" in res:
            LOG.debug("It is not. Trying to set up rally deployment.")
            self.create_rally_json()

            cmd = "docker exec -t %s rally deployment create " \
                  "--file=%s/conf/existing.json --name=existing" % \
                  (self.container_id, self.home)
            utils.run_cmd(cmd)
        else:
            LOG.debug("Seems like it is present.")

        LOG.debug('Trying to use Rally deployment')

        cmd = ("docker exec -t {cid} "
               "rally deployment use existing").format(
            cid=self.container_id)
        utils.run_cmd(cmd, quiet=True)

    def _check_rally_setup(self):
        self._check_and_fix_flavor()
        self._rally_deployment_check()

    def _setup_rally_on_docker(self):
        self.check_computes()
        self._verify_rally_container_is_up()
        self._check_rally_setup()

    def _prepare_certification_task_args(self):
        args = {}

        def _ADD(argname):
            args[argname] = utils.GET(self.config, argname, 'certification')

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
        args["glance_image_location"] = os.path.join(
            self.home, 'images/cirros-0.3.1-x86_64-disk.img')
        args["service_list"] = utils.GET(self.config,
                                         'services',
                                         'certification').split(',')
        return args

    def prepare_workload_task(self):
        image_id = self.create_fedora_image()
        net, rou = self.get_network_router_id()
        concurrency = utils.GET(self.config, 'concurrency', 'workload')
        instance_count = utils.GET(self.config, 'instance_count', 'workload')
        task_args = {
            'network_id': net,
            'router_id': rou,
            'concurrency': concurrency,
            'instance_count': instance_count,
            'image_id': image_id
        }

        return task_args

    def prepare_big_data_task(self):
        mos_version = utils.GET(self.config, 'mos_version', 'basic')
        image_id = self.create_sahara_image(mos_version)
        flavor_id = self.create_or_get_flavor()
        file_size = utils.GET(self.config, 'file_size', 'workload')
        worker = utils.GET(self.config, 'workers_count', 'workload')
        task_args = {
            'file_size': file_size,
            'workers_count': worker,
            'flavor_id': flavor_id,
            'sahara_image_uuid': image_id,
            'terasort_jar_path': TERASORT_JAR_PATH,
            'hadoop_version': MOS_HADOOP_MAP[mos_version],
        }

        return task_args

    def create_cmd_for_task(self, location, task_args):
        cmd = ("docker exec -t {container} rally"
               " --rally-debug task start {location}"
               " --task-args '{task_args}'").format(
            container=self.container_id,
            location=os.path.join(self.home, location),
            task_args=json.dumps(task_args))
        return cmd

    def _run_rally_on_docker(self, task, *args, **kwargs):
        if task == 'certification':
            LOG.info("Running Rally Certification Task")
            task_args = self._prepare_certification_task_args()
            location = "tests/certification/openstack/task.yaml"
            cmd = self.create_cmd_for_task(location, task_args)

        elif task == 'workload.yaml':
            LOG.info("Running Workload")
            task_args = self.prepare_workload_task()
            location = os.path.join(self.home, "tests/workload.yaml")
            cmd = self.create_cmd_for_task(location, task_args)

        elif task == 'big-data-workload.yaml':
            LOG.info("Running BigData Workload")
            task_args = self.prepare_big_data_task()
            location = os.path.join(self.home, "tests/big-data-workload.yaml")
            cmd = self.create_cmd_for_task(location, task_args)

        else:
            LOG.info("Running task %s" % task)
            location = os.path.join(self.home, 'tests/%s' % task)
            gre_enabled = utils.GET(self.config, 'gre_enabled', 'rally')
            vlan_amount = utils.GET(self.config, 'vlan_amount', 'rally')
            concurrency = utils.GET(self.config, 'concurrency', 'rally')
            network = self.create_test_network()
            if isinstance(concurrency, basestring):
                concurrency = int(concurrency)

            task_args = {"compute": kwargs["compute"],
                         "concurrency": concurrency,
                         "current_path": os.path.join(self.home, 'tests'),
                         "gre_enabled": gre_enabled,
                         "vlan_amount": vlan_amount,
                         'network': network
                         }

            cmd = self.create_cmd_for_task(location, task_args)
        if self.skip:
            self.test_not_found.append(task)
            return
        utils.run_cmd(cmd)

        failed = False

        if 'workload.yaml' in task:
            failed = self.proceed_workload_result(task)

        else:
            cmd = 'docker exec -t %s ' \
                  '/bin/sh -c "rally task status 2>/dev/null" ' \
                  ' | grep -i Task | awk \'{print $3}\' ' % self.container_id
            task_status = utils.run_cmd(cmd).strip()
            if task_status != 'finished':
                failed = True

        cmd = ("docker exec -t {cid} rally task report"
               " --out={home}/reports/{task}.html").format(
            cid=self.container_id,
            home=self.home,
            task=task)

        utils.run_cmd(cmd)

        cmd = "cp {fld}/reports/{task}.html {pth}".format(
            fld=self.homedir, task=task, pth=self.path)

        utils.run_cmd(cmd)

        return failed

    def _get_task_result_from_docker(self):
        cmd = 'docker exec -t {cid} /bin/sh -c ' \
              '"rally task results 2>/dev/null"'.format(cid=self.container_id)
        p = utils.run_cmd(cmd, quiet=True)

        try:
            return json.loads(p)[0]  # actual test result as a dictionary
        except ValueError:
            LOG.error("Gotten not-JSON object. Please see mcv-log")
            LOG.debug("Not-JSON object: %s, After command: %s", p, cmd)

    def proceed_workload_result(self, task):
        failed = False
        cmd = 'docker exec -t {cid} /bin/sh -c ' \
              '"rally task results 2>/dev/null"'.format(cid=self.container_id)

        p = utils.run_cmd(cmd, quiet=True)

        try:
            res = json.loads(p)
        except ValueError:
            LOG.error("Gotten not-JSON object. Please see mcv-log")
            LOG.debug("Not-JSON object: %s, After command: %s", p, cmd)
            res = False
        if not res:
            LOG.info('Workload test failed')
            return True

        if task == 'big-data-workload.yaml':
            # TODO(ekudryashova): Proceed failures correctly
            if res[0]['sla']:
                failed = True
                LOG.info('Workload test failed with reason %s'
                         % res[0]['sla'][0]['detail'])
                return failed

            a = res[0]['result'][0]['atomic_actions']
            total = res[0]['result'][0]['duration']
            LOG.info('Big Data Workload results:')
            for (k, v) in a.iteritems():
                LOG.info("%s: %s" % (k, v))
            LOG.info("Total duration: %s" % total)
        else:
            if res[0]['result'][0]['output']['complete']:
                a = res[0]['result'][0]['output']
                a = a['complete'][0]['data']['rows']
                LOG.info('Workload results:')
                for row in a:
                    LOG.info("%s: %s" % (row[0], row[1]))
            else:
                LOG.info('Workload test failed')
                failed = True

        return failed

    def run_batch(self, tasks, *args, **kwargs):
        LOG.info("Time start: %s UTC\n" % str(datetime.datetime.utcnow()))
        self._setup_rally_on_docker()

        tasks, missing = self.discovery.match(tasks)
        self.test_not_found.extend(missing)

        result = super(RallyRunner, self).run_batch(tasks, *args, **kwargs)
        self.cleanup_fedora_image()
        self.cleanup_test_flavor()
        self.cleanup_network()
        LOG.info("Time end: %s UTC" % str(datetime.datetime.utcnow()))
        return result

    def run_individual_task(self, task, *args, **kwargs):
        try:
            task_failed = self._run_rally_on_docker(task, *args, **kwargs)
        except subprocess.CalledProcessError as e:
            LOG.error("Task %s has failed with: %s" % (task, e))
            self.test_failures.append(task)
            LOG.info(" * FAILED")
            return False
        if task_failed is True:
            LOG.warning("Task %s has failed for some "
                        "instrumental issues" % task)
            self.test_failures.append(task)
            LOG.info(" * FAILED")
            return False
        elif self.skip:
            LOG.debug("Skipped test %s" % task)
            LOG.info(" * SKIPPED")
            return False
        LOG.debug("Retrieving task results for %s" % task)
        task_result = self._get_task_result_from_docker()
        if task_result is None:
            self.test_failures.append(task)
            LOG.info(" * FAILED")
            return False
        return self._evaluate_task_result(task, task_result)


