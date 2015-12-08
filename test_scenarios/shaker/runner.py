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
import os
import subprocess
import sys
from test_scenarios import runner
try:
    import json
except:
    import simplejson as json

import glanceclient as glance
from keystoneclient.v2_0 import client as keystone_v2

nevermind = None

config = ConfigParser.ConfigParser()
default_config = "/etc/mcv/mcv.conf"
LOG = logging


class ShakerRunner(runner.Runner):

    valid_staarten = ("yaml", "json")

    def __init__(self, accessor=None, config_location=None, *args, **kwargs):
        super(ShakerRunner, self).__init__()
        self.identity = "shaker"
        self.config_section = "shaker"
        self.test_failures = []  # this object is supposed to live for one run
                                 # so let's leave it as is for now.
        self.failure_indicator = 40

    def _it_ends_well(self, something):
        if something.split('.')[-1] in self.valid_staarten:
            return True
        return False

    def _evaluate_task_result(self, task, resulting_dict):
        # logs both success and problems in an uniformely manner.
        if resulting_dict.get('error', '') == '':
            LOG.info("Task %s has completed successfully." % task)
        else:
            LOG.warning("Task %s has failed with the following error: %s" % \
                        (task,resulting_dict['error']))
            return False
        return True

    def _get_task_path(self, task):
        # a quick and dirty way to find a task
        return 'test_scenarios/shaker/tests/%s' % task

    def _run_shaker(self, task):
        LOG.debug("Running task %s" % task)
        # important: at this point task must be transformed to a full path
        path_to_task = self._get_task_path(task)
        cmd = "rally task start %s" % path_to_task
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
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
                                    stderr=subprocess.STDOUT)
        res = json.loads(p)[0]  # actual test result as a dictionary
        return res

    def run_batch(self, tasks, *args, **kwargs):
        return super(ShakerRunner, self).run_batch(tasks, *args, **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
        # runs a set of commands
        task_id = self._run_rally(task)
        task_result = self._get_task_result(task_id)
        if self._evaluate_task_result(task, task_result):
            return
        else:
            self.test_failures.append(task)

class ShakerOnDockerRunner(ShakerRunner):

    def __init__(self, accessor, path, *args, **kwargs):
        self.config = kwargs["config"]
        self.container_id = None
        self.accessor = accessor
        self.path = path
        super(ShakerOnDockerRunner, self).__init__()

    def get_glanceclient(self):
        self.key_client = keystone_v2.Client(
            username=self.accessor.access_data['os_username'],
            auth_url=self.config.get('basic', 'auth_protocol')+"://" + self.accessor.access_data["auth_endpoint_ip"] +
                     ":5000/v2.0/",
            password=self.accessor.access_data['os_password'],
            tenant_name=self.accessor.access_data['os_tenant_name'],
            insecure=True)
        image_api_url =self.key_client.service_catalog.url_for(
            service_type="image")
        self.glance = glance.Client(
            '1',
            endpoint=image_api_url,
            token=self.key_client.auth_token,
            insecure=True)

    def _check_shaker_setup(self):
        LOG.info("Checking Shaker setup. If this is the first run of "\
                 "mcvconsoler on this cloud go grab some coffee, it will "\
                 "take a while.")
        if self.config.get("basic", "auth_protocol") == "https":
            self._patch_shaker()
        path = '/etc/toolbox/shaker'
        for f in os.listdir(path):
            if f.endswith(".ss.img"):
                path += '/' + f
                break
        if path.endswith('shaker'):
            LOG.error('No shaker image available')
            return
        LOG.debug('Authenticating in glance')
        self.get_glanceclient()
        i_list = self.glance.images.list()
        image = False
        for im in i_list:
            if im.name=='shaker-image':
                image = True
        if not image:
            LOG.debug('Creating shaker image')
            self.glance.images.create(name='shaker-image', disk_format="qcow2",
                                      container_format="bare",data=open(path))
        else:
            LOG.debug("Shaker image exists")
        LOG.debug("Run shaker-image-builder")
        res = subprocess.Popen(["docker", "exec", "-it",
                                self.container_id,
                                "shaker-image-builder--image-name shaker-image"],
                                stdout=subprocess.PIPE).stdout.read()

    def start_shaker_container(self):
        LOG.debug( "Bringing up Shaker container with credentials")
        protocol = self.config.get('basic', 'auth_protocol')
        if self.config.get("basic", "auth_fqdn") != '':
            add_host = "--add-host="+self.config.get("basic", "auth_fqdn") +\
                       ":" + self.accessor.access_data["auth_endpoint_ip"]
        res = subprocess.Popen(["docker", "run", "-d", "-P=true",] +
                               [add_host]*(add_host != "") +
            ["-p", "5999:5999", "-e", "OS_AUTH_URL="+protocol+"://" +
            self.accessor.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
            "-e", "OS_TENANT_NAME=" +
            self.accessor.access_data["os_tenant_name"],
            "-e", "OS_USERNAME=" + self.accessor.access_data["os_username"],
            "-e", "OS_PASSWORD=" + self.accessor.access_data["os_password"],
            "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
            "-it", "mcv-shaker"], stdout=subprocess.PIPE).stdout.read()

    def _setup_shaker_on_docker(self):
        self.verify_container_is_up("shaker")
        self._check_shaker_setup()
        p = subprocess.check_output("docker ps", shell=True,
                                    stderr=subprocess.STDOUT)
        p = p.split('\n')
        for line in p:
            elements = line.split()
            if elements[1].find("shaker") != -1:
                self.container = elements[0]
                status = elements[4]
                break

    def _create_task_in_docker(self, task):
        cmd  = "docker inspect -f '{{.Id}}' %s" % self.container
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        test_location = os.path.join(os.path.dirname(__file__), "tests", task)
        LOG.debug("Preparing to task %s" % task)
        cmd = r"cp "+test_location+\
              " /var/lib/docker/aufs/mnt/%s/tmp/pending_rally_task" %\
              p.rstrip('\n')
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        LOG.debug("Successfully prepared to task %s" % task)


    def _run_shaker_on_docker(self, task):
        LOG.info("Starting task %s" % task)
        self.endpoint = self.accessor.access_data['auth_endpoint_ip']
        cmd = "docker exec -it %s shaker-image-builder --image-name " \
              "shaker-image" % self.container
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        # Note: make port configurable
        cmd = "docker exec -it %s shaker --server-endpoint %s:5999 --scenario \
         /etc/shaker/scenarios/networking/%s --report-template \
         /etc/shaker/shaker/resources/report_template.jinja2 --debug \
         --log-file /etc/shaker/shaker.log --output theoutput --report \
         %s.html" % (self.container, self.accessor.access_data["instance_ip"],
                     task, task)
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "docker exec -it %s cat theoutput" % self.container
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        result = json.loads(p)
        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "sudo cp %(pref)s/%(id)s/%(task)s.html %(pth)s" % \
                  {"pref": "/var/lib/docker/aufs/mnt", "id": p.rstrip('\n'),
                   'task': task, "pth": self.path}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        self.clear_shaker_image()
        return result

    def _patch_shaker(self):
        # Currently there is a bug in shaker which prevents it from doing good
        # things sometimes. Yes, that's the second reason we have too few good
        # things. Not the best way to go, yet since noone is planning to
        # develop it any time soon we'll stick with this.
        LOG.debug("Patching Shaker.")
        cmd_prefix = "docker exec -it %s sed -i" % self.container_id
        path_prefix = "/usr/local/lib/python2.7/dist-packages"
        cmds = [
            ("/location = resp.headers.get('location')/ a " + "\ "*16 + \
                "location = location.replace('http', 'https')",
             "heatclient/common/http.py"),
            ("23a \ \ \ \ kwargs['verify'] = False",
             "shaker/openstack/clients/keystone.py"),
            ("s/return session.Session(auth=auth, verify=cacert)/return " +\
                 "session.Session(auth=auth, verify=False)/",
             "shaker/openstack/clients/keystone.py"),
            ("/token=keystone_client.auth_token,/a insecure=True,",
             "shaker/openstack/clients/glance.py"),
            ("/token=keystone_client.auth_token,/a insecure=True,",
             "shaker/openstack/clients/heat.py")
            ]
        for cmd in cmds:
            path = os.path.join(path_prefix, cmd[-1])
            cmd = " ".join([cmd_prefix, "\"" + cmd[0] +"\"", path])
            res = subprocess.check_output(cmd, shell=True,
                                          stderr=subprocess.STDOUT)

    def clear_shaker_image(self):
        clear_image = self.config.get('shaker', 'clear_image')
        if clear_image == 'True':
            i_list = self.glance.images.list()
            for im in i_list:
                if im.name=='shaker-image':
                    self.glance.images.delete(im)

    def _get_task_result_from_docker(self, task_id):
        LOG.info("Retrieving task results for %s" % task_id)
        cmd = "docker exec -it %s %s" % (self.container, task_id)
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        if task_id.find("detailed") ==-1:
            res = json.loads(p)[0]  # actual test result as a dictionary
            return res
        else:
            return p.split('\n')[-4:-1]

    def run_batch(self, tasks, *args, **kwargs):
        self._setup_shaker_on_docker()
        return super(ShakerOnDockerRunner, self).run_batch(tasks, *args,
                                                           **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
        task_result = self._run_shaker_on_docker(task)
        if type(task_result) == dict and\
                self._evaluate_task_result(task, task_result):
            return True
        else:
            LOG.warning("Task %s has failed with %s" % (task, task_result))
            self.test_failures.append(task)
            return False
