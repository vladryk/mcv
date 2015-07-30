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
import logger as LOG
import os
import subprocess
import sys
from test_scenarios import runner
try:
    import json
except:
    import simplejson as json

nevermind = None

config = ConfigParser.ConfigParser()
default_config = "/etc/mcv/mcv.conf"


class ShakerRunner(runner.Runner):

    valid_staarten = ("yaml", "json")

    def __init__(self, config_location=None):
        super(ShakerRunner, self).__init__()
        self.identity = "shaker"
        self.config_section = "shaker"
        self.test_failures = []  # this object is supposed to live for one run
                                 # so let's leave it as is for now.

    def _it_ends_well(self, something):
        if something.split('.')[-1] in self.valid_staarten:
            return True
        return False

    def _evaluate_task_result(self, task, resulting_dict):
        # logs both success and problems in an uniformely manner.
        if resulting_dict.get('error', '') == '':
            LOG.log_test_task_ok(task)
        else:
            LOG.log_test_task_failure(task, resulting_dict['error'])
            return False
        return True

    def _get_task_path(self, task):
        # a quick and dirty way to find a task
        return 'test_scenarios/shaker/tests/%s' % task

    def _run_shaker(self, task):
        LOG.log_running_task(task)
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

    def run_batch(self, tasks):
        return super(ShakerRunner, self).run_batch(tasks)

    def run_individual_task(self, task):
        # runs a set of commands
        task_id = self._run_rally(task)
        task_result = self._get_task_result(task_id)
        if self._evaluate_task_result(task, task_result):
            return
        else:
            self.test_failures.append(task)

class ShakerOnDockerRunner(ShakerRunner):

    def __init__(self):
        self.container = None
        super(ShakerOnDockerRunner, self).__init__()

    def _setup_shaker_on_docker(self):
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
        LOG.log_arbitrary("Preparing to task %s" % task)
        cmd = r"cp "+test_location+\
              " /var/lib/docker/aufs/mnt/%s/tmp/pending_rally_task" %\
              p.rstrip('\n')
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        LOG.log_arbitrary("Successfully prepared to task %s" % task)


    def _run_shaker_on_docker(self, task):
        LOG.log_arbitrary("Starting task %s" % task)
        cmd = "docker exec -it %s keystone endpoint-list | grep :5000" %\
        self.container
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        self.endpoint = p.split('|')[3].split(':')[1].lstrip('/')
        cmd = "docker exec -it %s shaker-image-builder \
        --image-builder-template  \
        /etc/shaker/shaker/resources/image_builder_template.yaml" % \
        self.container
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "docker exec -it %s shaker --server-endpoint %s:5999 --scenario \
         /etc/shaker/scenarios/networking/%s --report-template \
         /etc/shaker/shaker/resources/report_template.jinja2 --debug \
         --log-file /etc/shaker/shaker.log --output theoutput" %\
             (self.container, self.endpoint, task)
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "docker exec -it %s cat theoutput" % self.container
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        result = json.loads(p)
        return result

    def _get_task_result_from_docker(self, task_id):
        LOG.log_arbitrary("Retrieving task results for %s" % task_id)
        cmd = "docker exec -it %s %s" % (self.container, task_id)
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        if task_id.find("detailed") ==-1:
            res = json.loads(p)[0]  # actual test result as a dictionary
            return res
        else:
            return p.split('\n')[-4:-1]

    def run_batch(self, tasks):
        self._setup_shaker_on_docker()
        return super(ShakerOnDockerRunner, self).run_batch(tasks)

    def run_individual_task(self, task):
        task_result = self._run_shaker_on_docker(task)
        if type(task_result) == dict and\
                self._evaluate_task_result(task, task_result):
            return True
        else:
            LOG.log_warning("Task %s has failed with %s" % (task, task_result))
            self.test_failures.append(task)
            return False
