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
#default_config = "/etc/cloud_validator/mcv.conf"
default_config = "etc/mcv.conf"


class RallyRunner(runner.Runner):

    valid_staarten = ("yaml", "json")

    def __init__(self, config_location=None):
        super(RallyRunner, self).__init__()
        self.identity = "rally"
        self.config_section = "rally"
        if config_location is None:
            self.config_location = default_config
        else:
            self.config_location = config_location
        self.config_values = self.read_confug_values()
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
            LOG.log_test_task_ok(task)
        else:
            LOG.log_test_task_failure(task, resulting_dict['result'])
            return False
        return True

    def _get_task_path(self, task):
        # a quick and dirty way to find a task
        return 'test_scenarios/rally/tests/%s' % task

    def _run_rally(self, task):
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
        self._setup_rally()
        return super(RallyRunner, self).run_batch(tasks)

    def run_individual_task(self, task):
        # runs a set of commands
        task_id = self._run_rally(task)
        task_result = self._get_task_result(task_id)
        if self._evaluate_task_result(task, task_result):
            return
        else:
            self.test_failures.append(task)

class RallyOnDockerRunner(RallyRunner):

    def __init__(self):
        self.container = None
        super(RallyOnDockerRunner, self).__init__()

    def _setup_rally_on_docker(self):
        # do docker magic here
        # apparently this has to be done with providing credentials in the
        # form of json
        # open question -- who should provide the credentials? right now it
        # should be ok to put them in the conf file, later on it is better to
        # retrieve them automagically.
        # Find docker container:
        p = subprocess.check_output("docker ps", shell=True,
                                    stderr=subprocess.STDOUT)
        p = p.split('\n')
        for line in p:
            elements = line.split()
            if elements[1].find("rally") != -1:
                self.container = elements[0]
                status = elements[4]
                break

    def _create_task_in_docker(self, task):
        cmd  = "docker inspect -f '{{.Id}}' %s" % self.container
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = r"cp test_scenarios/rally/tests/%s\
              /var/lib/docker/aufs/mnt/%s/tmp/pending_rally_task" %\
              (task, p.rstrip('\n'))
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)


    def _run_rally_on_docker(self, task):
        # madskillz go go!
        self._create_task_in_docker(task)
        cmd = "docker exec -it %s rally task start /tmp/pending_rally_task" %\
             self.container
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        # here out is in fact a command which can be run to obtain task resuls
        # thus it is returned directly.
        out = p.split('\n')[-4].lstrip('\t')
        return out.rstrip('\r')

    def _get_task_result_from_docker(self, task_id):
        cmd = "docker exec -it %s %s" % (self.container, task_id)
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        res = json.loads(p)[0]  # actual test result as a dictionary
        return res

    def run_batch(self, tasks):
        self._setup_rally_on_docker()
        return super(RallyRunner, self).run_batch(tasks)

    def run_individual_task(self, task):
        # here be the fix for running rally in a docker container.
        # apparently we'll need something to set up rally inside docker.
        task_id = self._run_rally_on_docker(task)
        task_result = self._get_task_result_from_docker(task_id)
        if self._evaluate_task_result(task, task_result):
            return
        else:
            self.test_failures.append(task)
