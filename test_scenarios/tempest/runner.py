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
import subprocess
from test_scenarios.rally import runner as rrunner
import json
import glob
LOG = logging


class TempestOnDockerRunner(rrunner.RallyOnDockerRunner):
    """Runner to run Tempest via Rally.

    The same container which is used for running Rally tests is used for
    running Tempest via Rally. Tempest must be cloned to a proper location
    inside the container.
    """

    def __init__(self, accessor, path, *args, **kwargs):
        self.config = kwargs["config"]
        self.path = path
        self.container = None
        self.accessor = accessor

        super(TempestOnDockerRunner, self).__init__(accessor, path, *args, **kwargs)
        self.failure_indicator = 80

    def _verify_rally_container_is_up(self):
        self.verify_container_is_up("tempest")

    def scenario_is_fine(self, scenario):
        return True

    def _it_ends_well(self, scenario):
        return True

    def start_tempest_container(self):
        LOG.debug("Bringing up Tempest container with credentials")
        protocol = self.config.get('basic', 'auth_protocol')
        add_host = ""
        if self.config.get("basic", "auth_fqdn") != '':
            add_host = "--add-host="+self.config.get("basic", "auth_fqdn") +":" + self.accessor.access_data["auth_endpoint_ip"]
        res = subprocess.Popen(["docker", "run", "-d", "-P=true",] +
            [add_host]*(add_host != "") +
            ["-p", "6001:6001", "-e", "OS_AUTH_URL=" + protocol +"://" +
            self.accessor.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
            "-e", "OS_TENANT_NAME=" +
            self.accessor.access_data["os_tenant_name"],
            "-e", "OS_USERNAME=" + self.accessor.access_data["os_username"],
            "-e", "OS_PASSWORD=" + self.accessor.access_data["os_password"],
            "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
            "-it", "mcv-tempest"], stdout=subprocess.PIPE).stdout.read()
        self._verify_rally_container_is_up()
        # here we fix glance image issues
        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        self.long_id = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).rstrip('\n')

    def copy_tempest_image(self):
        LOG.info('Copying image files required by tempest')
        subprocess.Popen(["sudo", "chmod", "a+r",
                          "/etc/toolbox/tempest/cirros-0.3.4-x86_64-disk.img"],
                         stdout=subprocess.PIPE).stdout.read()
        cmd = "docker exec -it %(container)s mkdir /home/rally/.rally/tempest/data" %\
              {"container": self.container_id}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        subprocess.Popen(["sudo", "cp",
                          "/etc/toolbox/tempest/cirros-0.3.4-x86_64-disk.img",
                          "/var/lib/docker/aufs/mnt/%(id)s/home/rally/.rally/tempest/data"\
                          % {"id": self.long_id, }],\
                          stdout=subprocess.PIPE).stdout.read()

    def _run_tempest_on_docker(self, task, *args, **kwargs):
        LOG.info("Searching for installed tempest")
        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        self.long_id = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).rstrip('\n')

        install = glob.glob('/var/lib/docker/aufs/mnt/%(id)s/home/rally/.rally/tempest/for-deployment-*'% {"id": self.long_id})
        if not install:
            LOG.info("No installation found. Installing tempest")
            cmd = "docker exec -it %(container)s rally verify install --deployment existing --source /tempest"%\
             {"container": self.container_id}

            p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            cirros = glob.glob('/var/lib/docker/aufs/mnt/%(id)s/home/rally/.rally/tempest/data/cirros-*'% {"id": self.long_id})
            if not cirros:
                self.copy_tempest_image()

        LOG.info("Starting verification")
        cmd = "docker exec -it %(container)s rally verify start --set %(set)s" %\
              {"container": self.container_id,
               "set": task}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "docker exec -it %(container)s rally verify list" %\
              {"container": self.container_id}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        # get the last run results. This should be done in a more robust and
        # sane manner at some point.
        run = p.split('\n')[-3].split('|')[8]
        if run == 'failed':
            LOG.error('Verification failed, unable to generate report')
            return ''
        run = p.split('\n')[-3].split('|')[1]
        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        LOG.info('Generating html report')
        cmd = "docker exec -it %(container)s rally verify results --html --out=%(task)s.html" %\
              {"container": self.container_id, "task": task}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "sudo cp /var/lib/docker/aufs/mnt/%(id)s/home/rally/%(task)s.html %(pth)s" %\
              {"id": p.rstrip('\n'), 'task': task, "pth": self.path}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "docker exec -it %(container)s rally verify results --json" %\
              {"container": self.container_id}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return p

    def _patch_rally(self):
        pass

    def parse_results(self, res, task):
        LOG.info("Parsing results")
        if res == '':
            LOG.info("Results of test set '%s': FAILURE" % task)
            self.failure_indicator = 83
            return False
        self.task = json.loads(res)
        failures = self.task.get('failures')
        success = self.task.get('success')
        LOG. info("Results of test set '%s': SUCCESS: %d FAILURES: %d" % (task, success, failures))
        for (name, case) in self.task['test_cases'].iteritems():
            if case['status'] == 'success':
                self.test_success.append(case['name'])
        if failures:
            for (name, case) in self.task['test_cases'].iteritems():
                if case['status'] == 'fail':
                    self.test_failures.append(case['name'])
                    self.failure_indicator = 81
            return False
        return True

    def run_batch(self, tasks, *args, **kwargs):
        try:
            max_failed_tests = int(self.config.get('tempest', 'max_failed_tests'))
        except ConfigParser.NoOptionError:
            max_failed_tests = int(self.config.get('basic', 'max_failed_tests'))

        self._setup_rally_on_docker()
        t = []
        for task in tasks:
            task = task.replace(' ', '')
            LOG.info('Running %s tempest set' % task)
            self.run_individual_task(task, *args,  **kwargs)
            t.append(self.task['test_cases'].keys())
            if len(self.test_failures)>max_failed_tests:
                self.total_checks = len(t)
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                self.failure_indicator = 89
                break
        self.total_checks = len(t)
        return {"test_failures": self.test_failures,
                "test_success": self.test_success,
                "test_not_found": self.test_not_found}

    def run_individual_task(self, task, *args, **kwargs):
        results = self._run_tempest_on_docker(task, *args, **kwargs)

        self.parse_results(results, task)
        return True
