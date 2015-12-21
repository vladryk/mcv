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


import logging
import subprocess
from test_scenarios.rally import runner as rrunner
import json
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

    def _run_tempest_on_docker(self, task, *args, **kwargs):
        # TODO: when container contains Tempest use  --source /path/to/Tempest
        LOG.info("Searching for installed tempest")
        cmd = 'docker exec -it %(container)s find /home/rally/.rally/tempest -name "for-deployment-*" -type d ' % {"container": self.container_id}
        install = p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        if not install:
            LOG.info("No installation found. Installing tempest")
            cmd = "docker exec -it %(container)s rally verify install --deployment existing --source /tempest"
            p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        LOG.info("Starting verification")
        cmd = "docker exec -it %(container)s rally verify start" %\
              {"container": self.container_id}
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
        cmd = "docker exec -it %(container)s rally verify results --html --out=%(task)s.html" % {"container": self.container_id, "task": task}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "sudo cp /var/lib/docker/aufs/mnt/%(id)s/home/rally/%(task)s.html %(pth)s" % {"id": p.rstrip('\n'), 'task': task, "pth": self.path}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "docker exec -it %(container)s rally verify results --json" % {"container": self.container_id}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return p

    def parse_results(self, res):
        LOG.info("Parsing results")
        if res == '':
            self.failure_indicator = 83
            return False
        self.tasks = json.loads(res)
        failures = self.tasks.get('failures')
        errors = self.tasks.get('errors')
        for (name, case) in self.tasks['test_cases'].iteritems():
            if case['status'] == 'OK':
                self.test_success.append(case['name'])
        if failures or errors:
            for (name, case) in self.tasks['test_cases'].iteritems():
                if case['status'] == 'FAIL':
                    self.test_failures.append(case['name'])
                    self.failure_indicator = 81
                elif case['status'] == 'ERROR':
                    self.test_failures.append(case['name'])
                    self.failure_indicator = 82
            return False
        return True

    def run_batch(self, *args, **kwargs):
        self._setup_rally_on_docker()
        self.run_individual_task('tempest', *args,  **kwargs)
        tasks = self.tasks['test_cases'].keys()
        self.total_checks = len(tasks)
        LOG.info("Running full tempest suite ")
        return {"test_failures": self.test_failures,
                "test_success": self.test_success,
                "test_not_found": self.test_not_found}

    def run_individual_task(self, task, *args, **kwargs):
        results = self._run_tempest_on_docker(task, *args, **kwargs)

        self.parse_results(results)
        if not self.test_failures:
            return True
        return False
