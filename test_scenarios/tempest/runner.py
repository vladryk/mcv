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
        LOG.info("Starting Tempest verification")
        cmd = "docker exec -it %(container)s rally verify start" %\
              {"container": self.container_id}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        cmd = "docker exec -it %(container)s rally verify list" %\
              {"container": self.container_id}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        # get the last run results. This should be done in a more robust and
        # sane manner at some point.
        run = p.split('\n')[-3].split('|')[1]
        cmd = "docker exec -it %(container)s rally verify show %(run)s" %\
              {"container": self.container_id,
               "run": run}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        # TODO: should contain also a pass/fail indicator from Tempest
        return p

    def run_batch(self, *args, **kwargs):
        self._setup_rally_on_docker()
        return super(TempestOnDockerRunner, self).run_batch(['tempest'], *args, **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
        results = self._run_tempest_on_docker(task, *args, **kwargs)
        LOG.info("The following are the results of running Tempest: %s" %\
                 results)
        return True
