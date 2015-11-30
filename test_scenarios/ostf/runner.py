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


import re
import logging
import os
import subprocess
import sys
from test_scenarios import runner
try:
    import json
except:
    import simplejson as json

nevermind = None

default_config = "etc/mcv.conf"

LOG = logging


class OSTFOnDockerRunner(runner.Runner):

    def __init__(self, accessor, *args, **kwargs):
        self.config = kwargs["config"]
        self.accessor = accessor
        self.identity = "ostf"
        self.config_section = "ostf"
        self.test_failures = []  # this object is supposed to live for one run
                                 # so let's leave it as is for now.
        self.success = []
        self.failures = []
        self.not_found = []
        self.container = None
        super(OSTFOnDockerRunner, self).__init__()

    def _do_config_extraction(self):
        LOG.info( "Preparing OSTF")
        res = subprocess.Popen(["docker", "exec", "-it",
                                self.container_id,
                                "ostf-config-extractor", "-o",
                                "/tmp/ostfcfg.conf"],
                               stdout=subprocess.PIPE).stdout.read()
        LOG.debug("Config extraction resulted in: " + res)

    def start_ostf_container(self):
        LOG.debug( "Bringing up OSTF container with credentials")
        mos_version = self.config.get("ostf", "version")
        if mos_version == "6.1":
            cname = "mcv-ostf61"
        elif mos_version == "7.0":
            cname = "mcv-ostf70"
        else:
            LOG.error("Unsupported MOS version: " + mos_version)
            sys.exit(33)
        res = subprocess.Popen(["docker", "run", "-d", "-P=true",
            "-p", "8080:8080", #"-e", "OS_AUTH_URL=http://" +
            #self.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
            "-e", "OS_TENANT_NAME=" +
            self.accessor.access_data["os_tenant_name"],
            "-e", "OS_USERNAME=" + self.accessor.access_data["os_username"],
            "-e", "PYTHONWARNINGS=ignore",
            "-e", "NAILGUN_PROTOCOL="+self.config.get('basic', 'auth_protocol'),
            "-e", "OS_PASSWORD=" + self.accessor.access_data["os_password"],
            "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
            "-e", "NAILGUN_HOST=" + self.accessor.access_data["nailgun_host"],
            "-e", "NAILGUN_PORT=8000",
            "-e", "CLUSTER_ID=" + self.accessor.access_data["cluster_id"],
            "-e", "OS_REGION_NAME=RegionOne",
            "-it", cname], stdout=subprocess.PIPE).stdout.read()

    def _verify_ostf_container_is_up(self):
        self.verify_container_is_up("ostf")

    def _setup_ostf_on_docker(self):
        # Find docker container:
        self._verify_ostf_container_is_up()
        self._do_config_extraction()
        p = subprocess.check_output("docker ps", shell=True,
                                    stderr=subprocess.STDOUT)
        p = p.split('\n')
        for line in p:
            elements = line.split()
            if elements[1].find("ostf") != -1:
                self.container = elements[0]
                status = elements[4]
                break

    def check_task(self, task):
        cmd = "docker exec -it %s cloudvalidation-cli cloud-health-check "\
              "list_plugin_suites --validation-plugin fuel_health" %\
              self.container
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        result = p.split("\n")
        for line in result:
            if line.find(task) != -1:
                break
        line = line.split("|")[2].replace(" ", "")
        return line

    def _run_ostf_on_docker(self, task):
        LOG.debug("Starting task %s" % task)
        # --show-full-report
        task = self.check_task(task)
        if task is None:
            self.not_found.append(task)
        cmd = "docker exec -it %s cloudvalidation-cli "\
              "--config-file=/tmp/ostfcfg.conf cloud-health-check run_suite"\
              " --validation-plugin-name fuel_health --suite %s" %\
              (self.container, task)
        try:
            p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            LOG.error("Task %s has failed with: " % task, exc_info=True)
            self.failures.append(task)
            return
        original_output = p
        result = p.split("\n")
        failures = []
        successes = []
        for line, nline in zip(result[:-1], result[1:]):
            if line.find("Passed") != -1:
                name = nline.split("|")[2]
                self.success.append(name)
            elif line.find("Failed") != -1:
                name = nline.split("|")[2]
                self.failures.append(name)

    def run_batch(self, tasks, *args, **kwargs):
        self._setup_ostf_on_docker()
        for task in tasks:
            self.run_individual_task(task, *args, **kwargs)
        LOG.info("Succeeded tests: %s" % str(self.success))
        LOG.info("Failed tests: %s" % str(self.failures))
        LOG.info("Not found tests: %s" % str(self.not_found))

        return {"test_failures": self.failures,
                "test_success": self.success,
                "test_not_found": self.not_found}

    def run_individual_task(self, task, *args, **kwargs):
        task_id = self._run_ostf_on_docker(task)
