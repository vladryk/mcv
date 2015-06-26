import re
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
default_config = "etc/mcv.conf"


class OSTFOnDockerRunner(runner.Runner):

    def __init__(self):
        self.identity = "ostf"
        self.config_section = "ostf"
        self.test_failures = []  # this object is supposed to live for one run
                                 # so let's leave it as is for now.
        self.success = []
        self.failures = []
        self.not_found = []
        self.container = None
        super(OSTFOnDockerRunner, self).__init__()

    def _setup_ostf_on_docker(self):
        # Find docker container:
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
        LOG.log_arbitrary("Starting task %s" % task)
        # --show-full-report
        task = self.check_task(task)
        if task is None:
            self.not_found.append(task)
        cmd = "docker exec -it %s cloudvalidation-cli "\
              "--config-file=/tmp/ostfcfg.conf cloud-health-check run_suite"\
              " --validation-plugin-name fuel_health --suite %s" %\
              (self.container, task)
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
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

    def run_batch(self, tasks):
        self._setup_ostf_on_docker()
        for task in tasks:
            self.run_individual_task(task)
        LOG.log_arbitrary("Succeeded tests: %s" % str(self.success))
        LOG.log_arbitrary("Failed tests: %s" % str(self.failures))
        LOG.log_arbitrary("Not found tests: %s" % str(self.not_found))

        return {"test_failures": self.failures,
                "test_success": self.success,
                "test_not_found": self.not_found}

    def run_individual_task(self, task):
        task_id = self._run_ostf_on_docker(task)
