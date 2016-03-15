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
from ConfigParser import NoOptionError
from test_scenarios.ostf.reporter import Reporter
try:
    import json
except:
    import simplejson as json

import utils

nevermind = None

default_config = "etc/mcv.conf"

LOG = logging

class OSTFOnDockerRunner(runner.Runner):

    def __init__(self, accessor, path, *args, **kwargs):
        self.config = kwargs["config"]
        self.accessor = accessor
        self.path = path
        self.identity = "ostf"
        self.config_section = "ostf"
        self.test_failures = []  # this object is supposed to live for one run
                                 # so let's leave it as is for now.
        self.success = []
        self.failures = []
        self.not_found = []
        self.container = None
        super(OSTFOnDockerRunner, self).__init__()
        self.failure_indicator = 60

    def _do_config_extraction(self):
        LOG.info( "Preparing OSTF")
        res = subprocess.Popen(["docker", "exec", "-t",
                                self.container_id,
                                "ostf-config-extractor", "-o",
                                "/tmp/ostfcfg.conf"],
                               stdout=subprocess.PIPE,
                               preexec_fn=utils.ignore_sigint).stdout.read()
        LOG.debug("Config extraction resulted in: " + res)

    def start_ostf_container(self):
        LOG.debug( "Bringing up OSTF container with credentials")
        mos_version = self.config.get("ostf", "version")
        #@TODO(albartash): Remove tname when migrating to single ostf
        # container!
        if mos_version == "6.1":
            cname = "mcv-ostf61"
            tname = "ostf61"
        elif mos_version == "7.0":
            cname = "mcv-ostf70"
            tname = "ostf70"
        else:
            LOG.error("Unsupported MOS version: " + mos_version)
            sys.exit(33)

        add_host = ""
        if self.config.get("basic", "auth_fqdn") != '':
            add_host = "--add-host={fqdn}:{endpoint}".format(
                       fqdn=self.config.get("basic", "auth_fqdn"),
                       endpoint=self.accessor.access_data["auth_endpoint_ip"])

        res = subprocess.Popen(["docker", "run", "-d", "-P=true",] +
            [add_host]*(add_host != "") +
            ["-p", "8080:8080", #"-e", "OS_AUTH_URL=http://" +
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
            "-e", "OS_REGION_NAME=" + self.accessor.access_data["region_name"],
            "-v", "/home/mcv/toolbox/%s:/mcv" % tname, "-w", "/mcv",
            "-t", cname], stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()

    def _verify_ostf_container_is_up(self):
        self.verify_container_is_up("ostf")

    def _setup_ostf_on_docker(self):
        # Find docker container:
        self._verify_ostf_container_is_up()
        self._do_config_extraction()
        p = subprocess.check_output("docker ps", shell=True,
                                    stderr=subprocess.STDOUT,
                                    preexec_fn=utils.ignore_sigint)
        p = p.split('\n')
        for line in p:
            elements = line.split()
            if elements[1].find("ostf") != -1:
                self.container = elements[0]
                status = elements[4]
                break

    def check_task(self, task):
        if ':' in task:
            _cmd = 'list_plugin_tests'
        else:
            _cmd = 'list_plugin_suites'
        cmd = "docker exec -t %s cloudvalidation-cli cloud-health-check "\
              "%s --validation-plugin fuel_health" %\
              (self.container, _cmd)

        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        result = p.split("\n")
        for line in result:
            if line.find(task) != -1:
                break
        line = line.split("|")[2].replace(" ", "")
        return line

    def _run_ostf_on_docker(self, task):
        LOG.debug("Starting task %s" % task)
        task = self.check_task(task)
        if task is None:
            self.not_found.append(task)
            return

        # The task can be either a test or suite
        if ':' in task:
            _cmd = 'run_test'
            _arg = '--test'
        else:
            _cmd = 'run_suite'
            _arg = '--suite'

        cmd = "docker exec -t {container} cloudvalidation-cli "\
              "--raw --output-file=/tmp/ostf_report.json "\
              "--config-file=/tmp/ostfcfg.conf cloud-health-check {cmd} "\
              "--validation-plugin-name fuel_health {arg} {task}".format(
              container=self.container,
              cmd=_cmd,
              arg=_arg,
              task=task)
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)

        try:
            cmd = "sudo docker cp %(id)s:/tmp/ostf_report.json /tmp/ostf_report.json" \
                  % {"id": self.container}

            p = subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT,
                    preexec_fn=utils.ignore_sigint)

            cmd = "docker exec -t {container} rm /tmp/ostf_report.json".format(
                  container=self.container)
            p = subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT,
                    preexec_fn=utils.ignore_sigint)

            results = []
            try:
                fp = open('/tmp/ostf_report.json', 'r')
                results = json.loads(fp.read())
                fp.close()
                os.remove('/tmp/ostf_report.json')
            except IOError as e:
                LOG.error('Error while extracting report from OSTF container: {err_msg}'.format(
                    err_msg=str(e)))
            except OSError as e:
                LOG.error('Error while removing report file from container: {err_msg}'.format(
                    err_msg=str(e)))

            for result in results:
                if result['result'] == 'Passed':
                    self.success.append(result['suite'])
                elif result['result'] == 'Failed':
                    self.failures.append(result['suite'])


            def fix_suite(result):
                result['suite'] = result['suite'].split(':')[1]
                return result

            map(fix_suite, results)

            #@TODO(albartash): Replace path to folder when we have a single
            # place for templates!
	    folder = os.path.dirname(__file__)
            reporter = Reporter(folder)
            reporter.save_report(os.path.join(self.path, 'ostf_report.html'),
                                 'ostf_template.html', {'reports': results})

        except subprocess.CalledProcessError as e:
            LOG.error("Task %s has failed with: %s" % (task, e))
            self.failures.append(task)
            return

    def run_batch(self, tasks, *args, **kwargs):
        self._setup_ostf_on_docker()

        try:
            max_failed_tests = int(self.config.get('ostf', 'max_failed_tests'))
        except NoOptionError:
            max_failed_tests = int(self.config.get('basic', 'max_failed_tests'))

        for task in tasks:
            self.run_individual_task(task, *args, **kwargs)

            if len(self.failures) >= max_failed_tests:
                self.failure_indicator = 69
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                break

        LOG.info("Succeeded tests: %s" % str(self.success))
        LOG.info("Failed tests: %s" % str(self.failures))
        LOG.info("Not found tests: %s" % str(self.not_found))

        return {"test_failures": self.failures,
                "test_success": self.success,
                "test_not_found": self.not_found}

    def run_individual_task(self, task, *args, **kwargs):
        task_id = self._run_ostf_on_docker(task)
