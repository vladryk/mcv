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

from ConfigParser import NoOptionError
import json
import os
import re
import subprocess

from mcv_consoler.common.config import DEFAULT_FAILED_TEST_LIMIT
from mcv_consoler.common.config import MOS_VERSIONS

from mcv_consoler.common.errors import CAError
from mcv_consoler.common.errors import OSTFError

from mcv_consoler.logger import LOG

from mcv_consoler.plugins.ostf.reporter import Reporter
from mcv_consoler.plugins import runner

from mcv_consoler import utils


LOG = LOG.getLogger(__name__)


class OSTFOnDockerRunner(runner.Runner):

    def __init__(self, accessor, path, *args, **kwargs):
        self.config = kwargs["config"]
        self.access_data = accessor.os_data
        self.path = path
        self.identity = "ostf"
        self.config_section = "ostf"

        try:
            self.mos_version = self.config.get(self.config_section, "version")
        except NoOptionError:
            LOG.error('No MOS version found in configuration file. '
                      'Please specify it at section "ostf" as an option'
                      '"version"')
            self.failure_indicator = CAError.CONFIG_ERROR
            return

        LOG.debug('Found MOS version: %s' % self.mos_version)

        # this object is supposed to live for one run
        # so let's leave it as is for now.
        self.test_failures = []

        self.success = []
        self.failures = []
        self.not_found = []
        self.container = None

        self.homedir = '/home/mcv/toolbox/ostf'
        self.home = '/mcv'

        super(OSTFOnDockerRunner, self).__init__()
        self.failure_indicator = OSTFError.NO_RUNNER_ERROR

        if self.config.has_option(self.config_section, 'max_failed_tests'):
            self.max_failed_tests = int(self.config.get(self.config_section,
                                                        'max_failed_tests'))
        elif self.config.has_option('basic', 'max_failed_tests'):
            self.max_failed_tests = int(self.config.get('basic',
                                                        'max_failed_tests'))
        else:
            self.max_failed_tests = DEFAULT_FAILED_TEST_LIMIT

    def _do_config_extraction(self):
        LOG.debug("Trying to obtain OSTF configuration file")
        cmd = ('docker exec -t {cid} /mcv/execute.sh fuel-ostf.{version} '
               '"ostf-config-extractor -o {path}"').format(
                   cid=self.container_id,
                   version=self.mos_version,
                   path=os.path.join(self.home, 'conf', 'ostfcfg.conf'))
        utils.run_cmd(cmd)

    def start_container(self):
        LOG.debug("Bringing up OSTF container with credentials")

        if self.mos_version not in MOS_VERSIONS:
            LOG.error("Unsupported MOS version: " + self.mos_version)
            self.failure_indicator = OSTFError.UNSUPPORTED_MOS_VERSION
            return False

        add_host = ""
        if self.access_data["auth_fqdn"]:
            add_host = "--add-host={fqdn}:{endpoint}".format(
                       fqdn=self.access_data["auth_fqdn"],
                       endpoint=self.access_data["ips"]["endpoint"])

        protocol = "https" if self.access_data['insecure'] else 'http'
        nailgun_port = str(self.access_data["fuel"]["nailgun_port"])

        LOG.debug('Trying to start OSTF container.')
        res = subprocess.Popen(
            ["docker", "run", "-d", "-P=true", ] +
            [add_host]*(add_host != "") +
            ["-p", "8080:8080",
             "-e", "OS_TENANT_NAME=" + self.access_data["tenant_name"],
             "-e", "OS_USERNAME=" + self.access_data["username"],
             "-e", "PYTHONWARNINGS=ignore",
             "-e", "NAILGUN_PROTOCOL=" + protocol,
             "-e", "OS_PASSWORD=" + self.access_data["password"],
             "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
             "-e", "NAILGUN_HOST=" + self.access_data["fuel"]["nailgun_host"],
             "-e", "NAILGUN_PORT=" + nailgun_port,
             "-e", "CLUSTER_ID=" + self.access_data["fuel"]["cluster_id"],
             "-e", "OS_REGION_NAME=" + self.access_data["region_name"],
             "-v", "%s:%s" % (self.homedir, self.home), "-w", self.home,
             "-t", "mcv-ostf"],
            stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()

        LOG.debug('Finish starting OSTF container. Result: %s' % str(res))

        return True

    def _verify_ostf_container_is_up(self):
        self.verify_container_is_up("ostf")

    def _setup_ostf_on_docker(self):
        # Find docker container:
        self._verify_ostf_container_is_up()
        self._do_config_extraction()
        p = utils.run_cmd("docker ps")
        p = p.split('\n')
        for line in p:
            elements = line.split()
            if elements[1].find("ostf") != -1:
                self.container = elements[0]
                status = elements[4]
                LOG.debug("OSTF container status: " + status)
                break

    def check_task(self, task):

        if ':' in task:
            _cmd = 'list_plugin_tests'
        else:
            _cmd = 'list_plugin_suites'

        cmd = ('docker exec -t {cid} '
               '/mcv/execute.sh fuel-ostf.{mos_version} '
               '"cloudvalidation-cli cloud-health-check {cmd} '
               '--validation-plugin fuel_health"'
               ).format(cid=self.container,
                        mos_version=self.mos_version,
                        cmd=_cmd)

        p = utils.run_cmd(cmd)
        result = p.split("\n")
        task_re = re.compile('\.%s\s+' % task)
        line = ""
        for line in result:
            if task_re.search(line):
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

        cmd = ('docker exec -t {cid} '
               '/mcv/execute.sh fuel-ostf.{mos_version} '
               '"cloudvalidation-cli '
               '--output-file={home}/ostf_report.json '
               '--config-file={home}/conf/ostfcfg.conf '
               'cloud-health-check {cmd} '
               '--validation-plugin-name fuel_health {arg} {task}"'
               ).format(cid=self.container,
                        mos_version=self.mos_version,
                        home=self.home,
                        cmd=_cmd,
                        arg=_arg,
                        task=task)

        LOG.debug('Executing command: "%s"' % cmd)
        p = utils.run_cmd(cmd)

        LOG.debug('Finish executing Cloudvalidation CLI. Result: %s' % str(p))

        try:
            results = []
            try:
                fpath = os.path.join(self.homedir, 'ostf_report.json')
                fp = open(fpath, 'r')
                results = json.loads(fp.read())
                fp.close()
                os.remove(fpath)
            except IOError as e:
                LOG.error(('Error while extracting report '
                           'from OSTF container: {err_msg}').format(
                    err_msg=str(e)))
            except OSError as e:
                LOG.error(('Error while removing report '
                           'file from container: {err_msg}').format(
                    err_msg=str(e)))
            except ValueError as e:
                LOG.error(('Error while parsing report file: {'
                           'err_msg}').format(err_msg=str(e)))

            for result in results:
                if result['result'] == 'Passed':
                    self.success.append(result['suite'])
                elif result['result'] == 'Failed':
                    self.failures.append(result['suite'])

            def fix_suite(result):
                result['suite'] = result['suite'].split(':')[1]
                return result

            map(fix_suite, results)

            reporter = Reporter(os.path.dirname(__file__))
            reporter.save_report(os.path.join(self.path, 'ostf_report.html'),
                                 'ostf_template.html', {'reports': results})

        except subprocess.CalledProcessError as e:
            LOG.error("Task %s has failed with: %s" % (task, e))
            self.failures.append(task)
            return

    def run_batch(self, tasks, *args, **kwargs):
        self._setup_ostf_on_docker()

        for task in tasks:
            self.run_individual_task(task, *args, **kwargs)

            if len(self.failures) >= self.max_failed_tests:
                self.failure_indicator = OSTFError.FAILED_TEST_LIMIT_EXCESS
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                break

        LOG.info("Succeeded tests: %s" % str(self.success))
        LOG.info("Failed tests: %s" % str(self.failures))
        LOG.info("Not found tests: %s" % str(self.not_found))

        return {"test_failures": self.failures,
                "test_success": self.success,
                "test_not_found": self.not_found}

    def run_individual_task(self, task, *args, **kwargs):
        self._run_ostf_on_docker(task)
