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

import datetime
import json
import logging
import os
import subprocess

from oslo_config import cfg

from mcv_consoler.common.config import MOS_VERSIONS
from mcv_consoler.common.errors import OSTFError
from mcv_consoler.plugins.ostf.reporter import Reporter
from mcv_consoler.plugins import runner
from mcv_consoler import utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class OSTFOnDockerRunner(runner.Runner):
    failure_indicator = OSTFError.NO_RUNNER_ERROR
    identity = 'ostf'
    config_section = 'ostf'

    def __init__(self, ctx):
        super(OSTFOnDockerRunner, self).__init__(ctx)
        self.access_data = self.ctx.access_data
        self.path = self.ctx.work_dir.base_dir
        self.mos_version = self.ctx.access_data['mos_version']

        # this object is supposed to live for one run
        # so let's leave it as is for now.
        self.test_failures = []

        self.success = []
        self.failures = []
        self.not_found = []

        self.homedir = '/home/mcv/toolbox/ostf'
        self.home = '/mcv'
        self.config_filename = 'ostfcfg.conf'
        self.max_failed_tests = CONF.ostf.max_failed_tests

    def _do_config_extraction(self):
        LOG.debug("Checking for existing OSTF configuration file...")
        # NOTE(albartash): in case of multiple clouds, we probably would have
        # 5% of possibility that config for one of clouds won't be created, so
        # Consoler will try to run OSTF for one cloud using config from
        # another one. Just notice it.
        path = os.path.join(self.home, 'conf', self.config_filename)
        if os.path.isfile(path):
            LOG.debug("File '%s' exists. Skip extraction." %
                      self.config_filename)
            return

        LOG.debug("File '%s' does not exist." % self.config_filename)
        LOG.debug("Trying to obtain OSTF configuration file")
        cmd = ('docker exec -t {cid} /mcv/execute.sh fuel-ostf.{version} '
               '"ostf-config-extractor -o {path}"').format(
            cid=self.container_id,
            version=self.mos_version,
            path=path)
        utils.run_cmd(cmd)

    def start_container(self):
        LOG.debug("Bringing up OSTF container with credentials")

        if self.mos_version not in MOS_VERSIONS:
            LOG.error("Unsupported MOS version: " + self.mos_version)
            self.failure_indicator = OSTFError.UNSUPPORTED_MOS_VERSION
            return False

        add_host = ""
        if self.access_data["auth_fqdn"] != '':
            add_host = "--add-host={fqdn}:{endpoint}".format(
                fqdn=self.access_data["auth_fqdn"],
                endpoint=self.access_data["public_endpoint_ip"])

        protocol = "https" if self.access_data["insecure"] else "http"

        LOG.debug('Trying to start OSTF container.')
        res = subprocess.Popen(
            ["docker", "run", "-d", "-P=true", ] +
            [add_host] * (add_host != "") +
            ["-p", "8080:8080",
             "-e", "OS_TENANT_NAME={}".format(self.access_data["tenant_name"]),
             "-e", "OS_USERNAME={}".format(self.access_data["username"]),
             "-e", "PYTHONWARNINGS=ignore",
             "-e", "NAILGUN_PROTOCOL={}".format(protocol),
             "-e", "OS_PASSWORD={}".format(self.access_data["password"]),
             "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
             "-e", "NAILGUN_HOST={}".format(self.access_data["fuel"]["nailgun"]),
             "-e", "NAILGUN_PORT={}".format(self.access_data["fuel"]["nailgun_port"]),
             "-e", "CLUSTER_ID={}".format(self.access_data["fuel"]["cluster_id"]),
             "-e", "OS_REGION_NAME={}".format(self.access_data["region_name"]),
             "-v", "{}:{}".format(self.homedir, self.home), "-w", self.home,
             "-t", "mcv-ostf"],
            stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()

        LOG.debug('Finish starting OSTF container. Result: %s' % str(res))
        return self.verify_container_is_up()

    def _setup_ostf_on_docker(self):
        cid = self.lookup_existing_container()
        if not cid:
            self.start_container()
        self._do_config_extraction()

    def _run_ostf_on_docker(self, task):

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
               '--config-file={home}/conf/{conf_fname} '
               'cloud-health-check {cmd} '
               '--validation-plugin-name fuel_health {arg} {task}"'
               ).format(cid=self.container_id,
                        mos_version=self.mos_version,
                        home=self.home,
                        conf_fname=self.config_filename,
                        cmd=_cmd,
                        arg=_arg,
                        task=task)
        utils.run_cmd(cmd)

        try:
            results = []
            try:
                fpath = os.path.join(self.homedir, 'ostf_report.json')
                with open(fpath) as fp:
                    results = json.load(fp)
                os.remove(fpath)
                # TODO(albartash): check if we need LOG.error here
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

            def fix_suite(result):
                result['suite'] = result['suite'].split(':')[1]
                return result

            map(fix_suite, results)

            # store raw results
            self.dump_raw_results(task, results)

            for result in results:
                if result['result'] == 'Passed':
                    self.success.append(result['suite'])
                elif result['result'] == 'Failed':
                    self.failures.append(result['suite'])
                self.time_of_tests[result['suite']] = {'duration': result.get('duration', '0s')}
                LOG.info(" * %s --- %s" % (result['result'], result['suite']))

            reporter = Reporter(os.path.dirname(__file__))
            for record in results:
                reporter.save_report(
                    os.path.join(self.path, record['suite'] + '.html'),
                    'ostf_template.html',
                    {'reports': results}
                )

        except subprocess.CalledProcessError as e:
            LOG.error("Task %s has failed with: %s" % (task, e))
            self.failures.append(task)
            self.time_of_tests[task] = {'duration': '0s'}
            return

    def run_batch(self, tasks, *args, **kwargs):
        self._setup_ostf_on_docker()

        time_start = datetime.datetime.utcnow()
        LOG.info("Time start: %s UTC\n" % str(time_start))

        v = self.mos_version
        cid = self.container_id

        tasks, missing = self.discovery(cid, v).match(tasks)
        self.not_found.extend(missing)

        for task in tasks:
            self.run_individual_task(task, *args, **kwargs)

            if len(self.failures) >= self.max_failed_tests:
                self.failure_indicator = OSTFError.FAILED_TEST_LIMIT_EXCESS
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                break

        time_end = datetime.datetime.utcnow()
        LOG.info("\nTime end: %s UTC", time_end)

        return {"test_failures": self.failures,
                "test_success": self.success,
                "test_not_found": self.not_found,
                "time_of_tests": self.time_of_tests}

    def run_individual_task(self, task, *args, **kwargs):
        LOG.info("-" * 60)
        LOG.info("Starting task %s" % task)
        try:
            test_time = kwargs['db'][kwargs['tool_name']][task]
        except KeyError:
            LOG.info("You must update the database time tests. "
                     "There is no time for %s", task)
        else:
            exp_time = utils.seconds_to_humantime(test_time)
            LOG.info("Expected time to complete the test: %s ", exp_time)
        self._run_ostf_on_docker(task)
        LOG.info("-" * 60)
