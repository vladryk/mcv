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
import datetime
import glob
import json
import os.path
import shlex
import subprocess

from mcv_consoler.common.config import DEFAULT_FAILED_TEST_LIMIT
from mcv_consoler.common.errors import TempestError
from mcv_consoler.logger import LOG
from mcv_consoler.plugins.rally import runner as rrunner
from mcv_consoler import utils


LOG = LOG.getLogger(__name__)


class TempestOnDockerRunner(rrunner.RallyOnDockerRunner):

    def __init__(self, accessor, path, *args, **kwargs):
        super(TempestOnDockerRunner, self).__init__(accessor,
                                                    path,
                                                    *args,
                                                    **kwargs)

        self.config = kwargs["config"]
        self.path = path
        self.container = None
        self.failed_cases = 0
        self.home = '/mcv'
        self.homedir = '/home/mcv/toolbox/tempest'
        self.failure_indicator = TempestError.NO_RUNNER_ERROR

    def _verify_rally_container_is_up(self):
        self.verify_container_is_up("tempest")

    def start_container(self):
        LOG.debug("Bringing up Tempest container with credentials")
        add_host = ""
        # TODO(albartash): Refactor this place!
        if self.config.get("auth", "auth_fqdn") != '':
            add_host = "--add-host={fqdn}:{endpoint}".format(
                fqdn=self.access_data["auth_fqdn"],
                endpoint=self.access_data["ips"]["endpoint"])

        res = subprocess.Popen(
            ["docker", "run", "-d", "-P=true"] +
            [add_host] * (add_host != "") +
            ["-p", "6001:6001",
             "-e", "OS_AUTH_URL=" + self.access_data["auth_url"],
             "-e", "OS_TENANT_NAME=" + self.access_data["tenant_name"],
             "-e", "OS_REGION_NAME" + self.access_data["region_name"],
             "-e", "OS_USERNAME=" + self.access_data["username"],
             "-e", "OS_PASSWORD=" + self.access_data["password"],
             "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
             "-v", '%s:/home/rally/.rally/tempest' % self.homedir,
             "-v", "%s:%s" % (self.homedir, self.home), "-w", self.home,
             "-t", "mcv-tempest"],
            stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()

        LOG.debug('Finish bringing up Tempest container.'
                  'ID = %s' % str(res))

        self._verify_rally_container_is_up()
        self.copy_config()

    def copy_tempest_image(self):
        LOG.info('Copying image files required by tempest')
        # here we fix glance image issues
        subprocess.Popen(["sudo", "chmod", "a+r",
                         os.path.join(self.home,
                                      "images",
                                      "cirros-0.3.4-x86_64-disk.img")],
                         stdout=subprocess.PIPE,
                         preexec_fn=utils.ignore_sigint).stdout.read()

        cmd = "mkdir " + os.path.join(self.homedir, "data")
        utils.run_cmd(cmd)

        cmd = ("sudo ln -s {homedir}/images/cirros-0.3.4-x86_64-disk.img "
               "{homedir}/data/").format(homedir=self.homedir)

        cmd = shlex.split(cmd)

        subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         preexec_fn=utils.ignore_sigint).stdout.read()

    def _run_tempest_on_docker(self, task, *args, **kwargs):
        LOG.info("Searching for installed tempest")
        super(TempestOnDockerRunner, self)._rally_deployment_check()
        install = glob.glob(self.homedir + '/for-deployment-*')
        if not install:
            LOG.info("No installation found. Installing tempest")
            cmd = ("docker exec -t {cid} "
                   "sudo rally verify install "
                   "--deployment existing --source /tempest").format(
                cid=self.container_id)

            p = utils.run_cmd(cmd)
            cmd = "docker exec -t %(container)s sudo rally verify genconfig" %\
                  {"container": self.container_id}

            p = utils.run_cmd(cmd)
            cirros = glob.glob(self.homedir + '/data/cirros-*')
            if not cirros:
                self.copy_tempest_image()
        LOG.info("Starting verification")
        cmd = ("docker exec -t {cid} sudo rally "
               "--log-file {home}/log/tempest.log --rally-debug"
               " verify start --set {_set}").format(cid=self.container_id,
                                                    home=self.home,
                                                    _set=task)
        p = utils.run_cmd(cmd)

        cmd = "docker exec -t {cid} rally verify list".format(
            cid=self.container_id)

        try:
            p = utils.run_cmd(cmd)
        except subprocess.CalledProcessError as e:
            LOG.error("Task %s failed with: %s" % (task, e))
            return ''

        run = p.split('\n')[-3].split('|')[8]
        if run == 'failed':
            LOG.error('Verification failed, unable to generate report')
            return ''

        run = p.split('\n')[-3].split('|')[1]

        LOG.info('Generating html report')
        cmd = ("docker exec -t {cid} sudo rally verify results --html "
               "--out={home}/reports/{task}.html").format(
            cid=self.container_id, home=self.home, task=task)

        p = utils.run_cmd(cmd)

        cmd = ('docker exec -it {cid} sudo cp {home}/reports/{task}.html '
               '/home/rally/.rally/tempest').format(cid=self.container_id,
                                                    home=self.home,
                                                    task=task)

        p = utils.run_cmd(cmd)

        cmd = "sudo cp {homedir}/{task}.html {path}".format(
            homedir=self.homedir, task=task, path=self.path)
        p = utils.run_cmd(cmd)

        cmd = "docker exec -t {cid} rally verify results --json".format(
            cid=self.container_id)
        p = utils.run_cmd(cmd)

        return p

    def parse_results(self, res, task):
        LOG.info("Parsing results")
        if res == '':
            LOG.info("Results of test set '%s': FAILURE" % task)
            self.failure_indicator = TempestError.VERIFICATION_FAILED
            return False

        try:
            self.task = json.loads(res)
        except ValueError:
            LOG.info("Results of test set '%s': "
                     "FAILURE, gotten not-JSON object. "
                     "Please see logs" % task)
            LOG.debug("Not-JSON object: %s", res)
            return False

        failures = self.task.get('failures')
        success = self.task.get('success')
        self.failed_cases += failures
        LOG.info("Results of test set '%s': "
                 "SUCCESS: %d FAILURES: %d" % (task, success, failures))
        if not failures:
            self.test_success.append(task)
            return True
        else:
            self.test_failures.append(task)
            self.failure_indicator = TempestError.TESTS_FAILED
            return False

    def run_batch(self, tasks, *args, **kwargs):
        tool_name = kwargs["tool_name"]
        all_time = kwargs["all_time"]
        elapsed_time = kwargs["elapsed_time"]

        # Note (ayasakov): the database execution time of each test.
        # In the first run for each test tool calculate the multiplier,
        # which shows the difference of execution time between testing
        # on our cloud and the current cloud.

        db = kwargs.get('db')
        first_run = True
        multiplier = 1.0
        current_time = 0

        try:
            max_failed_tests = int(self.config.get('tempest',
                                                   'max_failed_tests'))
        except NoOptionError:
            max_failed_tests = DEFAULT_FAILED_TEST_LIMIT

        self._setup_rally_on_docker()
        t = []
        for task in tasks:
            task = task.replace(' ', '')
            if kwargs.get('event').is_set():
                LOG.info("Keyboard interrupt. Set %s won't start" % task)
                break
            time_start = datetime.datetime.utcnow()
            LOG.info('Running %s tempest set' % task)

            LOG.info("Time start: %s UTC" % str(time_start))
            if self.config.get('times', 'update') == 'False':
                try:
                    current_time = db[tool_name][task]
                except KeyError:
                    current_time = 0
                LOG.info("Expected time to complete %s: %s" %
                         (task,
                          self.seconds_to_time(current_time * multiplier)))

            self.run_individual_task(task, *args, **kwargs)

            time_end = datetime.datetime.utcnow()
            time = time_end - time_start
            LOG.info("Time end: %s UTC" % str(time_end))

            if self.config.get('times', 'update') == 'True':
                if tool_name in db.keys():
                    db[tool_name].update({task: time.seconds})
                else:
                    db.update({tool_name: {task: time.seconds}})
            else:
                if first_run:
                    first_run = False
                    if current_time:
                        multiplier = float(time.seconds) / float(current_time)
                all_time -= (current_time + elapsed_time)
                persent = 1.0
                if kwargs["all_time"]:
                    persent -= float(all_time) / float(kwargs["all_time"])
                persent = int(persent * 100)

                line = '\nCompleted %s' % persent + '% and remaining time '
                line += '%s\n' % self.seconds_to_time(all_time * multiplier)

                LOG.info(line)

            t.append(self.task['test_cases'].keys())
            if self.failed_cases > max_failed_tests:
                self.total_checks = len(t)
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                self.failure_indicator = TempestError.FAILED_TEST_LIMIT_EXCESS
                break

        if self.config.get('times', 'update') == 'True':
            f = file("/etc/mcv/times.json", "w")
            f.write(json.dumps(db))
            f.close()

        self.total_checks = len(t)
        return {"test_failures": self.test_failures,
                "test_success": self.test_success,
                "test_not_found": self.test_not_found}

    def run_individual_task(self, task, *args, **kwargs):
        results = self._run_tempest_on_docker(task, *args, **kwargs)

        self.parse_results(results, task)
        return True
