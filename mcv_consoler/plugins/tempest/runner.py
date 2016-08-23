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
import traceback

from mcv_consoler.common.config import DEFAULT_FAILED_TEST_LIMIT
from mcv_consoler.common.config import TIMES_DB_PATH
from mcv_consoler.common.errors import TempestError
from mcv_consoler.logger import LOG
from mcv_consoler.plugins.rally import runner as rrunner
from mcv_consoler import utils

LOG = LOG.getLogger(__name__)


class TempestOnDockerRunner(rrunner.RallyOnDockerRunner):
    def __init__(self, access_data, path, *args, **kwargs):
        super(TempestOnDockerRunner, self).__init__(access_data,
                                                    path,
                                                    *args,
                                                    **kwargs)

        self.config = kwargs["config"]
        self.path = path
        self.container = None
        self.identity = 'tempest'
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
        if self.access_data["auth_fqdn"] != '':
            add_host = "--add-host={fqdn}:{endpoint}".format(
                fqdn=self.access_data["auth_fqdn"],
                endpoint=self.access_data["public_endpoint_ip"])

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
        self._patch_rally()

        # Hotfix. set rally's permission for .rally/ folder
        # Please remove this. Use: `sudo -u rally docker run` when
        # rally user gets its permissions to start docker containers
        cmd = 'docker exec -t {cid} sudo chown rally:rally /home/rally/.rally'
        utils.run_cmd(cmd.format(cid=self.container_id))

        self.copy_config()

    def _patch_rally(self):
        dist = '/tempest/requirements.txt'
        LOG.debug('Patching tempest requirements')
        tempest_patch = '/mcv/custom_patches/requirements.patch'
        self._os_patch(dist, tempest_patch, self.container_id)

        git_commit_cmd = 'cd /tempest && ' \
                         'git config --global user.name  \"mcv-team\" && ' \
                         'git config --global user.email \"mirantis-cloud-validation-support@mirantis.com\" && ' \
                         'sudo git add . && ' \
                         'sudo git commit -m \"added markupsafe to requirements, which is needed for pbr\"'
        utils.run_cmd('docker exec -t {cid} sh -c "{cmd}"'.format(
            cid=self.container_id,
            cmd=git_commit_cmd))

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

    def make_detailed_report(self, task):
        LOG.debug('Generating detailed report')
        details_dir = os.path.join(self.home, 'reports/details/')
        details_file = os.path.join(details_dir, task + '.txt')

        cmd = "docker exec -t %(cid)s " \
              "rally deployment list | grep existing | awk \'{print $2}\'" \
              % dict(cid=self.container_id)
        deployment_id = utils.run_cmd(cmd, quiet=True).strip()

        cmd = 'docker exec -t {cid} mkdir -p {out_dir}'
        utils.run_cmd(cmd.format(cid=self.container_id, out_dir=details_dir),
                      quiet=True)

        # Note(ogrytsenko): tool subunit2pyunit returns exit code '1' if
        # at leas one test failed in a test suite. It also returns exit
        # code '1' if some error occurred during processing a file, like:
        # "Permission denied".
        # We force 'exit 0' here and will check the real status lately
        # by calling 'test -e <details_file>'
        cmd = 'docker exec -t {cid} /bin/sh -c \" ' \
              'subunit2pyunit /mcv/for-deployment-{ID}/subunit.stream ' \
              '2> {out_file}\"; ' \
              'exit 0'.format(cid=self.container_id,
                              ID=deployment_id,
                              out_file=details_file)
        out = utils.run_cmd(cmd, quiet=True)

        cmd = 'docker exec -t {cid} test -e {out_file} ' \
              '&& echo -n yes || echo -n no'.format(
            cid=self.container_id, out_file=details_file)
        exists = utils.run_cmd(cmd)
        if exists == 'no':
            LOG.debug('ERROR: Failed to create detailed report for '
                      '{task} set. Output: {out}'.format(task=task, out=out))
            return

        cmd = 'mkdir -p {path}/details'.format(path=self.path)
        utils.run_cmd(cmd, quiet=True)
        reports_dir = os.path.join(self.homedir, 'reports')
        cmd = 'cp {reports}/details/{task}.txt {path}/details'
        utils.run_cmd(
            cmd.format(reports=reports_dir, task=task, path=self.path),
            quiet=True
        )
        LOG.debug(
            "Finished creating detailed report for '{task}'. "
            "File: {details_file}".format(task=task, details_file=details_file)
        )

    def _run_tempest_on_docker(self, task, *args, **kwargs):
        LOG.debug("Searching for installed tempest")
        super(TempestOnDockerRunner, self)._rally_deployment_check()
        install = glob.glob(self.homedir + '/for-deployment-*')
        run_by_name = kwargs.get('run_by_name')
        if not install:
            LOG.debug("No Tempest installation found. Installing tempest...")
            cmd = ("docker exec -t {cid} "
                   "rally verify install "
                   "--deployment existing --source /tempest").format(
                cid=self.container_id)

            p = utils.run_cmd(cmd, quiet=True)
            cmd = "docker exec -t %(container)s rally verify genconfig" % \
                  {"container": self.container_id}

            p = utils.run_cmd(cmd, quiet=True)
            cirros = glob.glob(self.homedir + '/data/cirros-*')
            if not cirros:
                self.copy_tempest_image()
        LOG.debug("Starting verification")

        if run_by_name:
            cmd = ("docker exec -t {cid} rally "
                   "--log-file {home}/log/tempest.log --rally-debug"
                   " verify start --regex {_set}").format(cid=self.container_id,
                                                          home=self.home,
                                                          _set=task)
        else:
            cmd = ("docker exec -t {cid} rally "
                   "--log-file {home}/log/tempest.log --rally-debug"
                   " verify start --set {_set}").format(cid=self.container_id,
                                                        home=self.home,
                                                        _set=task)
        p = utils.run_cmd(cmd, quiet=True)

        cmd = "docker exec -t {cid} rally verify list".format(
            cid=self.container_id)

        # TODO(ogrytsenko): double-check this approach
        try:
            p = utils.run_cmd(cmd)
        except subprocess.CalledProcessError as e:
            LOG.error("Task %s failed with: %s" % (task, e))
            return ''

        run = p.split('\n')[-3].split('|')[8]
        if run == 'failed':
            LOG.error('Verification failed, unable to generate report')
            return ''

        LOG.debug('Generating html report')
        cmd = ("docker exec -t {cid} rally verify results --html "
               "--out={home}/reports/{task}.html").format(
            cid=self.container_id, home=self.home, task=task)
        utils.run_cmd(cmd, quiet=True)

        cmd = ('docker exec -t {cid} cp {home}/reports/{task}.html '
               '/home/rally/.rally/tempest').format(cid=self.container_id,
                                                    home=self.home,
                                                    task=task)
        utils.run_cmd(cmd, quiet=True)

        reports_dir = os.path.join(self.homedir, 'reports')
        cmd = "cp {reports}/{task}.html {path} ". \
            format(reports=reports_dir, task=task, path=self.path)
        utils.run_cmd(cmd, quiet=True)

        try:
            self.make_detailed_report(task)
        except:
            LOG.debug('ERROR: \n' + traceback.format_exc())

        cmd = "docker exec -t {cid} /bin/sh -c " \
              "\"rally verify results --json 2>/dev/null\" "\
              .format(cid=self.container_id)

        return utils.run_cmd(cmd, quiet=True)

    def parse_results(self, res, task):
        LOG.debug("Parsing results")
        if res == '':
            LOG.debug("Results of test set '%s': FAILURE" % task)
            self.failure_indicator = TempestError.VERIFICATION_FAILED
            self.test_failures.append(task)
            LOG.info(" * FAILED")
            return False

        try:
            self.task = json.loads(res)
        except ValueError:
            LOG.debug("Results of test set '%s': "
                      "FAILURE, gotten not-JSON object. "
                      "Please see logs" % task)
            LOG.debug("Not-JSON object: %s", res)
            self.test_failures.append(task)
            LOG.info(" * FAILED")
            return False

        time_of_tests = float(self.task.get('time', '0'))
        time_of_tests = str(round(time_of_tests, 3)) + 's'
        self.time_of_tests[task] = {'duration': time_of_tests}

        if self.task.get('tests', 0) == 0:
            self.test_failures.append(task)
            LOG.debug("Task '%s' was skipped. Perhaps the service "
                      "is not working" % task)
            LOG.info(" * FAILED")
            return False

        failures = self.task.get('failures')
        success = self.task.get('success')
        self.failed_cases += failures
        LOG.debug("Results of test set '%s': "
                  "SUCCESS: %d FAILURES: %d" % (task, success, failures))
        if not failures:
            self.test_success.append(task)
            LOG.info(" * PASSED")
            return True
        else:
            self.test_failures.append(task)
            self.failure_indicator = TempestError.TESTS_FAILED
            LOG.info(" * FAILED")
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
        all_time -= elapsed_time

        try:
            max_failed_tests = int(self.config.get('tempest',
                                                   'max_failed_tests'))
        except NoOptionError:
            max_failed_tests = DEFAULT_FAILED_TEST_LIMIT

        self._setup_rally_on_docker()

        # NOTE(ogrytsenko): only test-suites are discoverable for tempest
        if not kwargs.get('run_by_name'):
            cid = self.container_id
            tasks, missing = self.discovery(cid).match(tasks)
            self.test_not_found.extend(missing)

        t = []
        tempest_task_results_details = {}
        LOG.info("Time start: %s UTC\n" % str(datetime.datetime.utcnow()))
        for task in tasks:
            LOG.info("-" * 60)
            task = task.replace(' ', '')
            if kwargs.get('event').is_set():
                LOG.info("Keyboard interrupt. Set %s won't start" % task)
                break
            time_start = datetime.datetime.utcnow()
            LOG.info('Running %s tempest set' % task)

            LOG.debug("Time start: %s UTC" % str(time_start))
            if self.config.get('times', 'update') == 'False':
                try:
                    current_time = db[tool_name][task]
                except KeyError:
                    current_time = 0

                msg = "Expected time to complete %s: %s" \
                      % (task,
                         self.seconds_to_time(current_time * multiplier))
                if not current_time:
                    LOG.debug(msg)
                else:
                    LOG.info(msg)

            self.run_individual_task(task, *args, **kwargs)

            time_end = datetime.datetime.utcnow()
            time = time_end - time_start
            LOG.debug("Time end: %s UTC" % str(time_end))

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
                all_time -= current_time
                persent = 1.0
                if kwargs["all_time"]:
                    persent -= float(all_time) / float(kwargs["all_time"])
                persent = int(persent * 100)
                persent = 100 if persent > 100 else persent

                line = 'Completed %s' % persent + '%'
                time_to_string = self.seconds_to_time(all_time * multiplier)
                if all_time and multiplier:
                    line += ' and remaining time %s' % time_to_string

                LOG.info(line)
                LOG.info("-" * 60)

            t.append(self.task['test_cases'].keys())
            if self.failed_cases > max_failed_tests:
                self.total_checks = len(t)
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                self.failure_indicator = TempestError.FAILED_TEST_LIMIT_EXCESS
                break

            tempest_task_results_details[task] = {
                # overall number of tests in suit
                "tests": self.task.get("tests", 0),
                "test_succeed": self.task.get("success", 0),
                "test_failed": self.task.get("failures", 0),
                "test_skipped": self.task.get("skipped", 0),
                "expected_failures": self.task.get("expected_failures", 0)
            }

        if self.config.get('times', 'update') == 'True':
            f = file(TIMES_DB_PATH, "w")
            f.write(json.dumps(db))
            f.close()

        self.total_checks = len(t)
        LOG.info("\nTime end: %s UTC" % str(datetime.datetime.utcnow()))
        return {"test_failures": self.test_failures,
                "test_success": self.test_success,
                "test_not_found": self.test_not_found,
                "time_of_tests": self.time_of_tests,
                "tempest_tests_details": tempest_task_results_details,
                }

    def run_individual_task(self, task, *args, **kwargs):
        results = self._run_tempest_on_docker(task, *args, **kwargs)
        self.parse_results(results, task)
        return True
