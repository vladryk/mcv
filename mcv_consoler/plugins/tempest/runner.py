#    Copyright 2015-2016 Mirantis, Inc
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
import datetime
import json
import logging
import os.path
import subprocess
import traceback

from oslo_config import cfg

from mcv_consoler.common.config import DEFAULT_CIRROS_IMAGE
from mcv_consoler.common.config import TIMES_DB_PATH
from mcv_consoler.common.errors import TempestError
from mcv_consoler.plugins.rally import runner as rrunner
from mcv_consoler import utils


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

tempest_additional_conf = {
    'compute':
        {'fixed_network_name': CONF.networking.network_ext_name},
    'object-storage':
        {'operator_role': 'admin',
         'reseller_admin_role': 'admin'}

}


class TempestOnDockerRunner(rrunner.RallyOnDockerRunner):
    failure_indicator = TempestError.NO_RUNNER_ERROR
    identity = 'tempest'

    def __init__(self, ctx):
        super(TempestOnDockerRunner, self).__init__(ctx)
        self.path = self.ctx.work_dir.base_dir
        self.container = None
        self.failed_cases = 0
        self.home = '/mcv'
        self.homedir = '/home/mcv/toolbox/tempest'

    def _verify_rally_container_is_up(self):
        self.verify_container_is_up("tempest")

    def create_cirros_image(self):
        i_list = self.glanceclient.images.list()
        for im in i_list:
            if im.name == 'mcv-test-functional-cirros':
                return im.id

        img_fp = None
        try:
            img_fp = open(DEFAULT_CIRROS_IMAGE)
        except IOError as e:
            LOG.debug('Cannot open file {path}: {err}'.format(
                path=DEFAULT_CIRROS_IMAGE,
                err=str(e)))
            return
        im = self.glanceclient.images.create(name='mcv-test-functional-cirros',
                                             disk_format="qcow2",
                                             is_public=True,
                                             container_format="bare",
                                             data=img_fp)

    def cleanup_cirros_image(self):
        self.cleanup_image('mcv-test-functional-cirros')

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

        self.verify_container_is_up()
        self._patch_rally()

        # Hotfix. set rally's permission for .rally/ folder
        # Please remove this. Use: `sudo -u rally docker run` when
        # rally user gets its permissions to start docker containers
        cmd = 'docker exec -t {cid} sudo chown rally:rally /home/rally/.rally'
        utils.run_cmd(cmd.format(cid=self.container_id))
        self.copy_config()
        self.install_tempest()

    def _patch_rally(self):
        dist = '/tempest/requirements.txt'
        LOG.debug('Patching tempest requirements')
        tempest_patch = '/mcv/custom_patches/requirements.patch'
        self._os_patch(dist, tempest_patch, self.container_id)

        git_commit_cmd = (
            'cd /tempest && git config --global user.name  \"mcv-team\" && '
            'git config --global user.email '
            '\"mirantis-cloud-validation-support@mirantis.com\" && '
            'sudo git add . && sudo git commit -m \"added markupsafe to '
            'requirements, which is needed for pbr\"')
        utils.run_cmd('docker exec -t {cid} sh -c "{cmd}"'.format(
            cid=self.container_id,
            cmd=git_commit_cmd))

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

        # store tempest.conf
        self.store_config(os.path.join(self.homedir,
                                       "for-deployment-{ID}/tempest.conf"
                                       .format(ID=deployment_id)))

        self.store_config(os.path.join(self.homedir, "conf/existing.json"))

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
              '&& echo -n yes || echo -n no'.format(cid=self.container_id,
                                                    out_file=details_file)
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

    def install_tempest(self):
        LOG.debug("Searching for installed tempest")
        super(TempestOnDockerRunner, self)._rally_deployment_check()

        LOG.debug("Generating additional config")
        path_to_conf = os.path.join(self.homedir, 'additional.conf')
        with open(path_to_conf, 'wb') as conf_file:
            config = ConfigParser.ConfigParser()
            config._sections = tempest_additional_conf
            config.write(conf_file)

        LOG.debug("Installing tempest...")
        cmd = ("docker exec -t {cid} "
               "rally verify install --system-wide "
               "--deployment existing --source /tempest").format(
            cid=self.container_id)

        utils.run_cmd(cmd, quiet=True)
        cmd = "docker exec -t %(container)s rally verify genconfig " \
              "--add-options %(conf_path)s" % \
              {"container": self.container_id,
               "conf_path": os.path.join(self.home, 'additional.conf')}

        utils.run_cmd(cmd, quiet=True)

    def _run_tempest_on_docker(self, task, *args, **kwargs):

        LOG.debug("Starting verification")
        run_by_name = kwargs.get('run_by_name')
        if run_by_name:
            cmd = ("docker exec -t {cid} rally "
                   "--log-file {home}/log/tempest.log --rally-debug"
                   " verify start --system-wide "
                   "--regex {_set}").format(cid=self.container_id,
                                            home=self.home,
                                            _set=task)
        else:
            cmd = ("docker exec -t {cid} rally "
                   "--log-file {home}/log/tempest.log --rally-debug"
                   " verify start --system-wide "
                   "--set {_set}").format(cid=self.container_id,
                                          home=self.home,
                                          _set=task)
        utils.run_cmd(cmd, quiet=True)

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

        reports_dir = os.path.join(self.homedir, 'reports')
        cmd = "cp {reports}/{task}.html {path} ".format(
            reports=reports_dir, task=task, path=self.path)
        utils.run_cmd(cmd, quiet=True)

        try:
            self.make_detailed_report(task)
        except Exception:
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

    def cleanup_toolbox(self):
        LOG.info('Uninstalling tempest ...')
        cmd = ('docker exec -t {cid} ' 'rally verify uninstall '
               '--deployment existing'.format(cid=self.container_id))
        utils.run_cmd(cmd, quiet=True)

    def run_batch(self, tasks, *args, **kwargs):
        with self.store('rally.log', 'tempest.log'):
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
            test_time = 0
            all_time -= elapsed_time

            self.create_cirros_image()
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
                if not CONF.times.update:
                    try:
                        test_time = db[tool_name][task]
                    except KeyError:
                        test_time = 0

                    exp_time = utils.seconds_to_humantime(test_time *
                                                          multiplier)
                    msg = "Expected time to complete %s: %s"
                    if not test_time:
                        LOG.debug(msg, task, exp_time)
                    else:
                        LOG.info(msg, task, exp_time)

                self.run_individual_task(task, *args, **kwargs)

                time_end = datetime.datetime.utcnow()
                time = time_end - time_start
                LOG.debug("Time end: %s UTC" % str(time_end))

                if CONF.times.update:
                    if tool_name in db.keys():
                        db[tool_name].update({task: time.seconds})
                    else:
                        db.update({tool_name: {task: time.seconds}})
                else:
                    if first_run:
                        first_run = False
                        if test_time:
                            multiplier = float(time.seconds) / float(test_time)
                    all_time -= test_time
                    persent = 1.0
                    if kwargs["all_time"]:
                        persent -= float(all_time) / float(kwargs["all_time"])
                    persent = int(persent * 100)
                    persent = 100 if persent > 100 else persent

                    line = 'Completed %s' % persent + '%'
                    time_str = utils.seconds_to_humantime(all_time *
                                                          multiplier)
                    if all_time and multiplier:
                        line += ' and remaining time %s' % time_str

                    LOG.info(line)
                    LOG.info("-" * 60)

                t.append(self.task['test_cases'].keys())

                tempest_task_results_details[task] = {
                    # overall number of tests in suit
                    "tests": self.task.get("tests", 0),
                    "test_succeed": self.task.get("success", 0),
                    "test_failed": self.task.get("failures", 0),
                    "test_skipped": self.task.get("skipped", 0),
                    "expected_failures": self.task.get("expected_failures", 0)
                }
                if self.failed_cases > CONF.tempest.max_failed_tests:
                    LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                    self.failure_indicator = \
                        TempestError.FAILED_TEST_LIMIT_EXCESS
                    break

            if CONF.times.update:
                with open(TIMES_DB_PATH, "w") as f:
                    json.dump(db, f)

            LOG.info("\nTime end: %s UTC" % str(datetime.datetime.utcnow()))
            self.cleanup_toolbox()
            self.cleanup_cirros_image()
            return {"test_failures": self.test_failures,
                    "test_success": self.test_success,
                    "test_not_found": self.test_not_found,
                    "time_of_tests": self.time_of_tests,
                    "tempest_tests_details": tempest_task_results_details,
                    }

    def run_individual_task(self, task, *args, **kwargs):
        results = self._run_tempest_on_docker(task, *args, **kwargs)

        # store raw results
        self.dump_raw_results(task, results)

        self.parse_results(results, task)
        return True
