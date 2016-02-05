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

import ConfigParser
import datetime
import logging
import subprocess
from test_scenarios.rally import runner as rrunner
import json
import glob

import utils

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
            "-e", "OS_REGION_NAME" + self.accessor.access_data["region_name"],
            "-e", "OS_USERNAME=" + self.accessor.access_data["os_username"],
            "-e", "OS_PASSWORD=" + self.accessor.access_data["os_password"],
            "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
            "-it", "mcv-tempest"], stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()
        self._verify_rally_container_is_up()
        # here we fix glance image issues
        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        self.long_id = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint).rstrip('\n')

    def copy_tempest_image(self):
        LOG.info('Copying image files required by tempest')
        subprocess.Popen(["sudo", "chmod", "a+r",
                          "/etc/toolbox/tempest/cirros-0.3.4-x86_64-disk.img"],
                          stdout=subprocess.PIPE,
                          preexec_fn=utils.ignore_sigint).stdout.read()
        cmd = "docker exec -it %(container)s mkdir /home/rally/.rally/tempest/data" %\
              {"container": self.container_id}
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        subprocess.Popen(["sudo", "cp",
                          "/etc/toolbox/tempest/cirros-0.3.4-x86_64-disk.img",
                          "/var/lib/docker/aufs/mnt/%(id)s/home/rally/.rally/tempest/data"\
                          % {"id": self.long_id, }],
                          stdout=subprocess.PIPE,
                          preexec_fn=utils.ignore_sigint).stdout.read()

    def _run_tempest_on_docker(self, task, *args, **kwargs):
        LOG.info("Searching for installed tempest")
        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        self.long_id = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint).rstrip('\n')

        install = glob.glob('/var/lib/docker/aufs/mnt/%(id)s/home/rally/.rally/tempest/for-deployment-*'% {"id": self.long_id})
        if not install:
            LOG.info("No installation found. Installing tempest")
            cmd = "docker exec -it %(container)s rally verify install --deployment existing --source /tempest"%\
             {"container": self.container_id}

            p = subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT,
                    preexec_fn=utils.ignore_sigint)
            cirros = glob.glob('/var/lib/docker/aufs/mnt/%(id)s/home/rally/.rally/tempest/data/cirros-*'% {"id": self.long_id})
            if not cirros:
                self.copy_tempest_image()

        LOG.info("Starting verification")
        cmd = "docker exec -it %(container)s rally verify start --set %(set)s" %\
              {"container": self.container_id,
               "set": task}
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        cmd = "docker exec -it %(container)s rally verify list" %\
              {"container": self.container_id}
        try:
            p = subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT,
                    preexec_fn=utils.ignore_sigint)
        except subprocess.CalledProcessError:
            LOG.error("Task %s failed with: " % task, exc_info=True)
            return ''

        # get the last run results. This should be done in a more robust and
        # sane manner at some point.
        run = p.split('\n')[-3].split('|')[8]
        if run == 'failed':
            LOG.error('Verification failed, unable to generate report')
            return ''

        run = p.split('\n')[-3].split('|')[1]

        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        LOG.info('Generating html report')
        cmd = "docker exec -it %(container)s rally verify results --html --out=%(task)s.html" %\
              {"container": self.container_id, "task": task}
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        cmd = "sudo cp /var/lib/docker/aufs/mnt/%(id)s/home/rally/%(task)s.html %(pth)s" %\
              {"id": p.rstrip('\n'), 'task': task, "pth": self.path}
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        cmd = "docker exec -it %(container)s rally verify results --json" %\
              {"container": self.container_id}
        p = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                preexec_fn=utils.ignore_sigint)
        return p

    def parse_results(self, res, task):
        LOG.info("Parsing results")
        if res == '':
            LOG.info("Results of test set '%s': FAILURE" % task)
            self.failure_indicator = 83
            return False
        self.task = json.loads(res)
        failures = self.task.get('failures')
        success = self.task.get('success')
        LOG. info("Results of test set '%s': SUCCESS: %d FAILURES: %d" % (task, success, failures))
        for (name, case) in self.task['test_cases'].iteritems():
            if case['status'] == 'success':
                self.test_success.append(case['name'])
        if failures:
            for (name, case) in self.task['test_cases'].iteritems():
                if case['status'] == 'fail':
                    self.test_failures.append(case['name'])
                    self.failure_indicator = 81
            return False
        return True

    def run_batch(self, tasks, *args, **kwargs):
        tool_name = kwargs["tool_name"]
        all_time = kwargs["all_time"]
        elapsed_time = kwargs["elapsed_time"]

        # Note: the database execution time of each test. In the first run
        # for each test tool calculate the multiplier, which shows the
        # difference of execution time between testing on our cloud and
        # the current cloud.
        db = kwargs.get('db')
        first_run = True
        multiplier = 1.0
        current_time = 0

        try:
            max_failed_tests = int(self.config.get('tempest', 'max_failed_tests'))
        except ConfigParser.NoOptionError:
            max_failed_tests = int(self.config.get('basic', 'max_failed_tests'))

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

            self.run_individual_task(task, *args,  **kwargs)

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

                #line = '\n[' + '#'*(persent // 10) + ' '*(10 - (persent // 10)) + ']'
                line = '\nCompleted %s' % persent + '% and remaining time '
                line += '%s\n' % self.seconds_to_time(all_time * multiplier)

                LOG.info(line)

            t.append(self.task['test_cases'].keys())
            if len(self.test_failures)>max_failed_tests:
                self.total_checks = len(t)
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                self.failure_indicator = 89
                break

        if self.config.get('times', 'update') == 'True':
            f = file("/opt/mcv-consoler/times.json", "w")
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
