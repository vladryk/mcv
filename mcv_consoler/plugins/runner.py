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
import json
import os
import re
import subprocess
import time

from mcv_consoler.common.config import DEFAULT_FAILED_TEST_LIMIT
from mcv_consoler.common.errors import BaseSelfCheckError
from mcv_consoler.common.errors import CAError
from mcv_consoler.common.errors import OSTFError
from mcv_consoler.common.errors import RallyError
from mcv_consoler.common.errors import ResourceError
from mcv_consoler.common.errors import ShakerError
from mcv_consoler.common.errors import SpeedError
from mcv_consoler.common.errors import TempestError

from mcv_consoler.logger import LOG
from mcv_consoler import utils


LOG = LOG.getLogger(__name__)


class Runner(object):

    def __init__(self):
        self.current_task = 1
        self.test_success = []
        self.test_not_found = []
        self.time_of_tests = {}
        self.failure_indicator = CAError.NO_RUNNER_ERROR
        super(Runner, self).__init__()

    def run_individual_task(self, task, *args, **kwargs):
        raise NotImplementedError

    def verify_container_is_up(self, container_name):
        # TODO(albartash): We need to re-investigate this method.
        # It looks unsafe a little.

        LOG.debug("Checking %s container..." % container_name)
        res = subprocess.Popen(
            ["docker", "ps"],
            stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()
        detector = re.compile("mcv-" + container_name)
        if re.search(detector, res) is not None:
            # TODO(albartash): This does not relly belongs here,
            # better be moved someplace
            self.container_id = self._extract_container_id(container_name, res)
            LOG.debug("Container %s is fine" % container_name)
        else:
            LOG.debug("It has to be started.")
            getattr(self, "start_container")()
            time.sleep(10)
            return self.verify_container_is_up(container_name)

    def _extract_container_id(self, container_name, output):
        output = output.split('\n')
        container_name = "mcv-" + container_name
        container_id = ""
        for line in output:
            if re.search(container_name, line) is not None:
                container_id = line[0:12]

        if not container_id:
            LOG.critical('Cannot extract container ID. '
                         'Please check container name.')

        return container_id

    def get_error_code(self, tool_name):

        codes = {'ostf': OSTFError.FAILED_TEST_LIMIT_EXCESS,
                 'rally': RallyError.FAILED_TEST_LIMIT_EXCESS,
                 'resources': ResourceError.FAILED_TEST_LIMIT_EXCESS,
                 'selfcheck': BaseSelfCheckError.FAILED_TEST_LIMIT_EXCESS,
                 'shaker': ShakerError.FAILED_TEST_LIMIT_EXCESS,
                 'speed': SpeedError.FAILED_TEST_LIMIT_EXCESS,
                 'tempest': TempestError.FAILED_TEST_LIMIT_EXCESS}

        return codes[tool_name]

    def seconds_to_time(self, s):
        s = int(round(s))
        h = s // 3600
        m = (s // 60) % 60
        sec = s % 60

        if m < 10:
            m = str('0' + str(m))
        else:
            m = str(m)
        if sec < 10:
            m = str(m)
        if sec < 10:
            sec = str('0' + str(sec))
        else:
            sec = str(sec)

        return str(h) + 'h : ' + str(m) + 'm : ' + str(sec) + 's'

    def _validate_test_params(self, **params):
        for key in 'compute', 'concurrency':
            if key not in params:
                continue
            if not isinstance(params[key], int):
                LOG.warning("Type mismatch. Parameter '%s' expected to be "
                            "an %s. Got: %s" % (key, int, type(key)))

    def run_batch(self, tasks, *args, **kwargs):
        """Runs a bunch of tasks."""

        config = kwargs["config"]
        tool_name = kwargs["tool_name"]
        all_time = kwargs["all_time"]
        elapsed_time = kwargs["elapsed_time"]
        try:
            max_failed_tests = int(config.get(tool_name, 'max_failed_tests'))
        except NoOptionError:
            max_failed_tests = DEFAULT_FAILED_TEST_LIMIT

        LOG.debug("The following tests will be run:")
        LOG.debug("\n".join(tasks))
        self.total_checks = len(tasks)

        failures = 0

        # Note(ayasakov): the database execution time of each test.
        # In the first run for each test tool calculate the multiplier,
        # which shows the difference of execution time between testing
        # on our cloud and the current cloud.

        db = kwargs.get('db')
        first_run = True
        multiplier = 1.0
        current_time = 0
        all_time -= elapsed_time

        self._validate_test_params(**kwargs)

        for task in tasks:
            LOG.info("-" * 60)
            if kwargs.get('event').is_set():
                LOG.info("Caught keyboard interrupt. "
                         "Task %s won't start" % task)
                break
            time_start = datetime.datetime.utcnow()
            LOG.debug("Running task " + task)                   # was info
            LOG.debug("Time start: %s UTC" % str(time_start))   # was info
            if self.config.get('times', 'update') == 'False':
                try:
                    current_time = db[tool_name][task]
                except KeyError:
                    current_time = 0

                msg = "Expected time to complete %s: %s" % (task,
                    self.seconds_to_time(current_time * multiplier))
                if not current_time:
                    LOG.debug(msg)
                else:
                    LOG.info(msg)

            if self.run_individual_task(task, *args, **kwargs):
                self.test_success.append(task)
            else:
                failures += 1

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
                if all_time and multiplier:
                    line += ' and remaining time %s' % self.seconds_to_time(all_time * multiplier)
                LOG.info(line)
                LOG.info("-" * 60)

            if failures >= max_failed_tests:
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                self.failure_indicator = self.get_error_code(tool_name)
                break

        if self.config.get('times', 'update') == 'True':
            f = file("/etc/mcv/times.json", "w")
            f.write(json.dumps(db))
            f.close()

        return {"test_failures": self.test_failures,
                "test_success": self.test_success,
                "test_not_found": self.test_not_found,
                "time_of_tests": self.time_of_tests}

    def _evaluate_task_results(self, task_results):
        raise NotImplementedError

    def orient_self(self):
        self.directory = os.getcwd("")
