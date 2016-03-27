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

from common.errors import CAError
import ConfigParser
import datetime
import json
import subprocess
import logging
import os
import re
import sys
import time

import utils

# Base class for runners should be placed here.

nevermind = None

LOG = logging.getLogger(__name__)

class Runner(object):

    def __init__(self):
        self.current_task = 1
        self.test_success = []
        self.test_not_found = []
        self.failure_indicator = CAError.NO_RUNNER_ERROR
        super(Runner, self).__init__()

    def _it_ends_well(self, scenario):
        raise NotImplementedError

    def scenario_is_fine(self, scenario):
        #I am totally usure if it is needed to check for file existence
        #as it is sort of a bad idea to expect that there is an issue in
        #a pre-build tool. however as we provide an end-user with ability
        #to change settings we may run into a typo in a config.
        #probably each line retrieved from a config should be checked for
        #sanity as typos manage to creep in and ruin everything. however
        #that is a daunting task so probably not every single line.
        # very basic test for scenario correctness. It is assumed that
        # scenarios shipped with the tool are okay and are working. However
        # a typo might crawl in and cause a malfunction.
        scenario = scenario.lstrip('\n')
        entry_point = os.path.dirname(__file__)  # should be modified
        where_is_wally = os.path.join(entry_point, self.identity,
                                      'tests', scenario)
        if os.path.exists(where_is_wally) and self._it_ends_well(scenario):
            return True

        #@TODO(bartash): here we need this block, as this mechanism
        # should be restructured completely
        # In fact, if Rally scenarios are at the place they're expected to be,
        # Certification Task scenarios must be there too
        if scenario == 'certification':
                return True
        return False

    def run_individual_task(self, task, *args, **kwargs):
        """Runs a single task.

        This function has to be defined in a subclass!"""
        raise NotImplementedError

    def verify_container_is_up(self, container_name):
        # container_name == rally, shaker, ostf
        LOG.debug("Checking %s container..." % container_name)
        res = subprocess.Popen(
            ["docker", "ps"],
            stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()
        detector = re.compile("mcv-" + container_name)
        if re.search(detector, res) is not None:
            # This does not relly belongs here, better be moved someplace
            self.container_id = self._extract_container_id(container_name, res)
            LOG.debug("Container %s is fine" % container_name)
        else:
            LOG.debug("It has to be started.")
            getattr(self, "start_container")()
            time.sleep(10)  # we are in no hurry today
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

    def check_task_list(self, tasks):
        fine_to_run = filter(self.scenario_is_fine, tasks)
        rejected_tasks = [x for x in tasks if x not in fine_to_run and x != '']
        self.test_not_found = rejected_tasks
        map(tasks.remove, rejected_tasks)
        LOG.info("The following tests will be run: %s" % ", ".join(fine_to_run)) if fine_to_run else \
             LOG.error("Looks like not a single test will be run for group %s" % self.identity)
        LOG.warning("The following tasks have not been found: %s. Skipping them" % ", ".join(rejected_tasks))if rejected_tasks else nevermind


    def get_error_code(self, tool_name):

        codes = {'rally': 59,
                 'shaker': 49,
                 'resources': 39,
                 'speed': 29,
                 'ostf': 69,
                 'tempest': 89}

        return codes.get(tool_name, 11)

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

    def run_batch(self, tasks, *args, **kwargs):
        """Runs a bunch of tasks."""

        config = kwargs["config"]
        tool_name = kwargs["tool_name"]
        all_time = kwargs["all_time"]
        elapsed_time = kwargs["elapsed_time"]
        try:
            max_failed_tests = int(config.get(tool_name, 'max_failed_tests'))
        except ConfigParser.NoOptionError:
            max_failed_tests = int(config.get('basic', 'max_failed_tests'))

        self.check_task_list(tasks)
        self.total_checks = len(tasks)

        failures = 0

        # Note: the database execution time of each test. In the first run
        # for each test tool calculate the multiplier, which shows the
        # difference of execution time between testing on our cloud and
        # the current cloud.
        db = kwargs.get('db')
        first_run = True
        multiplier = 1.0
        current_time = 0

        for task in tasks:
            if kwargs.get('event').is_set():
                LOG.info("Caught keyboard interrupt. Task %s won't start" % task)
                break
            time_start = datetime.datetime.utcnow()
            LOG.info("Running " + task)
            LOG.info("Time start: %s UTC" % str(time_start))
            if self.config.get('times', 'update') == 'False':
                try:
                    current_time = db[tool_name][task]
                except KeyError:
                    current_time = 0
                LOG.info("Expected time to complete %s: %s" %
                         (task,
                          self.seconds_to_time(current_time * multiplier)))

            if self.run_individual_task(task, *args, **kwargs):
                self.test_success.append(task)
            else:
                failures += 1

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
                persent = 100 if persent > 100 else persent

                #line = '\n[' + '#'*(persent // 10) + ' '*(10 - (persent // 10)) + ']'
                line = '\nCompleted %s' % persent + '% and remaining time '
                line += '%s\n' % self.seconds_to_time(all_time * multiplier)

                LOG.info(line)

            if failures >= max_failed_tests:
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                self.failure_indicator = self.get_error_code(tool_name)
                break

        if self.config.get('times', 'update') == 'True':
            f = file("/opt/mcv-consoler/times.json", "w")
            f.write(json.dumps(db))
            f.close()

        return {"test_failures": self.test_failures, 
                "test_success": self.test_success, 
                "test_not_found": self.test_not_found}

    def _evaluate_task_results(self, task_results):
        raise NotImplementedError

    def orient_self(self):
        self.directory = os.getcwd("")
