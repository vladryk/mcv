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
import subprocess
import logging
import os
import re
import sys
import time

# Base class for runners should be placed here.

nevermind = None

LOG = logging.getLogger(__name__)

class Runner(object):

    def __init__(self):
        self.current_task = 1
        self.test_success = []
        self.test_not_found = []
        self.failure_indicator = 10
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
        res = subprocess.Popen(["docker", "ps"],
            stdout=subprocess.PIPE).stdout.read()
        detector = re.compile("mcv-" + container_name)
        if re.search(detector, res) is not None:
            # This does not relly belongs here, better be moved someplace
            self.container_id = self._extract_container_id(container_name, res)
            LOG.debug("Container %s is fine" % container_name)
        else:
            LOG.debug("It has to be started.")
            getattr(self, "start_" + container_name + "_container")()
            time.sleep(10)  # we are in no hurry today
            return self.verify_container_is_up(container_name)

    def _extract_container_id(self, container_name, output):
        output = output.split('\n')
        container_name = "mcv-" + container_name
        for line in output:
            if re.search(container_name, line) is not None:
                container_id = line[0:12]
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
                 'dummy': 79,
                 'tempest': 89}

        return codes.get(tool_name, 11)


    def run_batch(self, tasks, *args, **kwargs):
        """Runs a bunch of tasks."""

        config = kwargs["config"]
        tool_name = kwargs["tool_name"]
        try:
            max_failed_tests = int(config.get(tool_name, 'max_failed_tests'))
        except ConfigParser.NoOptionError:
            max_failed_tests = int(config.get('basic', 'max_failed_tests'))

        self.check_task_list(tasks)
        self.total_checks = len(tasks)

        failures = 0
        for task in tasks:
            LOG.info("Running "+ task)
            if self.run_individual_task(task, *args, **kwargs):
                self.test_success.append(task)
            else:
                failures += 1

            if failures >= max_failed_tests:
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                self.failure_indicator = self.get_error_code(tool_name)
                break

        return {"test_failures": self.test_failures, 
                "test_success": self.test_success, 
                "test_not_found": self.test_not_found}

    def _evaluate_task_results(self, task_results):
        raise NotImplementedError

    def orient_self(self):
        self.directory = os.getcwd("")
