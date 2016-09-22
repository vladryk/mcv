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

import logging

from mcv_consoler.common.errors import BaseSelfCheckError
import mcv_consoler.plugins.runner as run
from mcv_consoler.plugins.selfcheck import selfcheck_tester as st

LOG = logging.getLogger(__name__)


class SelfCheckRunner(run.Runner):
    failure_indicator = BaseSelfCheckError.SELF_CHECK_WRONG_RUNNER
    identity = 'selfcheck'

    def __init__(self, ctx):
        super(SelfCheckRunner, self).__init__(ctx)
        self.test_failures = []

    def _evaluate_task_results(self, task_results):
        for task_result in task_results:
            if task_result is not True:
                self.failure_indicator = task_result
                return False
        return True

    def run_batch(self, tasks, *args, **kwargs):
        tasks, missing = self.discovery.match(tasks)
        self.test_not_found.extend(missing)
        return super(SelfCheckRunner, self).run_batch(tasks, *args,
                                                      **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
        selfcheck_class = getattr(st, task)
        if not selfcheck_class:
            LOG.error('Incorrect selfcheck class')
            return False
        scheck = selfcheck_class()
        res = scheck.run()

        # store raw results
        self.dump_raw_results(task, res)

        if self._evaluate_task_results(res):
            return True
        else:
            self.test_failures.append(task)
            return False
