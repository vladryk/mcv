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

from mcv_consoler.common.errors import ResourceError
import datetime
from mcv_consoler.log import LOG
from mcv_consoler.plugins.resources import resource_reporter as resources
import mcv_consoler.plugins.runner as run

LOG = LOG.getLogger(__name__)


class ResourceReportRunner(run.Runner):
    failure_indicator = ResourceError.NO_RUNNER_ERROR
    identity = 'resources'
    config_section = 'resources'

    def __init__(self, ctx):
        super(ResourceReportRunner, self).__init__(ctx)
        self.config = self.ctx.config
        self.access_data = self.ctx.access_data
        self.path = self.ctx.work_dir
        self.test_failures = []

    def _evaluate_task_results(self, task_results):
        return True

    def run_batch(self, tasks, *args, **kwargs):
        LOG.info("Time start: %s UTC\n" % str(datetime.datetime.utcnow()))

        tasks, missing = self.discovery.match(tasks)
        self.test_not_found.extend(missing)

        result = super(ResourceReportRunner, self).run_batch(tasks, *args,
                                                             **kwargs)
        LOG.info("\nTime end: %s UTC" % str(datetime.datetime.utcnow()))
        return result

    def generate_report(self, html, task):

        # TODO(ekudryashova): Append last run to existing file for now.
        # Not sure how to fix this properly

        LOG.debug('Generating report in resources.html file')
        report = file('%s/%s.html' % (self.path, task), 'w')
        report.write(html)
        report.close()

    def run_individual_task(self, task, *args, **kwargs):
        LOG.info('Running task %s' % task)
        time_start = datetime.datetime.utcnow()
        reporter_class = getattr(resources, task)
        if not reporter_class:
            LOG.error('Incorrect choice of reporter')
            LOG.info(" * FAILED")
            return False
        reporter = reporter_class(self.access_data, config=self.config)
        res = reporter.search_resources()
        time_end = datetime.datetime.utcnow()
        time_of_tests = str(round((time_end - time_start).total_seconds(), 3)) + 's'
        self.time_of_tests[task] = {'duration': time_of_tests}
        self.generate_report(res, task)
        LOG.info(" * PASSED")
        return True
