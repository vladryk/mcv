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

import logging

import test_scenarios.runner as run
from test_scenarios.resources import resource_reporter as resources

LOG = logging


class ResourceReportRunner(run.Runner):

    def __init__(self, accessor, *args, **kwargs):
        # Need accessor for access data
        self.config = kwargs.get("config")
        self.accessor = accessor
        self.identity = "resources"
        self.config_section = "resources"
        self.test_failures = []
        super(ResourceReportRunner, self).__init__()
        self.failure_indicator = 30

    def scenario_is_fine(self, scenario):
        return True

    def _it_ends_well(self, scenario):
        return True

    def _evaluate_task_results(self, task_results):
        return True

    def run_batch(self, tasks, *args, **kwargs):
        return super(ResourceReportRunner, self).run_batch(tasks, *args,
                                                           **kwargs)

    def generate_report(self, html, task):
        # Append last run to existing file for now. Not sure how to fix this properly
        LOG.debug('Generating report in resources.html file')
        report = file('%s.html' % task, 'w')
        report.write(html)
        report.close()

    def run_individual_task(self, task, *args, **kwargs):
        # runs a set of commands
        LOG.debug('Start generating %s' %task)
        reporter_class = getattr(resources, task)
        if not reporter_class:
            LOG.error('Incorrect choice of reporter')
            return False
        reporter = reporter_class(self.accessor.access_data, config=self.config)
        res = reporter.search_resources()
        self.generate_report(res, task)
        return True