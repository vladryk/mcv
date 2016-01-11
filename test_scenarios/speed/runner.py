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
import ConfigParser

import test_scenarios.runner as run
from test_scenarios.speed.prepare_instance import Preparer
from test_scenarios.speed import speed_tester as st

LOG = logging


class SpeedTestRunner(run.Runner):

    def __init__(self, accessor, path, *args, **kwargs):
        # Need accessor for access data
        self.accessor = accessor
        self.identity = "speed"
        self.config_section = "speed"
        self.config = kwargs.get('config')
        self.test_failures = []
        self.path = path
        super(SpeedTestRunner, self).__init__()
        self.failure_indicator = 20

    def scenario_is_fine(self, scenario):
        return True

    def _it_ends_well(self, scenario):
        return True

    def _evaluate_task_results(self, task_results):
        res = True
        try:
            threshold = self.config.get('speed', 'threshold')
        except ConfigParser.NoOptionError:
            LOG.info('Default threshold is 50 Mb/s')
            threshold = 50
        for speed in task_results:
            if speed < int(threshold):
                res = False
                LOG.warning('Average speed is under the threshold')
                break
        return res

    def _prepare_vm(self):
        tenant = self.accessor.access_data['os_tenant_name']
        auth_url = self.config.get('basic', 'auth_protocol') + "://"
        auth_url += self.accessor.access_data["auth_endpoint_ip"]
        auth_url += ":5000/v2.0/"
        myPreparer = Preparer(uname=self.accessor.access_data['os_username'],
                              passwd=self.accessor.access_data['os_password'],
                              tenant=tenant,
                              auth_url=auth_url)
        return myPreparer.prepare_instance()

    def _remove_vm(self):
        myPreparer = Preparer()
        myPreparer.delete_instance()

    def run_batch(self, tasks, *args, **kwargs):
        self._prepare_vm()
        res = super(SpeedTestRunner, self).run_batch(tasks)
        self._remove_vm()
        return res

    def generate_report(self, html, task):
        # Append last run to existing file for now. Not sure how to fix this properly
        LOG.debug('Generating report in speed.html file')
        report = file('%s/%s.html' % (self.path, task), 'w')
        report.write(html)
        report.close()

    def run_individual_task(self, task, *args, **kwargs):
        # runs a set of commands
        try:
            i_s = self.config.get('speed', 'image_size')
        except ConfigParser.NoOptionError:
            LOG.info('Use default image sise 1Gb')
            i_s = 1
        try:
            v_s = self.config.get('speed', 'volume_size')
        except ConfigParser.NoOptionError:
            LOG.info('Use default volume sise 1Gb')
            v_s = 1
        LOG.debug('Start generating %s' %task)
        try:
            speed_class = getattr(st, task)
        except AttributeError:
            LOG.error('Incorrect task')
            return False
        reporter = speed_class(self.accessor.access_data, image_size=i_s, volume_size=v_s, config=self.config, *args, **kwargs)
        try:
            res, r_average, w_average = reporter.measure_speed()
        except RuntimeError:
            LOG.error('Failed to measure speed')
            self.test_failures.append(task)
            return False
        self.generate_report(res, task)
        if self._evaluate_task_results([r_average, w_average]):
            return True
        else:
            self.test_failures.append(task)
            return False
