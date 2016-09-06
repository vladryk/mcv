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

import mock
import unittest

from mcv_consoler import accessor
import mcv_consoler.plugins.speed.runner as runner


class FakeReporter(object):
    html = 'fake-html'
    r_av = 'fake-r-speed'
    w_av = 'fake-w-speed'

    def measure_speed(self):
        return self.html, self.r_av, self.w_av


class BaseTestCase(unittest.TestCase):
    fake_access_data_template = {"controller_ip": '10.6.7.7',
                                 "instance_ip": '10.6.7.1',
                                 "os_username": 'admin',
                                 "os_tenant_name": 'admin',
                                 "os_password": 'admin',
                                 "auth_endpoint_ip": '10.6.7.5',
                                 "nailgun_host": '10.6.7.4'}

    def setUp(self):
        self.accessor = accessor.AccessSteward({'qwe': 'fake'})
        self.accessor.access_data = self.fake_access_data_template
        self.accessor.novaclient = mock.Mock()


class TestSpeedRunner(BaseTestCase):

    def test_scenario_fine(self):
        run = runner.SpeedTestRunner(self.accessor, 'fake-path', config='qwe')
        run.scenario_is_fine('fake')

    def test_it_ends_well(self):
        run = runner.SpeedTestRunner(self.accessor, 'fake-path', config='qwe')
        run._it_ends_well('fake')

    def test_evaluate_result_pass(self):
        fake_config = {}
        run = runner.SpeedTestRunner(self.accessor,
                                     'fake-path',
                                     config=fake_config)

        run._evaluate_task_results([80])

    def test_evaluate_result_fail(self):
        fake_config = {}
        run = runner.SpeedTestRunner(self.accessor,
                                     'fake-path',
                                     config=fake_config)

        res = run._evaluate_task_results([10])
        self.assertFalse(res)

    def test_wrong_task(self):
        run = runner.SpeedTestRunner(self.accessor,
                                     'fake-path',
                                     config={'fake': 'fake'})

        res = run.run_individual_task('fake-task')
        self.assertFalse(res)
