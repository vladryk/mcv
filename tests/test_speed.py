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

import accessor
import test_scenarios.speed.speed_tester as st
import test_scenarios.speed.runner as runner


class FakeReporter():
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
                                 "nailgun_host": '10.6.7.4',
                                }

    def setUp(self):
        self.accessor = accessor.AccessSteward('fake-config')
        self.accessor.access_data = self.fake_access_data_template
        self.accessor.novaclient = mock.Mock()


class TestSpeedRunner(BaseTestCase):

    def test_evaluate_result_pass(self):
        run = runner.SpeedTestRunner(self.accessor, 'fake-path')
        res = run._evaluate_task_results([80, 80])
        self.assertTrue(res)

    def test_evaluate_result_fail(self):
        run = runner.SpeedTestRunner(self.accessor, 'fake-path')
        res = run._evaluate_task_results([10, 80])
        self.assertFalse(res)

    def test_wrong_task(self):
        run = runner.SpeedTestRunner(self.accessor, 'fake-path', config={'fake': 'fake'})
        res = run.run_individual_task('fake-task')
        self.assertFalse(res)
