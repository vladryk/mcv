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


import contextlib
import copy
import functools
import operator
import time
import mock
import unittest
import StringIO
import sys
import ConfigParser

import accessor


def input_diverter(f, *args, **kwargs):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        orig_raw_input = __builtins__["raw_input"]
        f(*args, **kwargs)
        __builtins__['raw_input'] = orig_raw_input
    return inner


def bender_rodrigues(f, *args, **kwargs):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        saved_out = sys.stdout
        out = StringIO.StringIO()
        sys.stdout = out
        kwargs['out'] = out
        f(*args, **kwargs)
        sys.stdout = saved_out
    return inner


class test_AccessSteward(unittest.TestCase):
    fake_access_data_template = {"controller_ip": '10.6.7.7',
                                 "instance_ip": '10.6.7.1',
                                 "os_username": 'admin',
                                 "os_tenant_name": 'admin',
                                 "os_password": 'admin',
                                 "auth_endpoint_ip": '10.6.7.5',
                                 "nailgun_host": '10.6.7.4',
                                }

    def setUp(self):
        self.fake_config=ConfigParser.ConfigParser()
        self.fake_config.add_section('basic')
        self.accessor = accessor.AccessSteward(self.fake_config)
        self.accessor.novaclient = mock.Mock()

    @input_diverter
    def test_request_ip_ok(self):
        __builtins__['raw_input'] = lambda x: "172.16.57.41"
        with mock.patch.object(self.accessor, '_address_is_reachable') as\
                mocked_reachable:
            mocked_reachable.side_effect = [True]
            ip = self.accessor._request_ip("whatever")
        self.assertEqual(ip, "172.16.57.41")

    @input_diverter
    def test_request_ip_mistake(self):
        gen = (x for x in (None, '272.16.57.41','172.16.57.41'))
        gen.send(None)
        # this should be redone with sideeffects
        __builtins__['raw_input'] = gen.send
        with mock.patch.object(self.accessor, '_address_is_reachable') as\
                mocked_reachable:
            mocked_reachable.side_effect = [True]
            ip = self.accessor._request_ip("whatever")
        self.assertEqual(ip, "172.16.57.41")

    @input_diverter
    def test_verify_access_data_is_set_set(self):
        __builtins__['raw_input'] = lambda x: "spam"
        req_methods = filter(lambda x: x.startswith("_request"),
                             dir(self.accessor))
        req_methods.remove("_request_ip")
        mmocker = lambda x: mock.patch.object(self.accessor,x)
        fad = copy.deepcopy(self.fake_access_data_template)
        self.accessor.access_data = fad
        with contextlib.nested(*map(mmocker, req_methods)) as requests:
            self.accessor._verify_access_data_is_set()
            result = reduce(operator.add, map(lambda x: x.called, requests))
        self.assertEqual(result, 0)

    @mock.patch('accessor.LOG')
    def test_check_and_fix_floating_ips_enough(self, mock_logging):
        #self.accessor.novaclient.floating_ips = mock.Mock()
        self.accessor.novaclient.floating_ips.list.return_value =\
            ['10.0.0.2', '10.0.0.3', '10.0.0.4']
        self.accessor.check_and_fix_floating_ips()
        self.assertTrue(mock_logging.debug.called)

    @mock.patch('accessor.LOG')
    def test_check_and_fix_floating_ips_not_enough(self, mock_logging):
        self.accessor.novaclient.floating_ips = mock.Mock()
        self.accessor.novaclient.floating_ips.list.side_effect = \
            [['10.0.0.7'],['10.0.0.7', '10.0.0.8']]

        self.accessor.check_and_fix_floating_ips()
        self.assertTrue(mock_logging.info.called)

    @mock.patch('accessor.LOG')
    def test_check_and_fix_floating_ips_never_enough(self, mock_logging):
        self.accessor.novaclient.floating_ips = mock.Mock()
        self.accessor.novaclient.floating_ips.list.return_value = ['10.0.0.5']
        self.accessor.novaclient.floating_ips.create.side_effect = Exception('NO.')

        self.accessor.check_and_fix_floating_ips()
        self.assertTrue(mock_logging.warning.called)



    @mock.patch('accessor.LOG')
    def test_check_mcv_secgroup_there(self, mock_logging):
        self.accessor.novaclient.security_groups = mock.Mock()
        a=type('foo', (object,), {})
        a.name='mcv-special-group'
        b=[a, a]
        self.accessor.novaclient.security_groups.list.return_value = b
        self.assertEqual(self.accessor.check_mcv_secgroup(), None)
        #





