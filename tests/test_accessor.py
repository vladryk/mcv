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
        self.accessor = accessor.AccessSteward()
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
    @bender_rodrigues
    def test_request_ip_unreachable(self, out):
        gen = (x for x in (None, '10.16.57.51', '172.16.57.41'))
        gen.send(None)
        __builtins__['raw_input'] = gen.send
        with mock.patch.object(self.accessor, '_address_is_reachable') as\
                mocked_reachable:
            mocked_reachable.side_effect = [False, True]
            ip = self.accessor._request_ip("whatever")
        output = out.getvalue().strip()
        self.assertEqual(ip, "172.16.57.41")
        self.assertEqual(output, "Address 10.16.57.51 is unreachable.")

    @input_diverter
    def test_verify_access_data_is_set_empty_dict(self):
        __builtins__['raw_input'] = lambda x: "spam"
        req_methods = filter(lambda x: x.startswith("_request"),
                             dir(self.accessor))
        req_methods.remove("_request_ip")
        mmocker = lambda x: mock.patch.object(self.accessor,x)
        with contextlib.nested(*map(mmocker, req_methods)) as requests:
            self.accessor._verify_access_data_is_set()
            result = reduce(operator.mul, map(lambda x: x.called, requests))
        self.assertEqual(result, 1)

    @input_diverter
    def test_verify_access_data_is_set_missing_value(self):
        __builtins__['raw_input'] = lambda x: "spam"
        req_methods = filter(lambda x: x.startswith("_request"),
                             dir(self.accessor))
        req_methods.remove("_request_ip")
        mmocker = lambda x: mock.patch.object(self.accessor,x)
        for method in req_methods:
            field_name = method.lstrip("_request_")
            fad = copy.deepcopy(self.fake_access_data_template)
            fad[field_name] = None
            self.accessor.access_data = fad
            with mmocker(method) as mock_method:
                self.accessor._verify_access_data_is_set()
                self.assertEqual(mock_method.called, True)

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

    @mock.patch("subprocess.Popen")
    @bender_rodrigues
    def test_verify_container_is_up_up(self, mcp, out):
        with mock.patch.object(self.accessor, 'extract_rally_container_id') as\
                extractor:
            proc_mock = mock.Mock()
            attrs = {"stdout.read.return_value": """c310bf7d96cd        """\
                     """mcv-rally           "/bin/sh -c 'bash --   4 days """\
                     """ago          Up 4 days           0.0.0.0:6000->600"""\
                     """0/tcp """}
            proc_mock.configure_mock(**attrs)
            mcp.return_value = proc_mock
            self.accessor._verify_container_is_up("rally")
            self.assertEqual(extractor.called, True)

    @mock.patch("subprocess.Popen")
    @bender_rodrigues
    def test_verify_container_is_up_down(self, mcp, out=0):
        with mock.patch.object(self.accessor, 'extract_rally_container_id') as\
                mock_extractor,\
                mock.patch.object(self.accessor, 'start_rally_container') as\
                mock_starter,\
                mock.patch.object(time, 'sleep') as mock_sleep:
            proc_mock = mock.Mock()
            gen = (x for x in ["""ham""", """c310bf7d96cd        mcv-rally"""\
                               """"/bin/sh -c 'bash --   4 days ago       """\
                               """Up 4 days           0.0.0.0:6000->6000/t"""\
                               """cp """])
            attrs = {"stdout.read": gen.next}
            proc_mock.configure_mock(**attrs)
            mcp.return_value = proc_mock
            mock_sleep.return_value = True
            mock_starter.return_value = True
            self.accessor._verify_container_is_up("rally")
            self.assertEqual(mock_starter.called, True)
            self.assertEqual(mock_extractor.called, True)

    @bender_rodrigues
    def test_check_and_fix_floating_ips_enough(self, out):
        self.accessor.novaclient.floating_ips = mock.Mock()
        self.accessor.novaclient.floating_ips.list.return_value =\
            ['10.0.0.2', '10.0.0.3', '10.0.0.4']
        self.accessor.check_and_fix_floating_ips()

        self.assertEqual(out.getvalue().strip(), "Apparently there is "
                                                 "enough floating ips")

    @bender_rodrigues
    def test_check_and_fix_floating_ips_not_enough(self, out):
        self.accessor.novaclient.floating_ips = mock.Mock()
        self.accessor.novaclient.floating_ips.list.side_effect = \
            [['10.0.0.7'],['10.0.0.7', '10.0.0.8']]

        self.accessor.check_and_fix_floating_ips()
        self.assertNotEqual(out.getvalue().strip().find("Need to create"),
                                                -1)

    @bender_rodrigues
    def test_check_and_fix_floating_ips_never_enough(self, out):
        self.accessor.novaclient.floating_ips = mock.Mock()
        self.accessor.novaclient.floating_ips.list.return_value = ['10.0.0.5']
        self.accessor.novaclient.floating_ips.create.side_effect = Exception('NO.')

        self.accessor.check_and_fix_floating_ips()
        self.assertNotEqual(out.getvalue().strip().find("Apparently"), -1)

    @bender_rodrigues
    def test_check_and_fix_flavor_not_found(self, out):
        fake_flavor = mock.Mock()
        fake_flavor.name = 'm1.nano'
        self.accessor.novaclient.flavors = mock.Mock()
        self.accessor.novaclient.flavors.list.side_effect = [[], [fake_flavor]]
        self.accessor._check_and_fix_flavor()
        self.assertNotEqual(out.getvalue().strip().find("Apparently"), -1)
        self.assertNotEqual(out.getvalue().strip().find("Proper"), -1)

    @bender_rodrigues
    def test_check_and_fix_flavor_found(self, out):
        fake_flavor = mock.Mock()
        fake_flavor.name = 'm1.nano'
        self.accessor.novaclient.flavors = mock.Mock()
        self.accessor.novaclient.flavors.list.return_value = [fake_flavor]
        self.accessor._check_and_fix_flavor()
        self.assertNotEqual(out.getvalue().strip().find("Proper"), -1)

    @bender_rodrigues
    def test_check_mcvsecgroup_there(self, out):
        self.accessor.novaclient.security_groups = mock.Mock()
        self.accessor.novaclient.security_groups.list.return_value = ['fake_group']
        self.accessor.check_mcv_secgroup()
        self.assertEqual(self.accessor.novaclient.security_groups.list.called, True)

    @bender_rodrigues
    def test_check_mcvsecgroup_not_there(self, out):
        self.accessor.novaclient.security_groups = mock.Mock()
        self.accessor.novaclient.security_group_rules = mock.Mock()
        self.accessor.novaclient.servers = mock.Mock()
        self.accessor.novaclient.security_groups.list.return_value = []
        self.accessor.novaclient.servers.list.return_value = ['fake_server']

        self.accessor.check_mcv_secgroup()
        self.assertEqual(self.accessor.novaclient.security_groups.create.called, True)
        self.assertEqual(self.accessor.novaclient.security_group_rules.create.called, True)
        self.assertEqual(self.accessor.novaclient.servers.add_security_group.called, True)

