import contextlib
import copy
import functools
import operator
import time
import imp
import mock
import unittest
import StringIO
import sys
import subprocess
accessor = imp.load_source("accessor", "../mcv-consoler/accessor.py")

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
    def _test_check_and_fix_floating_ips_enough(self, out):
        command_run_result = """
+--------------+--------------------------------------+---------------+-----------+
| Ip           | Server Id                            | Fixed Ip      | Pool      |
+--------------+--------------------------------------+---------------+-----------+
| 172.16.57.43 | -                                    | -             | net04_ext |
| 172.16.57.41 | 76dfd8ec-c64a-4941-8617-03171199ea14 | 192.168.111.5 | net04_ext |
| 172.16.57.44 | -                                    | -             | net04_ext |
+--------------+--------------------------------------+---------------+-----------+
        """
        with mock.patch.object(self.accessor,
                "_run_os_command_in_container") as mocked_runner:
            mocked_runner.return_value = command_run_result
            self.accessor.check_and_fix_floating_ips()
            self.assertEqual(out.getvalue().strip(),"Apparently there is "\
                             "enough floating ips")

    @bender_rodrigues
    def test_check_and_fix_floating_ips_not_enough(self, out):
        command_run_result1 = r"""
+--------------+--------------------------------------+---------------+-----------+
| Ip           | Server Id                            | Fixed Ip      | Pool      |
+--------------+--------------------------------------+---------------+-----------+
| 172.16.57.41 | 76dfd8ec-c64a-4941-8617-03171199ea14 | 192.168.111.5 | net04_ext |
| 172.16.57.44 | -                                    | -             | net04_ext |
+--------------+--------------------------------------+---------------+-----------+
        """
        command_run_result2 = r"""
+--------------+--------------------------------------+---------------+-----------+
| Ip           | Server Id                            | Fixed Ip      | Pool      |
+--------------+--------------------------------------+---------------+-----------+
| 172.16.57.43 | -                                    | -             | net04_ext |
| 172.16.57.41 | 76dfd8ec-c64a-4941-8617-03171199ea14 | 192.168.111.5 | net04_ext |
| 172.16.57.44 | -                                    | -             | net04_ext |
+--------------+--------------------------------------+---------------+-----------+
        """
        ip_create_result1 = """
+--------------+-----------+----------+-----------+
| Ip           | Server Id | Fixed Ip | Pool      |
+--------------+-----------+----------+-----------+
| 172.16.57.46 | -         | -        | net04_ext |
+--------------+-----------+----------+-----------+
        """
        def foo(*args, **kwargs):
            foo.counter += 1
            ret_vals = {1: command_run_result1, 2: ip_create_result1,
                        3: command_run_result2}
            return ret_vals[foo.counter]
        foo.counter = 0
        with mock.patch.object(self.accessor,
                "_run_os_command_in_container") as mocked_runner:
            mocked_runner.side_effect = foo
            self.accessor.check_and_fix_floating_ips()
            self.assertNotEqual(out.getvalue().strip().find("Need to create"),
                                -1)

    @bender_rodrigues
    def test_check_and_fix_floating_ips_never_enough(self, out):
        command_run_result1 = r"""
+--------------+--------------------------------------+---------------+-----------+
| Ip           | Server Id                            | Fixed Ip      | Pool      |
+--------------+--------------------------------------+---------------+-----------+
| 172.16.57.41 | 76dfd8ec-c64a-4941-8617-03171199ea14 | 192.168.111.5 | net04_ext |
+--------------+--------------------------------------+---------------+-----------+
        """
        ip_create_result1 = """
ERROR (NotFound): No more floating ips available. (HTTP 404) (Request-ID: req-49154145-2d65-4126-ba6b-87a5c3c057a9)
        """
        def foo(*args, **kwargs):
            foo.counter += 1
            ret_vals = {1: command_run_result1, 2: ip_create_result1,}
            return ret_vals[foo.counter]
        foo.counter = 0
        with mock.patch.object(self.accessor,
                "_run_os_command_in_container") as mocked_runner:
            mocked_runner.side_effect = foo
            self.accessor.check_and_fix_floating_ips()
            self.assertNotEqual(out.getvalue().strip().find("Apparently"), -1)

    @bender_rodrigues
    def test_check_and_fix_flavor_not_found(self, out):
        command_run_result1 = r"""
+--------------------------------------+---------------+-----------+------+-----------+------+-------+-------------+-----------+
| ID                                   | Name          | Memory_MB | Disk | Ephemeral | Swap | VCPUs | RXTX_Factor | Is_Public |
+--------------------------------------+---------------+-----------+------+-----------+------+-------+-------------+-----------+
+--------------------------------------+---------------+-----------+------+-----------+------+-------+-------------+-----------+
        """
        command_run_result2 = r"""
+--------------------------------------+---------------+-----------+------+-----------+------+-------+-------------+-----------+
| ID                                   | Name          | Memory_MB | Disk | Ephemeral | Swap | VCPUs | RXTX_Factor | Is_Public |
+--------------------------------------+---------------+-----------+------+-----------+------+-------+-------------+-----------+
| 42                                   | m1.nano       | 128       | 0    | 0         |      | 1     | 1.0         | True      |
+--------------------------------------+---------------+-----------+------+-----------+------+-------+-------------+-----------+
        """
        def foo(*args, **kwargs):
            foo.counter += 1
            ret_vals = {1: command_run_result1, 2: True,
                        3: command_run_result2}
            return ret_vals[foo.counter]
        foo.counter = 0
        with mock.patch.object(self.accessor,
                "_run_os_command_in_container") as mocked_runner,\
                mock.patch.object(time, "sleep") as mocked_sleep:
            mocked_runner.side_effect = foo
            mocked_sleep.return_value = True
            self.accessor._check_and_fix_flavor()
            self.assertNotEqual(out.getvalue().strip().find("Apparently"), -1)
            self.assertNotEqual(out.getvalue().strip().find("Proper"), -1)

    @bender_rodrigues
    def test_check_and_fix_flavor_found(self, out):
        command_run_result = r"""
+--------------------------------------+---------------+-----------+------+-----------+------+-------+-------------+-----------+
| ID                                   | Name          | Memory_MB | Disk | Ephemeral | Swap | VCPUs | RXTX_Factor | Is_Public |
+--------------------------------------+---------------+-----------+------+-----------+------+-------+-------------+-----------+
| 42                                   | m1.nano       | 128       | 0    | 0         |      | 1     | 1.0         | True      |
+--------------------------------------+---------------+-----------+------+-----------+------+-------+-------------+-----------+
        """
        def foo(*args, **kwargs):
            foo.counter += 1
            ret_vals = {1: command_run_result,}
            return ret_vals[foo.counter]
        foo.counter = 0
        with mock.patch.object(self.accessor,
                "_run_os_command_in_container") as mocked_runner:
            mocked_runner.side_effect = foo
            self.accessor._check_and_fix_flavor()
            self.assertNotEqual(out.getvalue().strip().find("Proper"), -1)

    @bender_rodrigues
    def test_check_mcvsecgroup_there(self, out):
        command_run_result = r"""
+--------------------------------------+-------------------+-------------+
| Id                                   | Name              | Description |
+--------------------------------------+-------------------+-------------+
| 44135f83-91f4-431a-86d5-5ba88e8897a6 | default           | default     |
| b2007c5d-090e-4344-9549-583ca5cad576 | mcv-special-group | mcvgroup    |
+--------------------------------------+-------------------+-------------+
        """
        def foo(*args, **kwargs):
            foo.counter += 1
            ret_vals = {1: command_run_result,}
            return ret_vals[foo.counter]
        foo.counter = 0
        with mock.patch.object(self.accessor,
                "_run_os_command_in_container") as mocked_runner:
            mocked_runner.side_effect = foo
            self.accessor.check_mcv_secgroup()
            self.assertEqual(mocked_runner.called, True)

    @bender_rodrigues
    def test_check_mcvsecgroup_not_there(self, out):
        command_run_result1 = r"""
+--------------------------------------+-------------------+-------------+
| Id                                   | Name              | Description |
+--------------------------------------+-------------------+-------------+
| 44135f83-91f4-431a-86d5-5ba88e8897a6 | default           | default     |
+--------------------------------------+-------------------+-------------+
        """
        self.accessor.access_data["instance_ip"] = "172.16.57.41"
        command_run_result2 = \
"""+--------------------------------------+------------+-------------------+------------+-------------+-----------------------------------+\r
| ID                                   | Name       | Status            | Task State | Power State | Networks                          |\r
+--------------------------------------+------------+-------------------+------------+-------------+-----------------------------------+\r
| 76dfd8ec-c64a-4941-8617-03171199ea14 | baiegoed   | ACTIVE            | -          | Running     | net04=192.168.111.5, 172.16.57.41 |\r
+--------------------------------------+------------+-------------------+------------+-------------+-----------------------------------+\r\n"""
        f = open('/dev/pts/19', 'w')
        def foo(*args, **kwargs):
            foo.counter += 1
            ret_vals = {1: command_run_result1, 2: True, 3: True, 4: True,
                        5: command_run_result2, 6:True}
            return ret_vals[foo.counter]
        foo.counter = 0
        with mock.patch.object(self.accessor,
                "_run_os_command_in_container") as mocked_runner:
            mocked_runner.side_effect = foo
            self.accessor.check_mcv_secgroup()
            f.write(out.getvalue().strip()+'\n')
            self.assertEqual(mocked_runner.called, True)
        pass
