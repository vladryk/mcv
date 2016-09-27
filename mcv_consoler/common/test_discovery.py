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

import json
import fnmatch
from functools32 import lru_cache
import os
from mcv_consoler import utils


TOOLBOX = '/home/mcv/toolbox'

# Pre-hardcoded list of tests that are common for most OSTF versions
# This is only used when we start a 'full' group.
# Note: this is NOT! a list of tests to be run. Each listed test will be
# validated later one-again, when docker container is Up. Some of them might
# be excluded.
# Basically this is a list of tests that we usually use for OSTF
# TODO(ogrytsenko): remove hardcoded tests
OSTF_DUMMY = [
    'SanityIdentityTest',
    'SanityComputeTest',
    'GlanceSanityTests',
    'SanityHeatTest',
    'NetworksTest',
    'GlanceSmokeTests',
    'FlavorsAdminTest',
    'VolumesTest',
    'TestImageAction',
    'MuranoSanityTests',
    'VanillaTwoTemplatesTest',
    'HDPTwoTemplatesTest',
    'CeilometerApiTests',
    'HeatSmokeTests:test_actions',
    'HeatSmokeTests:test_advanced_actions',
    'HeatSmokeTests:test_update',
    'HeatSmokeTests:test_rollback',
]

# This is only used when we run a 'full' group
# TODO(ogrytsenko): remove hardcoded tests
TEMPEST_DUMMY = [
    'baremetal',
    'compute',
    'database',
    'data_processing',
    'identity',
    'image',
    'messaging',
    'network',
    'object_storage',
    'orchestration',
    'scenario',
    'smoke',
    'telemetry',
    'volume',
]


ostf_py = """
import sys
import json
from cloudv_ostf_adapter.validation_plugin.fuel_health import FuelHealthPlugin

f = FuelHealthPlugin()
res = json.dumps(f.tests)
sys.stdout.write(res)
"""

tempest_py = """
import sys
import json
from rally.consts import TempestTestsAPI

res = json.dumps(list(TempestTestsAPI))
sys.stdout.write(res)
"""


def toolbox(path):
    return os.path.join(TOOLBOX, path)


def listdir(path, fpattern=None):
    files = os.listdir(path)
    if fpattern is not None:
        files = fnmatch.filter(files, fpattern)
    return files


def get_rally():
    tdir = toolbox('rally/tests')
    res = listdir(tdir, '*.yaml')
    res.append('certification')
    return res


def get_shaker():
    tdir = toolbox('shaker/tests/openstack')
    return listdir(tdir, '*.yaml')


def get_tempest(cid):
    if cid is None:
        # This is a special case which is currently used only for 'full' group
        return TEMPEST_DUMMY

    cmd = 'docker exec {cid} 2>/dev/null python -c "{code}" '\
        .format(cid=cid, code=tempest_py)
    out = utils.run_cmd(cmd, quiet=True)
    res = json.loads(out)
    return res


def get_ostf(cid, mos_version):
    """
    :param cid: docker container id
    :param mos_version: 'mos_version' from config file

    Ostf is a special case because we may run either 'tests' or a 'suites'
    and they can be mixed together.
    Thus resulted list of all discovered tests will contain tests and suites
    as well.
    """
    if cid is None:
        py_exe = '/home/mcv/venv/fuel-ostf.{v}/bin/python'.format(v=mos_version)
        cmd = '{} -c "{}" '.format(py_exe, ostf_py)
        out = utils.run_cmd(cmd, quiet=True)
        all_tests = json.loads(out)
        tests = set()
        suites = set()
        for test_path in all_tests:
            test_case = test_path.split('.')[-1]
            tests.add(test_case)
            if ':' in test_case:
                suites.add(test_case.split(':')[0])
        res = set(tests) | set(suites)
        return list(res)

    py_exe = '/home/mcv/venv/fuel-ostf.{v}/bin/python'.format(v=mos_version)
    cmd = 'docker exec {cid} 2>/dev/null {python} -c "{code}" '.format(
        cid=cid, python=py_exe, code=ostf_py)
    out = utils.run_cmd(cmd, quiet=True)
    all_tests = json.loads(out)
    tests = set()
    suites = set()
    for test_path in all_tests:
        test_case = test_path.split('.')[-1]
        tests.add(test_case)
        if ':' in test_case:
            suites.add(test_case.split(':')[0])
    res = set(tests) | set(suites)
    return list(res)


def get_speed():
    return ['ObjectStorageSpeed', 'BlockStorageSpeed']


def get_nwspeed():
    return ['Node2NodeSpeed', ]


def get_resources():
    return ['GeneralResourceSearch', 'ErrorResourceSearch']


class CacheProxy(object):

    def __init__(self, func):
        self.func = lru_cache(maxsize=32)(func)
        self._res = None

    def __call__(self, *args, **kwargs):
        self._res = self.func(*args, **kwargs)
        return self

    def __repr__(self):
        return 'Cached object for %s' % self.func.__repr__()

    def get(self):
        return self._res or self.__call__()._res

    def filter(self, *filters):
        """ Get a list of available tests and apply """
        res = self.get()
        if res is None:
            return
        for f in filters:
            res = filter(f, res)
        return res

    def match(self, items):
        """
        :param items: tests to be validated against a list of all available
        tests for this particular runner

        Always returns a tuple, containing two elements: list of found
        and list of not found tests
        """
        res = self.get()
        found = set(res).intersection(items)
        missing = set(items).difference(res)
        return list(found), list(missing)

    def cache_clear(self):
        self._res = None
        return self.func.cache_clear()


class _Discovery(object):

    def __init__(self):
        self.rally = CacheProxy(get_rally)
        self.shaker = CacheProxy(get_shaker)
        self.tempest = CacheProxy(get_tempest)
        self.speed = CacheProxy(get_speed)
        self.nwspeed = CacheProxy(get_nwspeed)
        self.resources = CacheProxy(get_resources)
        self.ostf = CacheProxy(get_ostf)

    def use(self, plugin_name):
        return getattr(self, plugin_name)

    def get_all_tests(self):
        no_semicolon = lambda s: ':' not in s
        ostf_tests = self.ostf(None, None).get()
        ostf_suites = filter(no_semicolon, ostf_tests)

        # TODO(ogrytsenko): remove filter after workloads are fixed
        rally_load = lambda s: s.startswith(('load-', 'certification'))

        res = {
            'rally': self.rally.filter(rally_load),
            'shaker': self.shaker.get(),
            'tempest': self.tempest(cid=None).get(),
            'speed': self.speed.get(),
            'nwspeed': self.nwspeed.get(),
            'resources': self.resources.get(),
            'ostf': ostf_suites,
        }
        # force cache cleaning as we used *_DUMMY objects
        # TODO(ogrytsenko): get rid of *_DUMMY lists. Do not clear cache here
        self.tempest.cache_clear()
        self.ostf.cache_clear()
        return res


discovery = _Discovery()


