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

import os

from mcv_consoler.common.config import DEFAULT_CONFIG_FILE
from mcv_consoler.common.errors import BaseSelfCheckError
from mcv_consoler.log import LOG

LOG = LOG.getLogger(__name__)


class BasicSelfCheck(object):

    def __init__(self):
        self.tests = ['consoler', 'board', 'config', 'hostname']
        self.results = []

    def run(self):
        for test in self.tests:
            getattr(self, test + '_exists')()
        return self.results

    def consoler_exists(self):
        # TODO(albartash): This test needs to be rewritten,
        # as we now have Consoler installed into system.
        # For now this test will be disabled.

        # self.results.append(True if os.path.isdir(
        #    '/opt/mcv-consoler') else BaseSelfCheckError.CONSOLER_NOT_EXISTS)
        self.results.append(True)

    def board_exists(self):
        self.results.append(True if os.path.isdir(
            '/opt/mcv-board') else BaseSelfCheckError.BOARD_NOT_EXISTS)

    def config_exists(self):
        self.results.append(True if os.path.isfile(
            DEFAULT_CONFIG_FILE) else BaseSelfCheckError.CONFIG_NOT_EXISTS)

    def hostname_exists(self):
        res = BaseSelfCheckError.HOSTNAME_NOT_EXISTS
        f = open('/etc/hosts', 'r')
        for line in f.readlines():
            if line.find('mcv') != -1:
                res = True
                break
        f.close()
        self.results.append(res)
