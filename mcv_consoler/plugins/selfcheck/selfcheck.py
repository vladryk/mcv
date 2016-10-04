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

import logging
import os
import socket

from mcv_consoler.common import config
from mcv_consoler.common import errors

LOG = logging.getLogger(__name__)


class BasicSelfCheck(object):

    def __init__(self):
        super(BasicSelfCheck, self).__init__()
        self.tests = ['board_existing', 'config_existing',
                      'hostname_existing', 'internet_availability']

    def run(self):
        return [getattr(self, 'test_{}'.format(test))()
                for test in self.tests]

    @staticmethod
    def test_board_existing():
        LOG.debug('Executing a board existing test')
        return True if os.path.isdir(config.DEFAULT_MCV_BOARD_DIR) \
            else errors.BaseSelfCheckError.BOARD_NOT_EXISTS

    @staticmethod
    def test_config_existing():
        LOG.debug('Executing a config file existing test')
        return True if os.path.isfile(config.DEFAULT_CONFIG_FILE) \
            else errors.BaseSelfCheckError.CONFIG_NOT_EXISTS

    @staticmethod
    def test_hostname_existing():
        LOG.debug('Executing an hosts file existing test')
        with open(config.DEFAULT_HOSTS_FILE, 'r') as f:
            for line in f.readlines():
                if 'mcv' in line:
                    return True
        return errors.BaseSelfCheckError.HOSTNAME_NOT_EXISTS

    @staticmethod
    def test_internet_availability(host='8.8.8.8', port=53, timeout=5):
        LOG.debug('Executing an internet availability test')
        sock = None
        def_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(timeout)
            sock = socket.socket()
            sock.connect((host, port))
            return True
        except Exception as ex:
            LOG.error(ex)
            LOG.debug('Error details', exc_info=True)
            return errors.BaseSelfCheckError.INTERNET_NOT_AVAILABLE
        finally:
            socket.setdefaulttimeout(def_timeout)
            if sock:
                sock.shutdown(socket.SHUT_RD)
                sock.close()
