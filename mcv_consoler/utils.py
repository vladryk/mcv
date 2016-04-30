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

from ConfigParser import NoOptionError
from ConfigParser import NoSectionError
import re
import signal
import subprocess

from mcv_consoler.logger import LOG

warnings = ('SNIMissingWarning',
            'InsecurePlatformWarning',
            'InsecureRequestWarning')


def ignore_sigint():
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def run_cmd(cmd, quiet=False):
    LOG.debug('Executing command: "%s"' % cmd)
    try:
        result = subprocess.check_output(cmd,
                                         shell=True,
                                         stderr=subprocess.STDOUT,
                                         preexec_fn=ignore_sigint)
    except subprocess.CalledProcessError as e:
        LOG.debug('ERROR: %s' % e.output)
        raise
    result = re.sub(r'/usr/local/.*(%s).*\n' % "|".join(warnings), '', result)
    result = re.sub(r'  (%s).*\n' % "|".join(warnings), '', result)
    quiet or LOG.debug('RESULT: "%s"' % result)
    return result


def GET(config, key, section="basic", default=None):
    try:
        value = config.get(section, key)
    except NoSectionError:
        LOG.warning('Section {sec} missed in configuration file. '
                    'It may be dangerous'.format(sec=section))
        value = None
    except NoOptionError:
        LOG.warning('Option {opt} missed in configuration file. '
                    'It may be dangerous'.format(opt=key))
        if default is not None:
            LOG.info('Setting {opt} to default value {val}'.format(opt=key,
                                                                   val=default))
        value = default
    return value
