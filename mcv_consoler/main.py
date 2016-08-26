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

import fcntl
import os
import sys
import threading
import time
import traceback

from requests.packages import urllib3
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3.exceptions import SNIMissingWarning

from mcv_consoler.common.cfgparser import config_parser
from mcv_consoler.common.config import DEFAULT_CONFIG_FILE, RUN_MODES
from mcv_consoler.common.cmd import argparser
from mcv_consoler.common.conf_validation import validate_conf
from mcv_consoler.common.errors import CAError
from mcv_consoler import consoler
from mcv_consoler.logger import LOG


urllib3.disable_warnings(InsecurePlatformWarning)
urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(SNIMissingWarning)

LOG = LOG.getLogger(__name__)

args = argparser.parse_args()


def acquire_lock():
    lockfile = open("/var/lock/consoler", "w")
    try:
        fcntl.lockf(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        return False
    return True


def load_config():
    if args.config is not None:
        default_config = args.config
    else:
        default_config = DEFAULT_CONFIG_FILE
    path_to_config = os.path.join(os.path.dirname(__file__), default_config)
    conf = config_parser
    conf.read(path_to_config)
    # a little hack. We will need this later, when validating a config
    conf._conf_path = path_to_config
    return conf


def main():
    LOG.debug('Consoler started by command: %s' % ' '.join(sys.argv))

    conf = load_config()

    # show deprecation warning. Replace 'mode' with 'run_mode' if needed
    if args.mode is not None:
        warn_msg = "\nDeprecation warning: option '--mode' is deprecated " \
                   "and might be removed in the nearest future. " \
                   "Use '--run-mode' instead\n"
        LOG.warning(warn_msg)
        if args.run_mode is None:
            args.run_mode = RUN_MODES[args.mode - 1]

    if args.run is not None:
        if not validate_conf(conf, args.run):
            return CAError.CONFIG_ERROR

    if not acquire_lock():
        LOG.error("There is another instance of MCVConsoler! Stop.")
        return CAError.TOO_MANY_INSTANCES

    consolerr = consoler.Consoler(config=conf, args=args)

    if args.test is not None:
        return consolerr.do_test()

    e = threading.Event()
    res = []
    t = threading.Thread(target=consolerr.console_user, args=[e, res])
    try:
        t.start()
        while t.isAlive():
            time.sleep(1)
    except KeyboardInterrupt:
        LOG.info("Consoler will be interrupted after finish of current task. "
                 "Results of it will be lost")
        e.set()
        return CAError.KEYBOARD_INTERRUPT
    except Exception:
        LOG.error("Something unforeseen has just happened."
                  " The consoler is no more. You can get an insight from"
                  " /home/mcv/toolbox/mcvconsoler.log")
        LOG.debug(traceback.format_exc())
        return CAError.UNKNOWN_EXCEPTION
    if res:
        LOG.debug('Consoler finished with exit code %s' % res[0])
        return res[0]


if __name__ == "__main__":
    sys.exit(main())
