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


import consoler
import ConfigParser
import fcntl
import sys
import time
import threading
import traceback
from common.cmd import argparser
from common.errors import CAError
from logger import LOG

LOG = LOG.getLogger(__name__)


def acquire_lock():
    try:
        fcntl.lockf(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        return False
    return True


# hooking up a config
config = ConfigParser.ConfigParser()
default_config_file = "/etc/mcv/mcv.conf"
lockfile = open("/var/lock/consoler", "w")


args = argparser.parse_args()


def main():
    if not acquire_lock():
        LOG.error("There is another instance of MCVConsoler! Stop.")
        return CAError.TOO_MANY_INSTANCES
    consolerr = consoler.Consoler(parser=argparser, args=args)
    e = threading.Event()
    res = []
    t = threading.Thread(target=consolerr.console_user, args=[e, res])
    try:
        t.start()
        while t.isAlive():
            time.sleep(30)
    except KeyboardInterrupt:
        LOG.info("Consoler will be interrupted after finish of current task. "
                 "Results of it will be lost")
        e.set()
        return CAError.KEYBOARD_INTERRUPT
    except Exception:
        LOG.error("Something unforeseen has just happened."
                  " The consoler is no more. You can get an insight from"
                  " /var/log/mcvconsoler.log")
        LOG.debug(traceback.format_exc())
        return CAError.UNKNOWN_EXCEPTION
    if res:
        return res[0]

if __name__ == "__main__":
    sys.exit(main())
