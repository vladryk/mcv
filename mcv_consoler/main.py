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

import fcntl
import logging
import sys
import threading
import time
import traceback

from oslo_config import cfg
import ruamel.yaml

from mcv_consoler.common import cfglib
from mcv_consoler.common.cmd import argparser
from mcv_consoler.common import context
from mcv_consoler.common.errors import CAError
from mcv_consoler import consoler
from mcv_consoler import log
from mcv_consoler.utils import copy_mcvconsoler_log

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

args = argparser.parse_args()


def acquire_lock():
    lockfile = open("/var/lock/consoler", "w")
    try:
        fcntl.lockf(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        return False
    return True


def load_scenario():
    with open(CONF.basic.scenario, 'r') as f:
        return ruamel.yaml.round_trip_load(f)


def main():
    if not cfglib.init_config(args.config):
        return CAError.CONFIG_ERROR

    log.configure_logging(args.debug, args.verbose)

    LOG.debug('Consoler started by command: %s', ' '.join(sys.argv))
    if not acquire_lock():
        LOG.error("There is another instance of MCVConsoler! Stop.")
        return CAError.TOO_MANY_INSTANCES

    ctx = context.Context(
        None,
        args=args,
        scenario=load_scenario(),
        terminate_event=threading.Event())
    app = consoler.Consoler(ctx)

    rcode = [None]
    t = threading.Thread(target=thread_wrapper, args=[app, rcode])

    try:
        t.start()
        while t.isAlive():
            time.sleep(1)
        result = rcode[0]
    except KeyboardInterrupt:
        LOG.info("Consoler will be interrupted after finish of current task. "
                 "Results of it will be lost")
        ctx.terminate_event.set()
        result = CAError.KEYBOARD_INTERRUPT
    except Exception:
        LOG.error("Something unforeseen has just happened."
                  " The consoler is no more. You can get an insight from"
                  " /home/mcv/toolbox/mcvconsoler.log")
        LOG.debug(traceback.format_exc())
        result = CAError.UNKNOWN_EXCEPTION

    LOG.debug('Consoler finished with exit code %s', result)

    # copy mcvconsoler log for current run and pack results into archive
    if app.results_dir:
        copy_mcvconsoler_log(app.results_dir)
        app.make_results_archive()

    return result


def thread_wrapper(worker, rcode_holder):
    rcode = CAError.UNKNOWN_EXCEPTION
    try:
        rcode = worker()
    except Exception as e:
        LOG.error('Unhandled exception in worker thread: %s', e)
        LOG.error('Check logs, for more details about this issue.')
        LOG.debug('Error details', exc_info=True)
    rcode_holder[:] = [rcode]


if __name__ == "__main__":
    sys.exit(main())
