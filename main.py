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


import argparse
import consoler
import ConfigParser
import logging
import os
import sys
import threading
import fcntl


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

# processing command line arguments.
parser = argparse.ArgumentParser(
    prog="mcvconsoler",
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Central point of control for cloud validation -- one tool
    to rule them all.""",
    epilog=r"""The following command gives an example of how tests could be run:

    # mcvconsoler --run custom short

    Default config could be found in <path-to-mcv>/etc/mcv.conf so you can try
    it out with the default config:

    # mcvconsoler --run custom short --config <path-to-mcv>/etc/mcv.conf

    Also it is recommended to run the tool as a superuser, running it as an
    ordinary user might cause unexpected errors in strange places for odd
    tools.

    ...and in the darkness bind them, in the cloud where the
    instances lie.""",)

parser.add_argument(
    "--run",
    nargs='+',
    help="""Run one of specified test suits : full, custom, single or
    short.""")

parser.add_argument(
    "--test",
    nargs='+',
    dest='test',
    help="""testing mcv test groups""")

parser.add_argument(
    "--config",
    help="""Provide custom config file instead of the default one""")

parser.add_argument(
    "--no-tunneling", action="store_true", default=False,
    help="""Forbids setting up automatic tunnels""")

args = parser.parse_args()


def main():
    import logging.config
    lc = os.path.join(os.path.dirname(__file__), 'etc/logging.conf')
    logging.config.fileConfig(lc)
    if not acquire_lock():
        logging.error("Thou shalt not pass! There is another instance of MCVConsoler!")
        sys.exit(1)
    # This is somewhat radical way to shut up paramiko, should be replaced with
    # handler substitution.
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    consolerr = consoler.Consoler(parser=parser, args=args)
    e = threading.Event()
    res = None
    t = threading.Thread(target=consolerr.console_user, args=[e, res])
    try:
        t.start()
        t.join()
        return res
    except KeyboardInterrupt:
        logging.info("Consoler will be interrupted after finish of current task. "
                     "Results of it will be lost")
        e.set()
        return 1
    except Exception as e:
        logging.error("Something unforseen has just happened. "
                      "The consoler is no more. You can get an insight from "
                      "/var/log/mcvconsoler.log", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
