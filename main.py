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


import accessor
import argparse
import inspect
import consoler
import ConfigParser
import logging
import logger as LOG
import imp
import subprocess
import os
import sys


# hooking up a config
config = ConfigParser.ConfigParser()
default_config_file = "/etc/mcv/mcv.conf"

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
    nargs = '+',
    help="""Run one of specified test suits : full, custom, single or
    short.""")

parser.add_argument(
    "--config",
    help="""Provide custom config file instead of the default one""")

args = parser.parse_args()

# setting up nice logging
__ = '%(asctime)s %(levelname)s %(message)s'
logger = logging.getLogger(__name__)


def main():
    consolerr = consoler.Consoler(parser=parser, args=args)
    try:
        consolerr.console_user()
    except:
        print "Something unforseen has just happened. The consoler is no more."
        print "You can get an insight from /var/log/mcvconsoler.log"


if __name__ == "__main__":
    main()
