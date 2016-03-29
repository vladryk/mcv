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
from common.config import PROJECT_NAME
from common.config import PROJECT_DESCRIPTION
from common.config import RUN_DESCRIPTION
from version import version


def _get_parser():
    parser = argparse.ArgumentParser(
        prog=PROJECT_NAME,
        formatter_class=argparse.RawTextHelpFormatter,
        description=PROJECT_DESCRIPTION,
        epilog=RUN_DESCRIPTION)

    parser.add_argument(
        "--run",
        nargs='+',
        help="""Run one of specified test suites.""")

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

    parser.add_argument(
        "--version",
        action="version",
        version=version,
        help="""Print out version of MCV Consoler and exit.""")

    return parser

argparser = _get_parser()