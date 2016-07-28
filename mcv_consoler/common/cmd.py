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

from mcv_consoler.common.config import MODES
from mcv_consoler.common.config import PROJECT_DESCRIPTION
from mcv_consoler.common.config import PROJECT_NAME
from mcv_consoler.common.config import RUN_DESCRIPTION
from mcv_consoler.version import version


def _get_parser():
    parser = argparse.ArgumentParser(
        prog=PROJECT_NAME,
        formatter_class=argparse.RawTextHelpFormatter,
        description=PROJECT_DESCRIPTION,
        epilog=RUN_DESCRIPTION)

    one_of_is_required = parser.add_mutually_exclusive_group(required=True)

    one_of_is_required.add_argument(
        "--run",
        nargs='+',
        help="""Run one of specified test suites.""")

    one_of_is_required.add_argument(
        "--test",
        nargs='+',
        dest='test',
        help="""testing mcv test groups""")

    parser.add_argument(
        "--config",
        help="""Provide custom config file instead of the default one""")

    parser.add_argument(
        "--no-tunneling", action="store_true", default=False,
        help="""Forbids setting up automatic tunnels. Used for L2
        only.""")

    parser.add_argument(
        "--mode", type=int, choices=MODES, required=True,
        help="""Choose mode in which Consoler is going to work.

        Possible values:

        1 - Run MCV inside the cloud as an instance (L1)
        2 - Run MCV as a separate node with direct access to admin network (L2)
        3 - Run MCV as a separate node in external network (L3)
        """)

    parser.add_argument(
        "--version",
        action="version",
        version=version,
        help="""Print out version of MCV Consoler and exit.""")

    return parser

argparser = _get_parser()
