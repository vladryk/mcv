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

from mcv_consoler.common import config
from mcv_consoler.version import version


def _get_parser():
    parser = argparse.ArgumentParser(
        prog=config.PROJECT_NAME,
        formatter_class=argparse.RawTextHelpFormatter,
        description=config.PROJECT_DESCRIPTION,
        epilog=config.RUN_DESCRIPTION)

    required = parser.add_mutually_exclusive_group(required=True)

    required.add_argument(
        "--run",
        nargs="+",
        help="Run one of specified test suites.")

    one_of_is_required.add_argument(
        "--compare-resources",
        default=False,
        help="""Compare current resources with yaml-file""")

    parser.add_argument(
        "--config",
        help="Provide custom config file instead of the default one")

    parser.add_argument(
        "--no-tunneling",
        action="store_true",
        default=False,
        help="Forbids setting up automatic tunnels. Used for L2 only.")

    parser.add_argument(
        '--os-ssh-key', type=argparse.FileType('rt'),
        help='SSH key for OpenStack nodes. If not set fetched from FUEL '
             'master.')

    parser.add_argument(
        '--os-openrc', type=argparse.FileType('rt'),
        help='Shell script contain definition of environment variables used '
             'by OpenStack CLI client for authentication. If not set etched '
             'from FUEL controller node.')

    parser.add_argument(
        '--os-fuelclient-settings', type=argparse.FileType('rt'),
        help='Settings for fuelclient. If not set fetched from FUEL master.')

    parser.add_argument(
        "--version",
        action="version",
        version=version,
        help="Print out version of MCV Consoler and exit.")

    required = parser.add_mutually_exclusive_group(required=True)

    required.add_argument(
        "--run-mode",
        choices=config.RUN_MODES,
        # TODO(abochkarev): need to set required to 'True'
        # after removing '--mode' from options
        required=False,
        help="""Choose mode in which Consoler is going to work.

Possible values:

instance -  Run MCV inside the cloud as an instance (L1)
node -      Run MCV as a separate node with direct access to admin network (L2)
external -  Run MCV as a separate node in external network (L3)""")

    required.add_argument(
        "--mode",
        type=int,
        choices=config.MODES,
        help="WARNING: This option is deprecated. Use '--run-mode' instead")

    parser.add_argument(
        "--debug",
        default=False,
        action="store_true",
        help="Show debug messages.")

    return parser


argparser = _get_parser()
