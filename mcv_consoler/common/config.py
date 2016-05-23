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


# Enables DEBUG logging
DEBUG = False

# Project description
PROJECT_NAME = "mcvconsoler"

PROJECT_DESCRIPTION = """The main tool in Mirantis Cloudvalidation Project."""

RUN_DESCRIPTION = r"""Here is an example of running MCV Consoler:

    # mcvconsoler --run custom quick

    Also it is recommended to run the tool as a superuser, running it as an
    ordinary user might cause unexpected errors in strange places for odd
    tools.

    ...and in the darkness bind them, in the cloud where the instances lie."""

DEFAULT_CONFIG_FILE = "/etc/mcv/mcv.conf"

# Default value is max_failed_tests is missed in MCV configuration file
DEFAULT_FAILED_TEST_LIMIT = 10

# List of supported MOS versions
MOS_VERSIONS = ['6.1', '7.0', '8.0']

# thees are used when verifying that docker images are up and running
DOCKER_REQUIRED_IMAGES = ("mcv-rally", "mcv-shaker", "mcv-ostf", 'mcv-tempest')
DOCKER_LOADING_IMAGE_TIMEOUT = 60 * 20  # 20 min
DOCKER_CHECK_INTERVAL = 20

# Default value for 'attempts' parameter to measure object/storage speed
SPEED_STORAGE_ATTEMPTS_DEFAULT = 3

# Default threshold value for Shaker
DEFAULT_SHAKER_THRESHOLD = 7

# Prefix for keys for generating shaker-report ('network_speed.html')
SHAKER_REPORT_KEYS = ['tcp_download', 'bandwidth', 'tcp_upload']
