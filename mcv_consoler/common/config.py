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

# Available modes to run MCV

MODES = (1,  # L1 segment (as an instance)
         2,  # L2 segment (separate node in admin network)
         3,  # L3 segment (separate node in external network)
         )

RUN_MODES = (
    'instance',     # L1 segment (as an instance)
    'node',         # L2 segment (separate node in admin network)
    'external',     # L3 segment (separate node in external network)
)

# Project name and name of executable file of Consoler
PROJECT_NAME = "mcvconsoler"

# Description of Consoler (for CLI)
PROJECT_DESCRIPTION = """The main tool in Mirantis Cloudvalidation Project."""

# Help message for Consoler CLI
RUN_DESCRIPTION = r"""Here is an example of running MCV Consoler:

    # mcvconsoler --run group quick --run-mode=instance

    Also it is recommended to run the tool as a superuser, running it as an
    ordinary user might cause unexpected errors in strange places for odd
    tools.

    ...and in the darkness bind them, in the cloud where the instances lie."""

# Folder name where Consoler will search for installed plugins.
PLUGINS_DIR_NAME = 'plugins'

# Path to default config file for Consoler
DEFAULT_CONFIG_FILE = "/etc/mcv/mcv.conf"

# Default value is max_failed_tests is missed in MCV configuration file
DEFAULT_FAILED_TEST_LIMIT = 10

# List of supported MOS versions
MOS_VERSIONS = ['6.1', '7.0', '8.0', '9.0']

# Options used while verifying that docker images are up and running
DOCKER_REQUIRED_IMAGES = ("mcv-rally", "mcv-shaker", "mcv-ostf", 'mcv-tempest')
DOCKER_LOADING_IMAGE_TIMEOUT = 60 * 20  # 20 min
DOCKER_CHECK_INTERVAL = 20

# Default value for 'attempts' parameter to measure object/block storage speed
SPEED_STORAGE_ATTEMPTS_DEFAULT = 3

# Default threshold value for speed tests
DEFAULT_SPEED_STORAGE = 50

# Image used for speed tests
DEFAULT_CIRROS_IMAGE = '/home/mcv/toolbox/rally/images/cirros-0.3.1-x86_64-disk.img'

# Default threshold value for Shaker
DEFAULT_SHAKER_THRESHOLD = 7

# Prefix for keys for generating shaker-report ('network_speed.html')
SHAKER_REPORT_KEYS = ['tcp_download', 'bandwidth', 'tcp_upload']

# Options for Rally Workload Tasks
SAHARA_IMAGE_PATH80 = '/home/mcv/toolbox/rally/images/sahara-liberty-vanilla-2.7.1-ubuntu-14.04.qcow2'
SAHARA_IMAGE_PATH70 = '/home/mcv/toolbox/rally/images/sahara-kilo-vanilla-2.6.0-ubuntu-14.04.qcow2'
TERASORT_JAR_PATH = 'file:///mcv/images/hadoop-mapreduce-examples-2.7.1.jar'
FEDORA_IMAGE_PATH = '/home/mcv/toolbox/rally/images/Fedora-Cloud-Base-23-20151030.x86_64.qcow2'
MOS_HADOOP_MAP = {
    '7.0': '2.6.0',
    '8.0': '2.7.1'
}

# Default timeout for SSH connection, sec
DEFAULT_SSH_TIMEOUT = 10

# Default path to RSA key on MCV host
DEFAULT_RSA_KEY_PATH = "/home/mcv/toolbox/keys/id_rsa"

# Default path to file with credentials received from the cloud
DEFAULT_CREDS_PATH = "/home/mcv/toolbox/keys/openrc"

FUELCLIENT_SETTINGS_ENV_VAR = 'FUELCLIENT_CUSTOM_SETTINGS'
FUELCLIENT_CONFIG = '/home/mcv/toolbox/fuelclient-config.yaml'

#
# Configuration for SSH tunneling
#

# Local port at MCV host to make a tunnel to controller node
MCV_LOCAL_PORT = 2222

# Remote port at controller node to make a tunnel.
# For now, we need an SSH standard port.
RMT_CONTROLLER_PORT = 22

# User on any controller to be used for reaching openrc
RMT_CONTROLLER_USER = 'root'

# Path to times.json
TIMES_DB_PATH = '/home/mcv/toolbox/times.json'

# Shaker timeout for agents
SHAKER_AGENTS_TIMEOUT = 60
