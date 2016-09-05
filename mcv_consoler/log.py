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

import logging
import logging.config

from requests.packages import urllib3
import yaml


def configure_logging(log_config=None, debug=None, hide_ssl_warnings=None):
    """Configure the logging system

    Load the logging configuration file and configure the
    logging system.

    :param log_config: path to the logging config file
    :param debug: allows to enable/disable the console
    debug mode
    :param hide_ssl_warnings: allows to enable/disable
    urllib3 warnings
    """
    with open(log_config, 'r') as f:
        logging.config.dictConfig(yaml.load(f))

    if not debug:
        logger = logging.getLogger()
        for handler in logger.handlers:
            if handler.name == 'console':
                handler.setLevel(logging.INFO)
                handler.setFormatter(logging.Formatter())
                break

    if hide_ssl_warnings:
        urllib3.disable_warnings()
