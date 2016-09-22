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

import logging
import logging.config

from oslo_config import cfg
from requests.packages import urllib3
import yaml

CONF = cfg.CONF


def configure_logging(debug=None, verbose=None):
    """Configure the logging system

    Load the logging configuration file and configure the
    logging system.

    :param debug: allows to enable/disable the console
    debug mode
    :param verbose: allows to verbose the debug messages
    """

    with open(CONF.basic.log_config, 'r') as f:
        logging.config.dictConfig(yaml.load(f))

    logger = logging.getLogger()
    if not debug:
        for handler in logger.handlers:
            if handler.name == 'console':
                handler.setLevel(logging.INFO)
                handler.setFormatter(logging.Formatter())
                break
    if verbose:
        logger.setLevel(logging.DEBUG)

    if CONF.basic.hide_ssl_warnings:
        urllib3.disable_warnings()

    CONF.log_opt_values(logging, logging.DEBUG)
