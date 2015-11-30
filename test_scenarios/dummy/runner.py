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


import ConfigParser
import logger as LOG
import os
import subprocess
import time
import sys
from test_scenarios import runner
try:
    import json
except:
    import simplejson as json

nevermind = None

config = ConfigParser.ConfigParser()
#default_config = "/etc/cloud_validator/mcv.conf"
default_config = "etc/mcv.conf"


class DummyRunner(runner.Runner):

    def __init__(self, config_location=None):
        super(DummyRunner, self).__init__()
        self.identity = "dummy"
        self.config_section = "dummy"
        if config_location is None:
            self.config_location = default_config
        else:
            self.config_location = config_location
        self.test_failures = []  # this object is supposed to live for one run
                                 # so let's leave it as is for now.
        self.failure_indicator = 70

    def _it_ends_well(self, something):
        return True

    def run_batch(self, tasks):
        return super(DummyRunner, self).run_batch(tasks)

    def run_individual_task(self, task):
        time.sleep(2)
        return
