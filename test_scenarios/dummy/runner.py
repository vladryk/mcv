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

    def _it_ends_well(self, something):
        return True

    def run_batch(self, tasks):
        return super(DummyRunner, self).run_batch(tasks)

    def run_individual_task(self, task):
        time.sleep(2)
        return
