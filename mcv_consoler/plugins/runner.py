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

import contextlib
import datetime
import json
import logging
import os
import shutil
import time
import traceback

from oslo_config import cfg

from mcv_consoler.common import config
from mcv_consoler.common import context
from mcv_consoler.common.errors import BaseSelfCheckError
from mcv_consoler.common.errors import CAError
from mcv_consoler.common.errors import OSTFError
from mcv_consoler.common.errors import RallyError
from mcv_consoler.common.errors import ResourceError
from mcv_consoler.common.errors import ShakerError
from mcv_consoler.common.errors import SpeedError
from mcv_consoler.common.errors import TempestError
from mcv_consoler.common.test_discovery import discovery
from mcv_consoler.exceptions import ProgramError
from mcv_consoler import utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class Runner(object):
    identity = None
    container_id = None
    failure_indicator = CAError.NO_RUNNER_ERROR

    def __init__(self, ctx):
        super(Runner, self).__init__()
        self.ctx = ctx
        context.add(self.ctx, 'runner', self)

        self.max_failed_tests = ctx.max_failed_tests

        self.current_task = 1
        self.test_failures = []
        self.test_without_report = []
        self.test_success = []
        self.test_not_found = []
        self.test_skipped = []
        self.time_of_tests = {}

        self.homedir = '/home/mcv/toolbox'

        # store mcv.conf
        for conf_path in CONF.default_config_files:
            self.store_config(os.path.abspath(conf_path))

    @property
    def discovery(self):
        return discovery.use(self.identity)

    @contextlib.contextmanager
    def store(self, *file_paths):
        file_paths = [os.path.join(self.homedir, 'log', file_path)
                      for file_path in file_paths]
        LOG.debug('Storing files: %s', ', '.join(file_paths))
        try:
            for file_path in file_paths:
                if os.path.exists(file_path):
                    with open(file_path, 'w'):
                        pass
            yield
        finally:
            for file_path in file_paths:
                self.store_logs(file_path)

    def store_logs(self, copy_from):
        # TODO(vkaznacheiev): move it to a separate module later.
        if not os.path.exists(copy_from):
            LOG.debug("Log file by the following path does not exist and will "
                      "not be copied in the results folder: %s", copy_from)
            return

        path_to_store = os.path.join(self.ctx.work_dir_global.base_dir,
                                     "logs", self.identity)

        if not os.path.exists(path_to_store):
            os.makedirs(path_to_store)

        path_to_store = os.path.join(path_to_store,
                                     os.path.basename(copy_from))
        shutil.copy2(copy_from, path_to_store)

        LOG.debug("Log by the following path has been copied to the results "
                  "dir: %s", copy_from)

    def store_config(self, copy_from):
        # TODO(vkaznacheiev): move it to a separate module later.
        if not os.path.exists(copy_from):
            LOG.debug("Config by the following path does not exist and will "
                      "not be copied in the results folder: %s", copy_from)
            return

        config_store_dir = os.path.join(self.ctx.work_dir_global.base_dir,
                                        "config")

        if not os.path.exists(config_store_dir):
            os.makedirs(config_store_dir)

        cfg_name = os.path.basename(copy_from)
        copy_to = os.path.join(config_store_dir, cfg_name)

        shutil.copy2(copy_from, copy_to)

        LOG.debug("Config by the following path has been copied to the "
                  "results dir: %s", copy_from)

    def dump_raw_results(self, task, raw_results):
        # FIXME(dbogun): define corresponding resource in WorkDir
        path_to_store = os.path.join(
            self.ctx.work_dir_global.base_dir, "raw_data", self.identity)

        if not os.path.exists(path_to_store):
            os.makedirs(path_to_store)

        task = task.replace('.yaml', '').replace(':', '.')
        path_to_store = os.path.join(path_to_store, "{}.json".format(task))
        try:
            with open(path_to_store, "w") as out_f:
                json.dump(raw_results, out_f, indent=2)
        except (TypeError, ValueError):
            LOG.error("Raw results for task `{task}` are not JSON "
                      "serializable and will not appear in the results "
                      "archive for {identity}."
                      .format(task=task, identity=self.identity))
            LOG.debug(traceback.format_exc())
        else:
            LOG.debug("Raw results for task `{task}` were dumped into file:"
                      " {path}".format(task=task, path=path_to_store))

    def run_individual_task(self, task, *args, **kwargs):
        raise NotImplementedError

    def start_container(self):
        raise NotImplementedError

    def verify_container_is_up(self, plugin=None, attempts=3, interval=10,
                               quiet=False):

        plugin = plugin or self.identity
        LOG.debug("Checking %s container...", plugin)

        docker_image = 'mcv-{}'.format(plugin)
        cmd = 'docker ps ' \
              '--filter "ancestor=%(image)s" ' \
              '--format "{{.ID}}\t{{.Status}}" ' \
              '| tail -1' % dict(image=docker_image)
        for _ in range(attempts):
            out = utils.run_cmd(cmd)
            if not out:
                LOG.debug('Container is not running')
                interval and time.sleep(interval)
                continue
            cid, status = out.strip().split('\t')
            break
        else:
            if quiet:
                return
            err = 'Failed to start docker container: {}'.format(plugin)
            raise ProgramError(err)
        self.container_id = cid
        LOG.debug("Container %s is fine. Status: %s", plugin, status)
        return cid

    def lookup_existing_container(self, plugin=None):
        return self.verify_container_is_up(plugin, attempts=1, interval=0,
                                           quiet=True)

    @staticmethod
    def get_error_code(tool_name):

        codes = {'ostf': OSTFError.FAILED_TEST_LIMIT_EXCESS,
                 'rally': RallyError.FAILED_TEST_LIMIT_EXCESS,
                 'resources': ResourceError.FAILED_TEST_LIMIT_EXCESS,
                 'selfcheck': BaseSelfCheckError.FAILED_TEST_LIMIT_EXCESS,
                 'shaker': ShakerError.FAILED_TEST_LIMIT_EXCESS,
                 'speed': SpeedError.FAILED_TEST_LIMIT_EXCESS,
                 'tempest': TempestError.FAILED_TEST_LIMIT_EXCESS}
        default = CAError.FAILED_TEST_LIMIT_EXCESS

        return codes.get(tool_name, default)

    @staticmethod
    def _validate_test_params(**params):
        for key in 'compute', 'concurrency':
            if key not in params:
                continue
            if not isinstance(params[key], int):
                LOG.warning("Type mismatch. Parameter '%s' expected to be "
                            "an %s. Got: %s", key, int, type(key))

    def run_batch(self, tasks, *args, **kwargs):
        """Runs a bunch of tasks."""

        tool_name = kwargs["tool_name"]
        all_time = kwargs["all_time"]
        elapsed_time = kwargs["elapsed_time"]

        LOG.debug("The following tests will be run:")
        LOG.debug("\n".join(tasks))

        failures = 0

        # Note(ayasakov): the database execution time of each test.
        # In the first run for each test tool calculate the multiplier,
        # which shows the difference of execution time between testing
        # on our cloud and the current cloud.

        db = kwargs.get('db')
        first_run = True
        multiplier = 1.0
        current_time = 0
        all_time -= elapsed_time

        self._validate_test_params(**kwargs)

        for task in tasks:
            LOG.info("-" * 60)
            if kwargs.get('event').is_set():
                LOG.info("Caught keyboard interrupt. "
                         "Task %s won't start", task)
                break
            time_start = datetime.datetime.utcnow()
            LOG.debug("Running task %s", task)
            LOG.debug("Time start: %s UTC", time_start)
            if not CONF.times.update:
                try:
                    current_time = db[tool_name][task]
                except KeyError:
                    current_time = 0

                msg = "Expected time to complete %s: %s"
                t = utils.seconds_to_humantime(current_time * multiplier)
                if not current_time:
                    LOG.debug(msg, task, t)
                else:
                    LOG.info(msg, task, t)

            # FIXME(dbogun): sort out exceptions handling
            try:
                if self.run_individual_task(task, *args, **kwargs):
                    self.test_success.append(task)
                else:
                    failures += 1
            except Exception:
                failures += 1
                LOG.debug(traceback.format_exc())

            time_end = datetime.datetime.utcnow()
            duration = time_end - time_start
            duration = duration.total_seconds()
            LOG.debug("Time end: %s UTC" % str(time_end))

            if CONF.times.update:
                if tool_name in db.keys():
                    db[tool_name].update({task: int(duration)})
                else:
                    db.update({tool_name: {task: int(duration)}})
            else:
                if first_run:
                    first_run = False
                    if current_time:
                        multiplier = duration / current_time
                all_time -= current_time
                percent = 1.0
                if kwargs["all_time"]:
                    percent -= float(all_time) / float(kwargs["all_time"])
                percent = int(percent * 100)
                percent = 100 if percent > 100 else percent

                line = 'Completed {} %'.format(percent)
                if all_time and multiplier:
                    t = utils.seconds_to_humantime(all_time * multiplier)
                    line = '{} and remaining time {}'.format(line, t)
                LOG.info(line)
                LOG.info("-" * 60)

            if failures >= self.max_failed_tests:
                LOG.info('*LIMIT OF FAILED TESTS EXCEEDED! STOP RUNNING.*')
                self.failure_indicator = self.get_error_code(tool_name)
                break

        if CONF.times.update:
            with open(config.TIMES_DB_PATH, "w") as f:
                json.dump(db, f)

        return {"test_failures": self.test_failures,
                "test_success": self.test_success,
                "test_not_found": self.test_not_found,
                "test_skipped": self.test_skipped,
                "time_of_tests": self.time_of_tests,
                "test_without_report": self.test_without_report}

    def _evaluate_task_results(self, task_results):
        raise NotImplementedError
