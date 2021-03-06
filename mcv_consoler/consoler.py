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

import copy
from datetime import datetime
import imp
import json
import logging
import os
import shutil
import subprocess
import traceback

from oslo_config import cfg
import prettytable
import ruamel.yaml

from mcv_consoler.accessor import AccessSteward
from mcv_consoler.common import cleanup
from mcv_consoler.common import clients
from mcv_consoler.common.config import PLUGINS_DIR_NAME
from mcv_consoler.common.config import TIMES_DB_PATH
from mcv_consoler.common import context
from mcv_consoler.common.errors import CAError
from mcv_consoler.common.errors import ComplexError
from mcv_consoler.common import resource
from mcv_consoler.common import ssh
from mcv_consoler.common.test_discovery import discovery
from mcv_consoler import exceptions
from mcv_consoler import reporter
from mcv_consoler.reporter import validate_section
from mcv_consoler import utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

TEMPEST_OUTPUT_TEMPLATE = ("Total: {tests}, Success: {test_succeed}, "
                           "Failed: {test_failed}, Skipped: {test_skipped}, "
                           "Expected failures: {expected_failures}")


class Consoler(object):
    all_time = 0
    group_name = None
    results_dir = None
    failure_indicator = CAError.NO_ERROR
    plugin_dir = PLUGINS_DIR_NAME

    def __init__(self, ctx):
        self.ctx = context.Context(ctx, resources=resource.Pool())
        self.scenario = ctx.scenario
        self._name_parts = [
            'mcv',
            datetime.utcnow().strftime('%Y-%b-%d~%H-%M-%S')]

    def prepare_tests(self, test_group):
        try:
            return self.scenario[test_group]
        except KeyError:
            raise exceptions.MissingDataError(
                "Test group {group} doesn't seem to exist in config!"
                .format(group=test_group))

    @staticmethod
    def pretty_print_tests(test_plan):
        LOG.info("Amount of tests requested per available tools:")
        for group, test_list in test_plan.iteritems():
            LOG.info(" %s : %s", group, len(test_list))

    def get_results_dir(self, dst_dir=None):
        no_artifacts = lambda s: s.replace('.yaml', '').replace(':', '.')
        parts = map(no_artifacts, self._name_parts)
        dirname = '_'.join(parts)
        if dst_dir is None:
            return dirname
        return os.path.join(dst_dir, dirname)

    def do_group(self, test_group):
        self.group_name = test_group
        self._name_parts.append(test_group)
        test_plan = self.prepare_tests(test_group)
        self.pretty_print_tests(test_plan)
        return self._do_test_plan(test_plan)

    def do_single(self, test_group, test_name):
        """Run specific test.

        The test must be specified as this: testool/tests/tesname
        """
        self.group_name = test_group
        self._name_parts.append(test_group)
        self._name_parts.append(test_name)
        return self._do_test_plan({test_group: [test_name]})

    def do_name(self, test_group, test_name):
        """Run specific test by name. """
        self.group_name = test_group
        self._name_parts.append(test_group)
        self._name_parts.append(test_name.rsplit('.', 1)[-1])
        return self._do_test_plan({test_group: test_name}, run_by_name=True)

    def do_full(self):
        self.group_name = "Full"
        LOG.info("Starting full check run.")
        test_plan = discovery.get_all_tests()
        self.pretty_print_tests(test_plan)
        return self._do_test_plan(test_plan)

    def _do_test_plan(self, test_plan, **kwargs):
        self.results_dir = self.get_results_dir('/tmp')
        os.mkdir(self.results_dir)

        context.add(
            self.ctx, 'work_dir_global', utils.WorkDir(self.results_dir))
        context.add(self.ctx, 'work_dir', self.ctx.work_dir_global)

        self._collect_predefined_data()

        clean_up_wrapper = utils.DummyContextWrapper
        if CONF.cleanup.show_trash:
            clean_up_wrapper = cleanup.CleanUpWrapper

        with self._make_access_helper() as access_helper:
            self._update_ctx_with_access_data(access_helper)
            with clean_up_wrapper(self.ctx):
                return self._exec_tests(test_plan, **kwargs)

    def _exec_tests(self, test_plan, **kwargs):
        elapsed_time_by_group = {}
        dispatch_result = {}

        with open(TIMES_DB_PATH, 'r') as fd:
            db = json.load(fd)

        if not CONF.times.update:
            for name, tests in test_plan.iteritems():
                elapsed_time_by_group[name] = self.all_time
                for test in tests:
                    try:
                        self.all_time += db[name][test]
                    except KeyError:
                        LOG.info("You must update the database time tests. "
                                 "There is no time for %s", test)

            msg = "Expected time to complete all the tests: %s\n"
            time_str = utils.seconds_to_humantime(self.all_time)
            if self.all_time == 0:
                LOG.debug(msg, time_str)
            else:
                LOG.info(msg, time_str)

        for name, tests in test_plan.iteritems():
            if self.ctx.terminate_event.is_set():
                LOG.info("Catch Keyboard interrupt. "
                         "No more tests will be launched")
                break
            if CONF.times.update:
                elapsed_time_by_group[name] = 0
                # FIXME(dbogun): rewrite timesdb implementation
                # We must reload timesdb because plugin (probably) update id
                with open(TIMES_DB_PATH, 'rt') as fd:
                    db = json.load(fd)

            dispatch_result[name] = {}
            try:
                spawn_point = os.path.dirname(__file__)
                path_to_runner = os.path.join(spawn_point, self.plugin_dir,
                                              name, "runner.py")
                module = imp.load_source("runner" + name, path_to_runner)
            except IOError as e:
                LOG.debug("Looks like there is no such runner: %s.", name)
                dispatch_result[name]['major_crash'] = 1
                LOG.error("The following exception has been caught: %s", e)
                LOG.debug(traceback.format_exc())
                self.failure_indicator = CAError.RUNNER_LOAD_ERROR
            except Exception:
                dispatch_result[name]['major_crash'] = 1
                LOG.error("Something went wrong. "
                          "Please check mcvconsoler logs")
                LOG.debug(traceback.format_exc())
                self.failure_indicator = CAError.RUNNER_LOAD_ERROR
            else:
                path = os.path.join(self.results_dir, name)
                os.mkdir(path)

                tests_count = len(tests)
                max_failed_tests = CONF.get(name, {}).get('max_failed_tests')
                max_failed_tests = max_failed_tests if max_failed_tests > 0 \
                    else tests_count

                factory = getattr(module, CONF[name]['runner'])
                runner = factory(context.Context(
                    self.ctx,
                    max_failed_tests=max_failed_tests,
                    work_dir=utils.WorkDir(
                        path, parent=self.ctx.work_dir_global)))

                LOG.debug("Running {} tests for {}".format(tests_count, name))

                try:
                    run_failures = runner.run_batch(
                        tests,
                        compute=1,
                        event=self.ctx.terminate_event,
                        scenario=self.scenario,
                        tool_name=name,
                        db=db,
                        all_time=self.all_time,
                        elapsed_time=elapsed_time_by_group[name],
                        **kwargs
                    )

                    if len(run_failures['test_failures']) > 0:
                        if self.failure_indicator == CAError.NO_ERROR:
                            self.failure_indicator = runner.failure_indicator
                        else:
                            self.failure_indicator = \
                                ComplexError.SOME_SUITES_FAILED
                except subprocess.CalledProcessError as e:
                    if e.returncode == 127:
                        LOG.debug(("It looks like you are trying to use a "
                                   "wrong runner. No tests will be run in "
                                   "this group this time. Reply %s"), e)
                        self.failure_indicator = CAError.WRONG_RUNNER
                except Exception:
                    self.failure_indicator = CAError.UNKNOWN_EXCEPTION
                    LOG.error("Something went wrong. "
                              "Please check mcvconsoler logs")
                    LOG.debug(traceback.format_exc())
                else:
                    dispatch_result[name]['results'] = run_failures
                    dispatch_result[name]['batch'] = tests

        return dispatch_result

    def describe_results(self, results):
        """Pretty printer for results"""

        def time_of_test(t):
            return time_of_tests.get(t, {}).get('duration', '0s')

        def get(item, default=None):
            return results[key].get('results', {}).get(item, default)

        res_table = prettytable.PrettyTable(
            ["Group", "Plugin", "Test", "Time Duration", "Status"])

        res_table.add_row([self.group_name, "", "", "", ""])
        for key in results.iterkeys():

            if results[key].get('major_crash') is not None:
                LOG.info(
                    "A major tool failure has been detected for plugin '%s'",
                    key)
                continue
            if not validate_section(results[key]):
                LOG.debug('Error: no results for %s', key)
                continue

            test_success = get('test_success', [])
            test_failures = get('test_failures', [])
            test_not_found = get('test_not_found', [])
            test_without_report = get('test_without_report', [])
            test_skipped = get('test_skipped', [])
            time_of_tests = get('time_of_tests', {})

            tempest_tests_details = get('tempest_tests_details', {})

            if tempest_tests_details:
                for suit, suit_results in tempest_tests_details.iteritems():
                    status = ("FAILED" if suit_results["test_failed"]
                              else "SUCCESS")
                    suit_res = TEMPEST_OUTPUT_TEMPLATE.format(**suit_results)
                    msg = "{suit}\n{res}".format(suit=suit,
                                                 res=suit_res)

                    res_table.add_row(
                        ["", key, msg, time_of_test(suit), status])
            else:
                msg_parts = []
                if test_success:
                    msg_parts.append("Successful: {}".format(
                        len(test_success)))
                if test_failures or test_without_report:
                    msg_parts.append("Failed: {}"
                                     .format(len(test_failures +
                                                 test_without_report)))
                if test_not_found:
                    msg_parts.append("Not found: {}"
                                     .format(len(test_not_found)))
                if test_skipped:
                    msg_parts.append("Skipped: {}"
                                     .format(len(test_skipped)))

                msg = ", ".join(msg_parts)

                res_table.add_row(["", key, msg, "", ""])

                for test in test_success:
                    res_table.add_row(
                        ["", "", test, time_of_test(test), " OK "])
                for test in (test_failures + test_without_report):
                    res_table.add_row(
                        ["", "", test, time_of_test(test), " FAILED "])
                for test in test_not_found:
                    res_table.add_row(
                        ["", "", test, time_of_test(test), " NOT FOUND "])
                for test in test_skipped:
                    res_table.add_row(
                        ["", "", test, time_of_test(test), " SKIPPED "])
            res_table.add_row(["", "", "", "", ""])

        res_table.align = "l"
        print(res_table)

    @staticmethod
    def update_scenario(run_results):
        failed = 'failed'
        test_failures = 'test_failures'
        results = 'results'
        with open(CONF.basic.scenario, 'r+') as f:
            yaml = ruamel.yaml.round_trip_load(f)
            yaml_copy = copy.deepcopy(yaml)
            if failed in yaml:
                del yaml[failed]
            group = {}
            for key, value in run_results.iteritems():
                if not validate_section(value, test_failures):
                    continue
                failures = value[results][test_failures]
                if failures:
                    group[key] = failures
            if group:
                yaml[failed] = group
            if yaml != yaml_copy:
                f.seek(0)
                ruamel.yaml.round_trip_dump(yaml, f, block_seq_indent=2)
                f.truncate()

    def _do_finalization(self, run_results):
        if run_results is None:
            LOG.warning("For some reason test tools have returned nothing")
            return

        self.describe_results(run_results)
        self.update_scenario(run_results)
        try:
            reporter.brew_a_report(run_results, self.results_dir, 'index.html')
        except Exception as e:
            LOG.warning("Brewing a report has failed with error: %s" % str(e))
            LOG.debug(traceback.format_exc())
            return

    def make_results_archive(self):
        LOG.debug('Creating a .tar.gz archive with test reports')
        try:
            archive_file = '%s.tar.gz' % self.results_dir
            cmd = "tar -zcf {arch_file} -C {results_dir} .".format(
                arch_file=archive_file, results_dir=self.results_dir)
            utils.run_cmd(cmd)

            cmd = "rm -rf %s" % self.results_dir
            utils.run_cmd(cmd)
        except subprocess.CalledProcessError:
            LOG.warning('Creation of .tar.gz archive has failed. See log '
                        'for details. You can still get your files from: '
                        '%s', self.results_dir, exc_info=1)
            return

        LOG.debug("Finished creating a report.")
        LOG.info("One page report could be found in %s\n", archive_file)

    def __call__(self):
        # FIXME(dbogun): implement acceptable way to run different cli commands
        if self.ctx.args.remove_trash is not False:
            self._show_resources()
            return
        elif self.ctx.args.compare_resources:
            self._show_resources()
            return

        params = self.ctx.args.run[:]
        method = params.pop(0)

        try:
            handler = getattr(self, "do_" + method)
        except AttributeError:
            LOG.error('\nError: No such runner: %s\n', method)
            return CAError.WRONG_RUNNER

        self._name_parts.append(method)

        try:
            run_results = handler(*params)
            self._do_finalization(run_results)
        except exceptions.AccessError as e:
            LOG.error('Have some issues with accessing cloud: %s', e)
            LOG.debug('Error details', exc_info=True)
            self.failure_indicator = CAError.WRONG_CREDENTIALS
        finally:
            LOG.debug('Perform house keeping')
            self.ctx.resources.terminate()
        return self.failure_indicator

    def _show_resources(self):
        self.results_dir = self.get_results_dir('/tmp')
        os.mkdir(self.results_dir)
        context.add(
            self.ctx, 'work_dir_global', utils.WorkDir(self.results_dir))
        context.add(self.ctx, 'work_dir', self.ctx.work_dir_global)
        self._collect_predefined_data()
        with self._make_access_helper() as access_helper:
            self._update_ctx_with_access_data(access_helper)

            cloud_cleanup = cleanup.Cleanup(self.ctx)
            if self.ctx.args.remove_trash is not False:
                cloud_cleanup.find_show_resources()
            else:
                cloud_cleanup.compare_yaml_resources(
                    self.ctx.args.compare_resources)
        self.ctx.resources.terminate()

    def _make_access_helper(self):
        return AccessSteward(
            self.ctx, self.ctx.args.run_mode)

    def _update_ctx_with_access_data(self, access_helper):
        access_data = access_helper.access_data()
        context.add(self.ctx, 'access_data', access_data)
        context.add(
            self.ctx, 'access', clients.OSClientsProxy(
                self.ctx, access_data))

    def _collect_predefined_data(self):
        work_dir = self.ctx.work_dir_global
        args = self.ctx.args

        if args.os_ssh_key:
            dest = work_dir.resource(work_dir.RES_OS_SSH_KEY, lookup=False)
            ssh.save_private_key(dest, args.os_ssh_key.read())

        for opt, res in (
                ('os_openrc', work_dir.RES_OS_OPENRC),
                ('os_fuelclient_settings', work_dir.RES_FUELCLIENT_SETTINGS)):
            opt = getattr(args, opt)
            if not opt:
                continue

            with open(
                    work_dir.resource(res, lookup=False), 'wt') as dest:
                shutil.copyfileobj(opt, dest)
