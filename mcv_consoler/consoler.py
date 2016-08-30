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

from ConfigParser import NoSectionError
from datetime import datetime
from distutils import util
import imp
import json
import logging
import os
import re
import shutil
import subprocess
import traceback

import prettytable

from mcv_consoler.accessor import AccessSteward
from mcv_consoler.common.config import DEFAULT_CONFIG_FILE
from mcv_consoler.common.config import PLUGINS_DIR_NAME
from mcv_consoler.common.config import TIMES_DB_PATH
from mcv_consoler.common import context
from mcv_consoler.common import clients
from mcv_consoler.common.errors import CAError
from mcv_consoler.common.errors import ComplexError
from mcv_consoler.common import resource
from mcv_consoler.common import ssh
from mcv_consoler.common.test_discovery import discovery
from mcv_consoler import exceptions
from mcv_consoler import reporter
from mcv_consoler.reporter import validate_section
from mcv_consoler import utils
from mcv_consoler.common import cleanup

LOG = logging.getLogger(__name__)

TEMPEST_OUTPUT_TEMPLATE = "Total: {tests}, Success: {test_succeed}, " \
                          "Failed: {test_failed}, Skipped: {test_skipped}, " \
                          "Expected failures: {expected_failures}"


class Consoler(object):
    all_time = 0
    group_name = None
    results_dir = None
    failure_indicator = CAError.NO_ERROR
    plugin_dir = PLUGINS_DIR_NAME

    def __init__(self, ctx):
        self.ctx = context.Context(ctx, resources=resource.Pool())
        self.config = ctx.config
        self.cloud_cleanup = None
        self._name_parts = [
            'mcv',
            datetime.utcnow().strftime('%Y-%b-%d~%H-%M-%S')]

    def prepare_tests(self, test_group):
        section = "custom_test_group_" + test_group
        try:
            self.config.options(section)
        except NoSectionError:
            LOG.warning(("Test group {group} doesn't seem to exist "
                         "in config!").format(group=test_group))
            return {}

        out = dict([(opt, self.config.get(section, opt)) for opt in
                    self.config.options(section)])
        return out

    def split_tests(self, runner, tests_str):
        res = list()
        lines = tests_str.split('\n')
        for line in lines:
            raw_tests = line.strip(', ').split(',')
            tests = map(str.strip, raw_tests)
            res.extend(tests)
        LOG.debug("Selected {n} tests for '{key}' runner: {tests}".format(
            n=len(res), key=runner, tests=', '.join(res)))
        return res

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

        def pretty_print_tests(tests):
            LOG.info("Amount of tests requested per available tools:")
            for group, test_list in tests.iteritems():
                test_list = test_list.strip(', ')
                LOG.info(" %s : %s", group, len(test_list.split(',')))

        test_plan = self.prepare_tests(test_group)
        if test_plan is None:
            return None

        pretty_print_tests(test_plan)

        return self._do_test_plan(test_plan)

    def do_single(self, test_group, test_name):
        """Run specific test.

        The test must be specified as this: testool/tests/tesname
        """
        self.group_name = test_group
        self._name_parts.append(test_group)
        self._name_parts.append(test_name)
        return self._do_test_plan({test_group: test_name})

    def do_name(self, test_group, test_name):
        """Run specific test by name.
        """
        self.group_name = test_group
        self._name_parts.append(test_group)
        self._name_parts.append(test_name.rsplit('.', 1)[-1])
        return self._do_test_plan({test_group: test_name})

    def do_full(self):
        self.group_name = "Full"
        LOG.info("Starting full check run.")
        return self._do_test_plan(discovery.get_all_tests())

    # FIXME(dbogun): rewrite/move to utils
    def seconds_to_time(self, s):
        h = s // 3600
        m = (s // 60) % 60
        sec = s % 60

        if m < 10:
            m = str('0' + str(m))
        else:
            m = str(m)
        if sec < 10:
            sec = str('0' + str(sec))
        else:
            sec = str(sec)

        return str(h) + 'h : ' + str(m) + 'm : ' + str(sec) + 's'

    def _do_test_plan(self, test_plan):
        self.results_dir = self.get_results_dir('/tmp')
        os.mkdir(self.results_dir)

        context.add(
            self.ctx, 'work_dir_global', utils.WorkDir(self.results_dir))
        context.add(self.ctx, 'work_dir', self.ctx.work_dir_global)

        self._collect_predefined_data()

        access_helper = AccessSteward(
            self.ctx, self.ctx.args.run_mode,
            port_forwarding=not self.ctx.args.no_tunneling)

        if not access_helper.check_and_fix_environment():
            raise exceptions.AccessError(
                'Unable to setup access to OS cloud.')
        try:
            self._exec_tests(test_plan, access_helper)
        finally:
            access_helper.cleanup()

    def _exec_tests(self, test_plan, access_helper):
        elapsed_time_by_group = dict()
        dispatch_result = {}

        with open(TIMES_DB_PATH, 'r') as fd:
            db = json.load(fd)

        if self.config.get('times', 'update') == 'False':
            for key in test_plan.keys():
                batch = [x for x in (''.join(test_plan[key].split()
                                             ).split(',')) if x]
                elapsed_time_by_group[key] = self.all_time
                for test in batch:
                    test = test.replace(' ', '')
                    try:
                        self.all_time += db[key][test]
                    except KeyError:
                        LOG.info("You must update the database time tests. "
                                 "There is no time for %s", test)

            msg = "Expected time to complete all the tests: " \
                  "%s\n" % self.seconds_to_time(self.all_time)
            if self.all_time == 0:
                LOG.debug(msg)
            else:
                LOG.info(msg)

        for key in test_plan:
            if self.ctx.terminate_event.is_set():
                LOG.info("Catch Keyboard interrupt. "
                         "No more tests will be launched")
                break
            if self.config.get('times', 'update') == 'True':
                # FIXME(dbogun): this value is always forced to 0, look
                # like a bug
                elapsed_time_by_group[key] = 0
                # FIXME(dbogun): rewrite timesdb implementation
                # We must reload timesdb because plugin (probably) update id
                with open(TIMES_DB_PATH, 'rt') as fd:
                    db = json.load(fd)

            dispatch_result[key] = {}
            try:
                spawn_point = os.path.dirname(__file__)
                path_to_runner = os.path.join(spawn_point, self.plugin_dir,
                                              key, "runner.py")
                module = imp.load_source("runner" + key, path_to_runner)
            except IOError as e:
                LOG.debug("Looks like there is no such runner: %s.", key)
                dispatch_result[key]['major_crash'] = 1
                LOG.error("The following exception has been caught: %s", e)
                LOG.debug(traceback.format_exc())
                self.failure_indicator = CAError.RUNNER_LOAD_ERROR
            except Exception:
                dispatch_result[key]['major_crash'] = 1
                LOG.error("Something went wrong. "
                          "Please check mcvconsoler logs")
                LOG.debug(traceback.format_exc())
                self.failure_indicator = CAError.RUNNER_LOAD_ERROR
            else:
                path = os.path.join(self.results_dir, key)
                os.mkdir(path)

                factory = getattr(module, self.config.get(key, 'runner'))
                access_data = access_helper.access_data()
                runner = factory(context.Context(
                    self.ctx,
                    work_dir=utils.WorkDir(
                        path, parent=self.ctx.work_dir_global),
                    access_data=access_data,
                    access=clients.OSClientsProxy(self.ctx, access_data)))

                batch = test_plan[key]
                if isinstance(batch, basestring):
                    batch = self.split_tests(key, batch)

                LOG.debug("Running {batch} for {key}"
                          .format(batch=len(batch),
                                  key=key))

                try:
                    run_failures = runner.run_batch(
                        batch,
                        compute=1,
                        event=self.ctx.terminate_event,
                        config=self.config,
                        tool_name=key,
                        db=db,
                        all_time=self.all_time,
                        elapsed_time=elapsed_time_by_group[key])

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
                    dispatch_result[key]['results'] = run_failures
                    dispatch_result[key]['batch'] = batch

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
                    msg_parts.append("Successful: {}".format(len(test_success)))
                if test_failures or test_without_report:
                    msg_parts.append("Failed: {}"
                                     .format(len(test_failures +
                                                 test_without_report)))
                if test_not_found:
                    msg_parts.append("Not found: {}"
                                     .format(len(test_not_found)))

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
            res_table.add_row(["", "", "", "", ""])

        res_table.align = "l"
        print(res_table)

    def _search_and_remove_group_failed(self, file_to_string):
        object_for_search = re.compile(
            r"\[custom_test_group_failed\].*?End\sof.*?\n",
            re.DOTALL)

        list_of_strings = object_for_search.findall(file_to_string)
        if list_of_strings:
            LOG.debug("Your config contains one or more "
                      "'custom_test_group_failed'."
                      "It will be removed")
            return re.sub(object_for_search, "", file_to_string)
        else:
            return file_to_string

    def update_config(self, results):
        with open(DEFAULT_CONFIG_FILE, 'r') as f:
            file_to_string = f.read()

        result = self._search_and_remove_group_failed(file_to_string)

        default_str = ""
        for key in results.iterkeys():
            if not validate_section(results[key], 'test_failures'):
                continue
            to_rerun = ",".join(results[key]["results"]["test_failures"])
            if to_rerun != "":
                default_str = (default_str + str(key) + '=' +
                               str(to_rerun) + '\n')
        if default_str != "":
            default_str = ("\n[custom_test_group_failed]\n" +
                           default_str + "# End of group failed. Don't remove"
                           + "this comment\n")

        with open(DEFAULT_CONFIG_FILE, 'w') as f:
            f.write(result + default_str)

    def _do_finalization(self, run_results):
        if run_results is None:
            LOG.warning("For some reason test tools have returned nothing")
            return

        self.describe_results(run_results)
        self.update_config(run_results)
        try:
            reporter.brew_a_report(run_results, self.results_dir, 'index.html')
        except Exception as e:
            LOG.warning("Brewing a report has failed with error: %s" % str(e))
            LOG.debug(traceback.format_exc())
            return

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
                        '%s' % self.results_dir)
            LOG.debug(traceback.format_exc())
            return

        LOG.debug("Finished creating a report.")
        LOG.info("One page report could be found in %s\n" % archive_file)

    def __call__(self):
        if self.ctx.args.compare_resources:
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
            if not self._check_fix_env():
                return CAError.WRONG_CREDENTIALS
            cleanup_status = utils.GET(self.config, 'show_trash', 'cleanup')

            try:
                if util.strtobool(cleanup_status):
                    self.cloud_cleanup = cleanup.Cleanup(
                        self.config, self.access_helper.access_data())
                    self.cloud_cleanup.get_started_resources()
            except Exception:
                LOG.error("Something went wrong with the command, "
                          "please refer to logs to discover the problem.")
                LOG.debug('Error details', exc_info=True)
                self.failure_indicator = CAError.UNKNOWN_OUTER_ERROR
            run_results = handler(*params)
            self._do_finalization(run_results)

        except exceptions.AccessError as e:
            LOG.error('Have some issues with accessing cloud: %s', e)
            LOG.debug('Error details', exc_info=True)
            self.failure_indicator = CAError.WRONG_CREDENTIALS
        finally:
            try:
                if self.cloud_cleanup:
                    self.cloud_cleanup.get_finished_resources()
            except Exception as e:
                LOG.debug(traceback.format_exc())
                LOG.debug('Cleanup failed.')

            for handler in (
                    self.access_helper.cleanup,
                    self.ctx.resources.terminate):
                try:
                    handler()
                except Exception as e:
                    LOG.error(
                        'Unhandled error during housekeeping stage: {}',
                        e, exc_info=True)

        return self.failure_indicator

    def _show_resources(self):
        if not self._check_fix_env():
            self.access_helper.cleanup()
            return CAError.WRONG_CREDENTIALS
        cloud_cleanup = cleanup.Cleanup(
            self.config, self.access_helper.access_data())
        try:
            cloud_cleanup.compare_yaml_resources(self.ctx.args.compare_resources[0])
        except Exception:
            LOG.debug("Cleanup failed", exc_info=True)
        finally:
            self.access_helper.cleanup()

    def _check_fix_env(self):
        # TODO(vokhrimenko): need rewrite function.
        # Best way - using a context manager
        try:
            self.access_helper = AccessSteward(
                self.ctx, self.ctx.args.run_mode,
                port_forwarding=not self.ctx.args.no_tunneling)
            if not self.access_helper.check_and_fix_environment():
                raise exceptions.AccessError(
                    'Unable to setup access to OS cloud.')
            return True
        except Exception as e:
            LOG.info("Something went wrong with checking credentials "
                     "and preparing environment")
            LOG.error("The following error has terminated "
                      "the consoler: %s", repr(e))
            LOG.debug('Error details', exc_info=True)
            return False

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
