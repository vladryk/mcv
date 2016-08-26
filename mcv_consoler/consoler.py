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
import imp
import json
import os
import prettytable
import re
import subprocess
import traceback

from mcv_consoler.accessor import AccessSteward
from mcv_consoler.common.config import DEFAULT_CONFIG_FILE
from mcv_consoler.common.config import PLUGINS_DIR_NAME
from mcv_consoler.common.config import TIMES_DB_PATH
from mcv_consoler.common.errors import CAError
from mcv_consoler.common.errors import ComplexError
from mcv_consoler.common.test_discovery import discovery
from mcv_consoler.logger import LOG
from mcv_consoler import reporter
from mcv_consoler.reporter import validate_section
from mcv_consoler import utils

LOG = LOG.getLogger(__name__)

TEMPEST_OUTPUT_TEMPLATE = "Total: {tests}, Success: {test_succeed}, " \
                          "Failed: {test_failed}, Skipped: {test_skipped}, " \
                          "Expected failures: {expected_failures}"


class Consoler(object):
    def __init__(self, config, args):
        self.config = config
        self.args = args
        self.all_time = 0
        self.plugin_dir = PLUGINS_DIR_NAME
        self.failure_indicator = CAError.NO_ERROR
        self.timestamp_str = datetime.utcnow().strftime('%Y-%b-%d~%H-%M-%S')
        self.group_name = None
        self.results_dir = None
        self._name_parts = ['mcv', self.timestamp_str]

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

        tests_to_run = self.prepare_tests(test_group)
        if tests_to_run is None:
            return None

        pretty_print_tests(tests_to_run)

        return self.dispatch_tests_to_runners(tests_to_run)

    def do_single(self, test_group, test_name):
        """Run specific test.

        The test must be specified as this: testool/tests/tesname
        """
        self.group_name = test_group
        self._name_parts.extend((test_group, test_name))
        the_one = dict(((test_group, test_name),))
        return self.dispatch_tests_to_runners(the_one)

    def do_name(self, test_group, test_name):
        """Run specific test by name.
        """
        kwargs = {'run_by_name': True}
        self.group_name = test_group
        self._name_parts.extend((test_group, test_name.split('.')[-1]))
        the_one = dict(((test_group, test_name),))
        return self.dispatch_tests_to_runners(the_one, **kwargs)

    def do_full(self):
        self.group_name = "Full"
        LOG.info("Starting full check run.")
        test_dict = discovery.get_all_tests()
        return self.dispatch_tests_to_runners(test_dict)

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

    def dispatch_tests_to_runners(self, test_dict, *args, **kwargs):
        dispatch_result = {}
        self.results_dir = self.get_results_dir('/tmp')
        os.mkdir(self.results_dir)

        f = open(TIMES_DB_PATH, 'r')
        db = json.loads(f.read())
        elapsed_time_by_group = dict()
        f.close()

        if self.config.get('times', 'update') == 'False':
            for key in test_dict.keys():
                batch = [x for x in (''.join(test_dict[key].split()
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

        for key in test_dict.keys():
            if self.event.is_set():
                LOG.info("Catch Keyboard interrupt. "
                         "No more tests will be launched")
                break
            if self.config.get('times', 'update') == 'True':
                elapsed_time_by_group[key] = 0
                f = open(TIMES_DB_PATH, 'r')
                db = json.loads(f.read())
                f.close()

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
                runner = getattr(
                    module,
                    self.config.get(key, 'runner'))(self.access_helper.router
                                                    .get_os_data(),
                                                    path,
                                                    config=self.config)

                batch = test_dict[key]
                if isinstance(batch, basestring):
                    batch = self.split_tests(key, batch)

                LOG.debug("Running {batch} for {key}"
                          .format(batch=len(batch),
                                  key=key))

                try:
                    run_failures = runner.run_batch(
                        batch,
                        compute=1,
                        event=self.event,
                        config=self.config,
                        tool_name=key,
                        db=db,
                        all_time=self.all_time,
                        elapsed_time=elapsed_time_by_group[key],
                        test_group=kwargs.get('testgroup'),
                        run_by_name=kwargs.get('run_by_name', False)
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

    def get_total_failures(self, results):
        t_failures = 0
        for key in results.iterkeys():
            if validate_section(results[key], 'test_failures'):
                t_failures += len(results[key]['results']['test_failures'])
        return t_failures

    def existing_plugin(self, plugin):
        base = os.path.join(os.path.dirname(__file__), self.plugin_dir)
        dirstolist = os.listdir(base)
        dirlist = filter(lambda x: os.path.isdir(os.path.join(base, x)),
                         dirstolist)
        return plugin in dirlist

    def a_real_file(self, fname, group):
        dir_to_walk = os.path.join(os.path.dirname(__file__), self.plugin_dir,
                                   group, "tests")
        return fname in os.listdir(dir_to_walk)

    def do_test(self):
        arguments = ' '.join(i for i in self.args.test)
        subprocess.call(('/opt/mcv-consoler/tests/tmux_mcv_tests_runner.sh '
                         '"({0})"').format(arguments),
                        shell=True,
                        preexec_fn=utils.ignore_sigint)
        return 1

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

    def console_user(self, event, result):
        self.event = event

        runner = getattr(self, "do_" + self.args.run[0], None)
        params = self.args.run[1:]
        if not runner:
            LOG.error('\nError: No such runner: %s\n' % self.args.run[0])
            return result.append(CAError.WRONG_RUNNER)
        self._name_parts.append(self.args.run[0])

        run_mode = self.args.run_mode
        try:
            kwargs = {'port_forwarding': not self.args.no_tunneling}
            self.access_helper = AccessSteward(self.config, event, run_mode,
                                               **kwargs)
            env_ready = self.access_helper.check_and_fix_environment()
        except Exception as e:
            LOG.info("Something went wrong with checking credentials "
                     "and preparing environment")
            LOG.error("The following error has terminated "
                      "the consoler: %s", repr(e))
            LOG.debug(traceback.format_exc())
            result.append(CAError.WRONG_CREDENTIALS)
            return
        if not env_ready:
            result.append(CAError.WRONG_CREDENTIALS)
            self.access_helper.cleanup()
            return

        try:
            run_results = runner(*params)
            self._do_finalization(run_results)
        except Exception:
            LOG.error("Something went wrong with the command, "
                      "please refer to logs to discover the problem.")
            LOG.debug(traceback.format_exc())
            self.failure_indicator = CAError.UNKNOWN_OUTER_ERROR
        finally:
            self.access_helper.cleanup()

        result.append(self.failure_indicator)
