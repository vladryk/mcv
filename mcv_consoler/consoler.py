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
import inspect
import json
import os
import re
import subprocess
import sys
import traceback

from mcv_consoler import accessor
from mcv_consoler.common.cfgparser import config_parser
from mcv_consoler.common.config import DEFAULT_CONFIG_FILE
from mcv_consoler.common.errors import CAError
from mcv_consoler.common.errors import ComplexError
from mcv_consoler.logger import LOG
from mcv_consoler import reporter
from mcv_consoler import utils

LOG = LOG.getLogger(__name__)


class Consoler(object):
    def __init__(self, parser, args):
        self.config = config_parser
        self.parser = parser
        self.args = args
        self.all_time = 0
        self.plugin_dir = "plugins"
        self.failure_indicator = CAError.NO_ERROR
        self.config_config()
        self.concurrency = self.config.get('basic', 'concurrency')
        self.gre_enabled = self.config.get('basic', "gre_enabled")
        self.vlan_amount = self.config.get('basic', "vlan_amount")

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

    def config_config(self):
        if self.args.config is not None:
            default_config = self.args.config
        else:
            default_config = DEFAULT_CONFIG_FILE
        self.path_to_config = os.path.join(os.path.dirname(__file__),
                                           default_config)
        self.config.read(self.path_to_config)

    def do_custom(self, test_group):
        def pretty_print_tests(tests):
            LOG.info("Amount of tests requested per available tools:")
            for group, test_list in tests.iteritems():
                LOG.info(" %s : %s", group, len(test_list.split(',')))
            LOG.info('\n')

        tests_to_run = self.prepare_tests(test_group)
        if tests_to_run is None:
            return None

        pretty_print_tests(tests_to_run)

        if test_group.find('scale') != -1:
            return self.do_scale(tests_to_run)
        return self.dispatch_tests_to_runners(tests_to_run)

    def do_scale(self, tests_to_run):
        LOG.info("Starting scale check run.")
        self.concurrency = self.config.get('scale', 'concurrency')
        return self.dispatch_tests_to_runners(tests_to_run)

    def do_single(self, test_group, test_name):
        """Run specific test.

        The test must be specified as this: testool/tests/tesname
        """
        the_one = dict(((test_group, test_name),))
        return self.dispatch_tests_to_runners(the_one)

    def discover_test_suits(self):
        # TODO(aovchinnikov): generalize discovery
        scenario_dir = os.path.join(os.path.dirname(__file__), self.plugin_dir)
        possible_places = map(lambda x: os.path.join(scenario_dir, x),
                              os.listdir(scenario_dir))
        per_component = [(x.split('/')[-1],
                          os.listdir(os.path.join(x, "tests")))
                         for x in filter(lambda x: os.path.isdir(x),
                                         possible_places)]
        per_component = dict(per_component)
        for k, v in per_component.iteritems():
            per_component[k] = ",".join(v)
        return dict(per_component)

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
        self.results_vault = "/tmp/mcv_run_{dt}".format(
                             dt=str(datetime.utcnow()).replace(" ", "_"))
        os.mkdir(self.results_vault)

        f = open('/etc/mcv/times.json', 'r')
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
                        LOG.info(("You must update the database time tests. "
                                 "There is no time for %s") % test)

            LOG.info("\nExpected time to complete all the tests: %s\n" %
                     self.seconds_to_time(self.all_time))

        for key in test_dict.keys():
            if self.event.is_set():
                LOG.info("Catch Keyboard interrupt. "
                         "No more tests will be launched")
                break
            if self.config.get('times', 'update') == 'True':
                elapsed_time_by_group[key] = 0
                f = open('/etc/mcv/times.json', 'r')
                db = json.loads(f.read())
                f.close()

            dispatch_result[key] = {}
            try:
                spawn_point = os.path.dirname(__file__)
                path_to_runner = os.path.join(spawn_point, self.plugin_dir,
                                              key, "runner.py")
                m = imp.load_source("runner" + key, path_to_runner)
            except IOError as e:
                LOG.debug("Looks like there is no such runner: " + key + ".")
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
                path = os.path.join(self.results_vault, key)
                os.mkdir(path)
                runner = getattr(m, self.config.get(key, 'runner')
                                 )(self.access_helper,
                                   path,
                                   config=self.config)

                batch = [x for x in (''.join(test_dict[key].split()
                                             ).split(',')) if x]

                LOG.debug("Running {batch} for {key}".format(
                          batch=str(len(batch)),
                          key=key))

                if isinstance(self.concurrency, basestring):
                    self.concurrency = int(self.concurrency)

                try:
                    run_failures = runner.run_batch(
                        batch,
                        compute=1,
                        event=self.event,
                        concurrency=self.concurrency,
                        config=self.config,
                        tool_name=key,
                        db=db,
                        all_time=self.all_time,
                        elapsed_time=elapsed_time_by_group[key],
                        gre_enabled=self.gre_enabled,
                        vlan_amount=self.vlan_amount,
                        test_group=kwargs.get('testgroup'))

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
                    run_failures = test_dict[key].split(',')
                    self.failure_indicator = CAError.UNKNOWN_EXCEPTION
                    LOG.error("Something went wrong. "
                              "Please check mcvconsoler logs")
                    LOG.debug(traceback.format_exc())
                else:
                    dispatch_result[key]['results'] = run_failures
                    dispatch_result[key]['batch'] = batch

        return dispatch_result

    def do_full(self):

        LOG.info("Starting full check run.")
        LOG.warning("WARNING! Full test suite contains Rally load tests. "
                    "These tests may break your cloud. It is not recommended "
                    "to run these tests on production clouds.")

        if self.config.get('rally', 'rally_load') != 'True':
            LOG.info("WARNING! Full test suite contains Rally load tests. "
                     "These tests may break your cloud. So, please set "
                     "rally_load=True manually in mcv.conf.")
            return {}

        test_dict = self.discover_test_suits()
        return self.dispatch_tests_to_runners(test_dict)

    def describe_results(self, results):
        """Pretty printer for results"""
        LOG.info('\n')
        LOG.info("-" * 40)
        LOG.info("The run resulted in:")
        for key in results.iterkeys():
            LOG.info("For %s:", key)
            if results[key].get('major_crash', None) is not None:
                LOG.info("A major tool failure has been detected")
                continue
            LOG.info('\n')
            LOG.info(len(results[key]['results']['test_success']))
            LOG.info("\t\t successful tests")
            LOG.info(len(results[key]['results']['test_failures']))
            LOG.info("\t\t failed tests")

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

    def console_user(self, event, result):
        # TODO(aovchinnikov): split this god's abomination.
        self.event = event

        def do_finalization(run_results):
            if run_results is None:
                LOG.warning("For some reason test tools have returned nothing")
                return

            self.describe_results(run_results)
            self.update_config(run_results)
            try:
                reporter.brew_a_report(run_results,
                                       self.results_vault + "/index.html")
            except Exception as e:
                LOG.warning("Brewing a report has failed with "
                            "error: %s" % str(e))
                LOG.debug(traceback.format_exc())
                return

            result_dict = {
                "timestamp": str(datetime.utcnow()).replace(" ", "_"),
                "location": self.results_vault
            }

            LOG.info('Creating a .tar.gz archive with test reports')
            try:
                cmd = ("tar -zcf /tmp/mcv_run_%(timestamp)s.tar.gz"
                       " -C %(location)s .") % result_dict
                utils.run_cmd(cmd)

                cmd = "rm -rf %(location)s" % {"location": self.results_vault}
                utils.run_cmd(cmd)
            except subprocess.CalledProcessError:
                LOG.warning('Creation of .tar.gz archive has failed. See log '
                            'for details. You can still get your files from: '
                            '%s' % self.results_vault)
                LOG.debug(traceback.format_exc())
                return

            LOG.debug("Finished creating a report.")
            LOG.info("One page report could be found in "
                     "/tmp/mcv_run_%(timestamp)s.tar.gz" % result_dict)

            return result_dict

        if len(sys.argv) < 2:
            self.parser.print_help()
            result.append(CAError.TOO_FEW_ARGS)
            return

        run_results = None

        if self.args.run is not None:
            self.access_helper = accessor.AccessSteward(
                self.config,
                self.event,
                not self.args.no_tunneling)
            try:
                res = self.access_helper.check_and_fix_environment()
                if not res:
                    result.append(CAError.WRONG_CREDENTIALS)
                    self.access_helper.cleanup()
                    return
            except Exception as e:
                LOG.info("Something went wrong with checking credentials "
                         "and preparing environment")
                LOG.error("The following error has terminated "
                          "the consoler: %s", repr(e))
                LOG.debug(traceback.format_exc())
                result.append(CAError.WRONG_CREDENTIALS)
                return

            try:
                run_results = getattr(self, "do_" + self.args.run[0])(
                    *self.args.run[1:])
            except TypeError as e:
                run_name = "do_" + self.args.run[0]
                expected_arglist = inspect.getargspec(
                    getattr(self, run_name)).args

                scolding = {"supplied_args": ", ".join(self.args.run[1:]),
                            "function": self.args.run[0],
                            "expected_args": "\', \'".join(expected_arglist),
                            "error": e}

                temessage = ("Somehow \'%(supplied_args)s\' is not enough for "
                             "\'%(function)s\'\n\'%(function)s\' actually "
                             "expects the folowing arguments: \'"
                             "%(expected_args)s\' Reply: \'%(error)s\'")

                LOG.error(temessage % scolding)
            except ValueError as e:
                LOG.error("Some unexpected outer error has terminated "
                          "the tool. Please try rerunning mcvconsoler. "
                          "Reply: %s", e)
                LOG.debug(traceback.format_exc())
                self.failure_indicator = CAError.UNKNOWN_OUTER_ERROR
            except Exception:
                LOG.error("Something went wrong with the command, "
                          "please refer to logs to discover the problem.")
                LOG.debug(traceback.format_exc())
                self.failure_indicator = CAError.UNKNOWN_OUTER_ERROR

        elif self.args.test is not None:
            arguments = ' '.join(i for i in self.args.test)
            subprocess.call(('/opt/mcv-consoler/tests/'
                             'tmux_mcv_tests_runner.sh '
                             '"({0})"').format(arguments),
                            shell=True,
                            preexec_fn=utils.ignore_sigint)
            return 1
        do_finalization(run_results)
        self.access_helper.cleanup()
        result.append(self.failure_indicator)
