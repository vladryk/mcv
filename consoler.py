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

import accessor
import datetime
import inspect
import ConfigParser
import imp
import json
import reporter
import subprocess
import traceback
import os
import sys

import utils
from logger import LOG
LOG = LOG.getLogger(__name__)


class Consoler(object):
    """Consoles poor user when her stack is not working as expected"""

    def __init__(self, parser, args):
        self.config = ConfigParser.ConfigParser()
        self.default_config_file = "/etc/mcv/mcv.conf"
        self.parser = parser
        self.args = args
        self.all_time = 0
        self.plugin_dir = "test_scenarios"
        self.failure_indicator = 0
        self.config_config()
        self.concurrency = self.config.get('basic', 'concurrency')
        self.gre_enabled = self.config.get('basic', "gre_enabled")
        self.vlan_amount = self.config.get('basic', "vlan_amount")

    def prepare_tests(self, test_group):
        section  = "custom_test_group_" + test_group
        try:
            restmp = self.config.options(section)
        except ConfigParser.NoSectionError:
            LOG.warning("Test group %s doesn't seem to exist in config!" % test_group)
            return {}

        out =  dict([(opt, self.config.get(section, opt)) for opt in
                    self.config.options(section)])
        return out

    def config_config(self):
        if self.args.config is not None:
            default_config = self.args.config
        else:
            default_config = self.default_config_file
        self.path_to_config = os.path.join(os.path.dirname(__file__),
                                           default_config)
        self.config.read(self.path_to_config)

    def do_custom(self, test_group):
        """Run custom test set.

        Custom test list should be stored in /etc/cloud_validator/mcv.conf.
        Test should be placed in sections named [custom_test_group_<groupname>]
        Two sections exist by default: [custom_test_group_default] which gets
        called each time custom does not get any parameter and another section
        [custom_test_group_short] which contains the most essential tests per
        average cloud operator opinion.
        Tool-specific tests should be described as follows:
        <tool1_name>=<testscenario1>,<testscenario2>,...
        <tool2_name>=<testscenario1>,<testscenario2>,...
        the test scenarios are supposed to be stored in corresponding place
        in MCVpackage. Each test scenraio is supposed to be stored in a separate
        file, also in some cases tests must be grouped together. This should be
        done per test tool. Arbitrary number of sections is allowed to be present
        in a config file. In case several custom groups have identical names
        the last will be used.
        """
        def pretty_print_tests(tests):
            LOG.info("The following amount of tests is requested per available tools:")
            for group, test_list in tests.iteritems():
                LOG.info(" %s : %s", group, len(test_list.split(',')))
            LOG.info('\n')

        if test_group == 'default':
            LOG.info("Either no group has been explicitly requested or it was group 'default'.")

        # NOTE: this cludge is used to prevent accidental production cloud
        # destruction and relies solely on group name. It is not bulletproof as
        # anyone could create loading group with a wrong name and easily break
        # everything up.

        if test_group.find('load') != -1 and test_group.find('workload') == -1:
            if self.config.get('rally', 'rally_load') != 'True':
                LOG.info("WARNING! Load test suit contains rally load tests. These tests may "
                         "break your cloud. So, please set rally_load=True manually in mcv.conf ")
                return None
        tests_to_run = self.prepare_tests(test_group)
        if tests_to_run is None:
            return None
        # tests_to_run is a dictionary that looks like this:
        # {'rally':'test1,test2,test3', 'ostf':'test1,test2', 'wtf':'test8'}
        pretty_print_tests(tests_to_run)
        if test_group.find('scale') != -1:
            return self.do_scale(tests_to_run)
        return self.dispatch_tests_to_runners(tests_to_run)

    def do_scale(self, tests_to_run):
        LOG.info("Starting scale check run.")
        self.concurrency = self.config.get('scale', 'concurrency')
        return self.dispatch_tests_to_runners(tests_to_run)

    def do_short(self):
        """Run the most essential tests.
        """
        # [custom_test_group_short]
        return self.do_custom("short")

    def do_single(self, test_group, test_name):
        """Run specific test.

        The test must be specified as this: testool/tests/tesname
        """
        the_one = dict(((test_group, test_name),))
        return self.dispatch_tests_to_runners(the_one)

    def discover_test_suits(self):
        """Discovers tests in default location.
        """
        # TODO: generalize discovery
        self.config.get('basic', 'scenario_dir')
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
        self.results_vault = "/tmp/mcv_run_" + str(datetime.datetime.utcnow()).replace(" ","_")
        os.mkdir(self.results_vault)

        f = open(os.path.join(os.path.dirname(__file__), 'times.json'), 'r')
        db = json.loads(f.read())
        elapsed_time_by_group = dict()
        f.close()

        if self.config.get('times', 'update') == 'False':
            for key in test_dict.keys():
                batch = [x for x in (''.join(test_dict[key].split()).split(',')) if x]
                elapsed_time_by_group[key] = self.all_time
                for test in batch:
                    test = test.replace(' ', '')
                    try:
                        self.all_time += db[key][test]
                    except KeyError:
                        LOG.info("You must update the database time tests. "\
                                 "There is no time for %s" % test)

            LOG.info("\nExpected time to complete all the tests: %s\n" %
                     self.seconds_to_time(self.all_time))

        for key in test_dict.keys():
            if self.event.is_set():
                LOG.info("Catch Keyboard interrupt. No more tests will be launched")
                break
            if self.config.get('times', 'update') == 'True':
                elapsed_time_by_group[key] = 0
                f = open(os.path.join(os.path.dirname(__file__),
                         'times.json'), 'r')
                db = json.loads(f.read())
                f.close()

            dispatch_result[key] = {}
            try:
                spawn_point = os.path.dirname(__file__)
                path_to_runner = os.path.join(spawn_point, self.plugin_dir,
                                              key, "runner.py")
                m = imp.load_source("runner"+key, path_to_runner)
            except IOError as e:
                major_crash = 1
                LOG.debug("Looks like there is no such runner: " + key + ".")
                dispatch_result[key]['major_crash'] = 1
                LOG.error("The following exception has been caught: %s", e)
                self.failure_indicator = 12
            except Exception:
                major_crash = 1
                dispatch_result[key]['major_crash'] = 1
                LOG.error("Something went wrong. Please check mcvconsoler logs")
                LOG.debug(traceback.format_exc())
                self.failure_indicator = 12
            else:
                path = os.path.join(self.results_vault, key)
                os.mkdir(path)
                runner = getattr(m, self.config.get(key, 'runner'))(self.access_helper, path, config=self.config)
                batch = [x for x in (''.join(test_dict[key].split()).split(',')) if x]
                LOG.debug("Running " + str(len(batch)) + " test"+"s"*(len(batch)!=1) +  " for " + key)
                try:
                    run_failures = runner.run_batch(batch, compute="1",#self.access_helper.compute,
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
                        if self.failure_indicator == 0:
                            self.failure_indicator = runner.failure_indicator
                        else:
                            self.failure_indicator = 100
                except subprocess.CalledProcessError as e:
                    if e.returncode == 127:
                        LOG.debug("It looks like you are trying to use a wrong "
                                  "runner. No tests will be run in this group "
                                  "this time. Reply %s", e)
                    raise e
                except Exception as e:
                    run_failures = test_dict[key].split(',')
                    self.failure_indicator = 11
                    raise e
                else:
                    dispatch_result[key]['results'] = run_failures
                    dispatch_result[key]['batch'] = batch


        return dispatch_result

    def do_full(self):
        """Run full test suit"""
        LOG.info("Starting full check run.")
        LOG.warning("WARNING! Full test suite contains Rally load tests. These tests may break your cloud. It is not recommended to run these tests on production clouds.")
        if self.config.get('rally', 'rally_load') != 'True':
            LOG.info("WARNING!Full test suite contains Rally load tests. These tests may "
                     "break your cloud. So, please set rally_load=True manually in mcv.conf ")
            return {}
        test_dict = self.discover_test_suits()
        return self.dispatch_tests_to_runners(test_dict)

    def describe_results(self, results):
        """Pretty printer for results"""
        LOG.info('\n')
        LOG.info("-"*40)
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

    def update_config(self, results):
        sent = False
        for key in results.iterkeys():
            to_rerun = ",".join(results[key]["results"]["test_failures"])
            if to_rerun != "":
                LOG.debug("Adding option %(key)s=%(trr)s" % {"key": key,
                                                             "trr": to_rerun})
                if not self.config.has_section("custom_test_group_failed"):
                    LOG.debug("Looks like there is no section 'custom_test_group_failed' in %s. Adding one." % self.path_to_config)
                    self.config.add_section("custom_test_group_failed")
                self.config.set("custom_test_group_failed", key, to_rerun)
                sent = True
            else:
                if self.config.has_section("custom_test_group_failed") and\
                        self.config.has_option("custom_test_group_failed", key):
                    LOG.debug("Removing %s from custom_test_group_failed" % key)
                    self.config.remove_option("custom_test_group_failed", key)
                    sent = True
        if self.config.has_section("custom_test_group_failed") and\
                self.config.options("custom_test_group_failed") == []:
            LOG.debug("Removing section 'custom_test_group_failed' since it is empty")
            self.config.remove_section("custom_test_group_failed")
            sent = True
        if sent:
            LOG.debug("Apparently config has changed. Writing changes down")
            with open(self.path_to_config, "w") as cf:
                self.config.write(cf)

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

    def check_args_run(self, to_check):
    # TODO: make a proper dispatcher for this stuff
        retval = []
        if to_check[0] == 'full' or to_check[0] == 'short':
            pass
        elif to_check[0] == 'custom': #and len(to_check) >= 2:
            if len(to_check) < 2:
                to_check.append("default")
            if len(to_check) > 2:
                LOG.warning("Ignoring arguments: " + ", ".join(to_check[2:]))
            results = self.prepare_tests(to_check[1])
            if results == {}:
                LOG.error("Can't find group '" + to_check[1] + "' in"+ self.path_to_config+ "Please, provide exisitng group name!")
                sys.exit(1)
            for key in results:
                if key in ['rally', 'ostf', 'shaker', 'resources'] and key not in retval:
                    retval.append(key)
        elif to_check[0] == 'single':
            if len(to_check) < 3:

                LOG.error("Too few arguments for option single. You must "
                          "specify test type and test name")
                sys.exit(1)
            if len(to_check) > 3:
                LOG.warning( "Ignoring arguments: "+ ", ".join(to_check[3:]))
            if not self.existing_plugin(to_check[1]):
                LOG.error("Unrecognized test group: "+ to_check[1])

                sys.exit(1)
            if not self.a_real_file(to_check[2], to_check[1]):
                LOG.error("Test not found: " + to_check[2])
                sys.exit(1)
            retval = [to_check[1]]
        else:
            LOG.error("Wrong option: " + to_check[0] + ". Please run mcvconsoler --help if unsure what has gone wrong")
            sys.exit(1)
        return retval

    def console_user(self, event, result):
        # TODO: split this god's abomination.
        self.event = event
        def do_finalization(run_results):
            r_helper = {"timestamp" : "xxx", "location": "xxx"}
            if run_results is not None:
                self.describe_results(run_results)
                self.update_config(run_results)
                try:
                    reporter.brew_a_report(run_results, self.results_vault+ "/index.html")
                except:
                    LOG.warning("Brewing a report has failed.")
                    return r_helper
                r_helper = {"timestamp": str(datetime.datetime.utcnow()).replace(" ", "_"),
                            "location": self.results_vault}
                cmd = "tar -zcf /tmp/mcv_run_%(timestamp)s.tar.gz -C %(location)s ." % r_helper
                p = subprocess.check_output(
                        cmd, shell=True, stderr=subprocess.STDOUT,
                        preexec_fn=utils.ignore_sigint)
                cmd = "rm -rf %(location)s" % {"location": self.results_vault}
                p = subprocess.check_output(
                        cmd, shell=True, stderr=subprocess.STDOUT,
                        preexec_fn=utils.ignore_sigint)
                LOG.debug("Done with report generation.")
            else:
                LOG.warning("For some reason test tools have returned nothing.")
            return r_helper

        if len(sys.argv) < 2:
            self.parser.print_help()
            sys.exit(1)
        run_results = None

        # TODO: leaving this leftover for now. In the nearest future this
        # should be forwarded to the real logging.
        path_to_main_log = os.path.join(self.config.get('basic', 'logdir'),
                                        self.config.get('basic', 'logfile'))
        if self.args.run is not None:
            required_containers = self.check_args_run(self.args.run)
            self.access_helper = accessor.AccessSteward(self.config)
            res = self.access_helper.check_and_fix_environment(
                required_containers, self.args.no_tunneling)
            if not res:
                result.append(14)
                return

            try:
                run_results = getattr(self, "do_" + self.args.run[0])(*self.args.run[1:])
            except TypeError as e:
                run_name = "do_" + self.args.run[0]
                expected_arglist = inspect.getargspec(getattr(self, run_name)).args
                scolding = {"supplied_args": ", ".join(self.args.run[1:]),
                            "function" : self.args.run[0],
                            "expected_args": "\', \'".join(expected_arglist),
                            "error": e}
                temessage = "Somehow \'%(supplied_args)s\' is not enough for "\
                            "\'%(function)s\'\n\'%(function)s\' actually expects the "\
                            "folowing arguments: \'%(expected_args)s\' Reply: \'%(error)s\'"
                LOG.error(temessage % scolding)
            except ValueError as e:
                LOG.error("Some unexpected outer error has terminated the tool."
                          " Please try rerunning mcvconsoler. Reply: %s", e)
                self.failure_indicator = 13
            except Exception:
                LOG.error("Something went wrong with the command, please refer to logs to find out what")
                LOG.debug(traceback.format_exc())
                self.failure_indicator = 13
        elif self.args.test is not None:
            arguments = ' '.join(i for i in self.args.test)
            subprocess.call(
                    '/opt/mcv-consoler/tests/tmux_mcv_tests_runner.sh "({0})"'.format(arguments),
                    shell=True, preexec_fn=utils.ignore_sigint)
            return 1
        r_helper = do_finalization(run_results)
        self.access_helper.stop_forwarding()
        captain_logs = os.path.join(self.config.get("basic", "logdir"),
                                    self.config.get("basic", "logfile"))
        result.append(self.failure_indicator)
        if run_results is not None:
            LOG.info("One page report could be found in /tmp/mcv_run_%s.tar.gz" % r_helper)
