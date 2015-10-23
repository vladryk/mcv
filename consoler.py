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
import argparse
import datetime
import inspect
import ConfigParser
import logging
import imp
import reporter
import subprocess
import os
import sys


LOG = logging


class Consoler(object):
    """Consoles poor user when her stack is not working as expected"""

    def __init__(self, parser, args):
        self.config = ConfigParser.ConfigParser()
        self.default_config_file = "/etc/mcv/mcv.conf"
        self.parser = parser
        self.args = args
        self.plugin_dir = "test_scenarios"
        pass

    def prepare_tests(self, test_group):
        section  = "custom_test_group_" + test_group
        try:
            restmp = self.config.options(section)
        except ConfigParser.NoSectionError:
            return {}

        out =  dict([(opt, self.config.get(section, opt)) for opt in
                    self.config.options(section)])
        return out

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
            print "The following amount of tests is requested per available tools:"
            for group, test_list in tests.iteritems():
                print group, '\t:\t', len(test_list.split(','))
            print

        if test_group == 'default':
            LOG.info("Either no group has been explicitly requested or it was group 'default'.")

        # NOTE: this cludge is used to prevent accidental production cloud
        # destruction and relies solely on group name. It is not bulletproof as
        # anyone could create loading group with a wrong name and easily break
        # everything up.
        if test_group.find('load') != -1:
            if self.config.get('rally', 'rally_load') != 'True':
                print "WARNING! Load test suit contains rally load tests. These tests may"
                print "break your cloud. So, please set rally_load=True manually in mcv.conf "
                return None
        tests_to_run = self.prepare_tests(test_group)
        if tests_to_run is None:
            return None
        # tests_to_run is a dictionary that looks like this:
        # {'rally':'test1,test2,test3', 'ostf':'test1,test2', 'wtf':'test8'}
        pretty_print_tests(tests_to_run)
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

    def dispatch_tests_to_runners(self, test_dict, *args, **kwargs):
        dispatch_result = {}
        self.results_vault = "/tmp/mcv_run_" + str(datetime.datetime.utcnow()).replace(" ","_")
        os.mkdir(self.results_vault)
        for key in test_dict.keys():
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
                LOG.error("The following exception has been caught: ", exc_info=True)
            except Exception as e:
                major_crash = 1
                dispatch_result[key]['major_crash'] = 1
                LOG.error("The following exception has been caught: ", exc_info=True)
            else:
                path = os.path.join(self.results_vault, key)
                os.mkdir(path)
                runner = getattr(m, self.config.get(key, 'runner'))(self.access_helper, path, config=self.config)
                batch = test_dict[key].split(',')
                batch = map(lambda x: x.strip('\n'), batch)
                LOG.debug("Running " + str(len(batch)) + " test"+"s"*(len(batch)!=1) +  " for " + key)
                try:
                    run_failures = runner.run_batch(batch, compute="1",#self.access_helper.compute,
                                                    concurrency=self.config.get('basic', 'concurrency'),
                                                    gre_enabled=self.config.get('basic', "gre_enabled"),
                                                    vlan_amount=self.config.get('basic', "vlan_amount"))
                except subprocess.CalledProcessError as e:
                    if e.returncode == 127:
                        LOG.debug("It looks like you are trying to use a wrong "\
                              "runner. No tests will be run in this group "\
                              "this time.", exc_info=True)
                    raise e
                except Exception as e:
                    run_failures = test_dict[key].split(',')
                    raise e
                dispatch_result[key]['results'] = run_failures
                dispatch_result[key]['batch'] = batch
        return dispatch_result

    def do_full(self):
        """Run full test suit"""
        LOG.info("Starting full check run.")
        LOG.warning("WARNING! Full test suite contains Rally load tests. These tests may break your cloud. It is not recommended to run these tests on production clouds.")
        if self.config.get('rally', 'rally_load') != 'True':
            print "WARNING!Full test suite contains Rally load tests. These tests may"
            print "break your cloud. So, please set rally_load=True manually in mcv.conf "
            return {}
        test_dict = self.discover_test_suits()
        return self.dispatch_tests_to_runners(test_dict)

    def describe_results(self, results):
        """Pretty printer for results"""
        print
        print "-"*40
        print "The run resulted in:"
        for key in results.iterkeys():
            print "For", key, ":",
            if results[key].get('major_crash', None) is not None:
                print "A major tool failure has been detected"
                continue
            print
            print len(results[key]['results']['test_success']),
            print "\t\t successful tests"
            print len(results[key]['results']['test_failures']),
            print "\t\t failed tests"

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

                LOG.error( "Too few arguments for option single. You must specify test group and test name")
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

    def console_user(self):
        # TODO: split this god's abomination.
        def do_finalization(run_results):
            r_helper = {"timestamp" : "xxx", "location": "xxx"}
            if run_results is not None:
                self.describe_results(run_results)
                try:
                    reporter.brew_a_report(run_results, self.results_vault+ "/index.html")
                except:
                    LOG.warning("Brewing a report has failed. Probably the tooldoes not support html reports generation")
                    return r_helper
                r_helper = {"timestamp": str(datetime.datetime.utcnow()).replace(" ", "_"),
                            "location": self.results_vault}
                cmd = "tar -zcf /tmp/mcv_run_%(timestamp)s.tar.gz -C %(location)s ." % r_helper
                p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                cmd = "rm -rf %(location)s" % {"location": self.results_vault}
                p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                LOG.debug("Done with report generation.")
            else:
                LOG.warning("For some reason test tools have returned nothing.")
            return r_helper

        if len(sys.argv) < 2:
            self.parser.print_help()
            sys.exit(1)
        run_results = None
        if self.args.config  is not None:
            default_config = self.args.config
        else:
            default_config = self.default_config_file
        self.path_to_config = os.path.join(os.path.dirname(__file__),
                                           default_config)
        self.config.read(self.path_to_config)
        # TODO: leaving this leftover for now. In the nearest future this
        # should be forwarded to the real logging.
        path_to_main_log = os.path.join(self.config.get('basic', 'logdir'),
                                        self.config.get('basic', 'logfile'))
        if self.args.run is not None:
            required_containers = self.check_args_run(self.args.run)
            self.access_helper = accessor.AccessSteward(self.config)
            self.access_helper.check_and_fix_environment(required_containers, self.args.no_tunneling)
            try:
                run_results = getattr(self, "do_" + self.args.run[0])(*self.args.run[1:])
            except TypeError as e:
                run_name = "do_" + self.args.run[0]
                expected_arglist = inspect.getargspec(getattr(self, run_name)).args
                scolding = {"supplied_args": ", ".join(self.args.run[1:]),
                            "function" : self.args.run[0],
                            "expected_args": "\', \'".join(expected_arglist)}
                temessage = "Somehow \'%(supplied_args)s\' is not enough for "\
                    "\'%(function)s\'\n\'%(function)s\' actually expects the "\
                    "folowing arguments: \'%(expected_args)s\'"
                LOG.error(temessage % scolding, exc_info=True)
            except ValueError as e:
                LOG.error("Some unexpected outer errojr has terminated the tool. Please try rerunning mcvconsoler")
            except Exception as e:
                print "Something went wrong with the command, please"\
                      " refer to logs to find out what"
                LOG.error("The following error has terminated the consoler:", exc_info=True)
        r_helper = do_finalization(run_results)
        self.access_helper.stop_forwarding()
        captain_logs = os.path.join(self.config.get("basic", "logdir"),
                                    self.config.get("basic", "logfile"))
        print
        print "-"*40
        if run_results is not None:
            print "One page report could be found in /tmp/mcv_run_%(timestamp)s.tar.gz" % r_helper
        print "For extra details and possible insights please refer to",
        print captain_logs
        print
        if self.get_total_failures(run_results or {}) != 0:
            return self.config.getint('basic', 'failure_indicator')
        else:
            return 0
