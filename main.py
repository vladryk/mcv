import argparse
import ConfigParser
import logging
import logger as LOG
import imp
import os
import sys


def prepare_tests(test_group):
    section  = "custom_test_group_" + test_group
    restmp = config.options(section)

    out =  dict([(opt, config.get(section, opt)) for opt in
                config.options(section)])
    return out


def do_custom(test_group='default'):
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
    tests_to_run = prepare_tests(test_group)
    # tests_to_run is a dictionary that looks like this:
    # {'rally':'test1,test2,test3', 'ostf':'test1,test2', 'wtf':'test8'}
    return dispatch_tests_to_runners(tests_to_run)


def do_short():
    """Run the most essential tests.
    """
    # [custom_test_group_short]
    return do_custom("short")


def do_single(test_group, test_name):
    """Run specific test.

    The test must be specified as this: testool/tests/tesname
    """
    the_one = dict(((test_group, test_name),))
    return dispatch_tests_to_runners(the_one)

def discover_test_suits():
    """Discovers tests in default location.
    """
    # TODO: generalize discovery
    config.get('basic', 'scenario_dir')
    scenario_dir = os.path.join(os.path.dirname(__file__), "test_scenarios")
    possible_places = map(lambda x: os.path.join(scenario_dir, x),
                          os.listdir(scenario_dir))
    per_component = [(x.split('/')[-1],  os.listdir(os.path.join(x, "tests")))
                     for x in filter(lambda x: os.path.isdir(x),
                                     possible_places)]
    per_component = dict(per_component)
    for k, v in per_component.iteritems():
        per_component[k] = ",".join(v)
    return dict(per_component)


def dispatch_tests_to_runners(test_dict):
    dispatch_result = {}
    for key in test_dict.keys():
        dispatch_result[key] = {}
        try:
            spawn_point = os.path.dirname(__file__)
            path_to_runner = os.path.join(spawn_point, "test_scenarios",
                                          key, "runner.py")
            m = imp.load_source("runner"+key, path_to_runner)
        except Exception as e:
            major_crash = 1
            dispatch_result[key]['major_crash'] = 1
            logger.exception("The following exception has been caught: %s" % e)
        else:
            runner = getattr(m, config.get(key, 'runner'))()
            batch = test_dict[key].split(',')
            try:
                run_failures = runner.run_batch(batch)
            except Exception as e:
                run_failures = test_dict[key].split(',')
                raise e
            dispatch_result[key]['failures_number'] = len(run_failures)
            dispatch_result[key]['test_number'] = len(batch)
    return dispatch_result


def do_full():
    """Run full test suit.
    """
    LOG.log_starting_full_check()
    test_dict = discover_test_suits()
    return dispatch_tests_to_runners(test_dict)

def describe_results(results):
    """Pretty printer for results.
    """
    issues = None
    for key, result in results.iteritems():
        if result.get('major_crash', None) is not None:
            issues = 1
            print key, '\t:\t', "something went horribly wrong"
            continue
        elif result['failures_number'] != 0:
            issues = 1
            print key, '\t:\t', result['failures_number'], "of",\
                result["test_number"], "have failed."
        else:
            print key, '\t:\t', "all tests are fine."
    captain_logs = os.path.join(config.get("basic", "logdir"),
                                config.get("basic", "logfile"))
    if issues:
        print "Please refer to", captain_logs,\
            "to find what exactly has gone awry."
    else:
        print "Run logs could be found in", captain_logs,\
            "if you wish to see them."



# hooking up a config
config = ConfigParser.ConfigParser()
default_config_file = "etc/mcv.conf"

# processing command line arguments.
parser = argparse.ArgumentParser(
    prog="mcvconsoler",
    description="""Central point of control for cloud validation -- one tool
    to rule them all.""",
    epilog="""...and in the darkness bind them, in the cloud where the
    instances lie.""",)

parser.add_argument(
    "--run",
    nargs = '+',
    help="""Run one of specified test suits : full, custom, single or
    short.""")

parser.add_argument(
    "--config",
    help="""Provide custom config file instead of the default one""")

args = parser.parse_args()

# setting up nice logging
__ = '%(asctime)s %(levelname)s %(message)s'
logger = logging.getLogger(__name__)

def main():
    if args.config  is not None:
        default_config = args.config
    else:
        default_config = default_config_file
    config.read(default_config)
    logging.basicConfig(level=getattr(logging,
                                      config.get('basic', 'loglevel').upper()),
                        filename=os.path.join(config.get('basic', 'logdir'),
                                              config.get('basic', 'logfile')),
                        format=__)
    if args.run is not None:
        try:
            run_results = globals()["do_" + args.run[0]](*args.run[1:])
        except Exception as e:
            print "Something went wrong with the command, please"\
                  " refer to logs to find out what"
            LOG.log_exception(e)
            return
    describe_results(run_results)


if __name__ == "__main__":
    main()
