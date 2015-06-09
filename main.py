import accessor
import argparse
import inspect
import ConfigParser
import logging
import logger as LOG
import imp
import subprocess
import os
import sys


def prepare_tests(test_group):
    section  = "custom_test_group_" + test_group
    try:
        restmp = config.options(section)
    except ConfigParser.NoSectionError:
        print "Come on, seriously, there is no such section in the config you\'ve provided!"

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
    def pretty_print_tests(tests):
        print "The following amount of tests is requested per available tools:"
        for group, test_list in tests.iteritems():
            print group, '\t:\t', len(test_list.split(','))
        print

    if test_group == 'default':
        print "Either no group has been explicitly requested or it was group \'default\'."
    tests_to_run = prepare_tests(test_group)
    if tests_to_run is None:
        return None
    # tests_to_run is a dictionary that looks like this:
    # {'rally':'test1,test2,test3', 'ostf':'test1,test2', 'wtf':'test8'}
    pretty_print_tests(tests_to_run)
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
        except IOError as e:
            major_crash = 1
            print "Looks like there is no such runner:", key, ". Have you let someone borrow it?"
            dispatch_result[key]['major_crash'] = 1
            logger.exception("The following exception has been caught: %s" % e)
        except Exception as e:
            major_crash = 1
            dispatch_result[key]['major_crash'] = 1
            logger.exception("The following exception has been caught: %s" % e)
        else:
            runner = getattr(m, config.get(key, 'runner'))()
            batch = test_dict[key].split(',')
            print "Running", len(batch), "test"+"s"*(len(batch)!=1), "for", key 
            try:
                run_failures = runner.run_batch(batch)
            except subprocess.CalledProcessError as e:
                if e.returncode == 127:
                    print "It looks like you are trying to use a wrong runner. No tests will be run in this group this time."
                raise e
            except Exception as e:
                run_failures = test_dict[key].split(',')
                raise e
            dispatch_result[key]['results'] = run_failures
            dispatch_result[key]['batch'] = batch
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
    print
    print "-"*40
    print "The run resulted in:"
    for key in results.iterkeys():
        print "For", key, ":",
        if results[key].get('major_crash', None) is not None:
            print "A major tool failure has been detected"
            return
        print
        print len(results[key]['results']['test_success']), "\t\t successful tests"
        print len(results[key]['results']['test_failures']), "\t\t failed tests"
        print len(results[key]['results']['test_not_found']), "\t\t not found tests"

    return


# hooking up a config
config = ConfigParser.ConfigParser()
default_config_file = "/etc/mcv/mcv.conf"

# processing command line arguments.
parser = argparse.ArgumentParser(
    prog="mcvconsoler",
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Central point of control for cloud validation -- one tool
    to rule them all.""",
    epilog=r"""The following command gives an example of how tests could be run:

    # mcvconsoler --run custom short

    Default config could be found in <path-to-mcv>/etc/mcv.conf so you can try
    it out with the default config:

    # mcvconsoler --run custom short --config <path-to-mcv>/etc/mcv.conf

    Also it is recommended to run the tool as a superuser, running it as an
    ordinary user might cause unexpected errors in strange places for odd
    tools.

    ...and in the darkness bind them, in the cloud where the
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
    print
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    run_results = None
    if args.config  is not None:
        default_config = args.config
    else:
        default_config = default_config_file
    path_to_config = os.path.join(os.path.dirname(__file__), default_config)
    # TODO: add effin check for right since noone cares to make them o'kay in the first place
    config.read(path_to_config)
    path_to_main_log = os.path.join(config.get('basic', 'logdir'),
                                              config.get('basic', 'logfile'))
    # TODO: ditto
    logging.basicConfig(level=getattr(logging,
                                      config.get('basic', 'loglevel').upper()),
                        filename=path_to_main_log,
                        format=__)
    if args.run is not None:
        access_helper = accessor.AccessSteward()
        access_helper.check_and_fix_environment()
        try:
            run_results = globals()["do_" + args.run[0]](*args.run[1:])
        except TypeError as e:
            print  "Somehow \'" + ", ".join(args.run[1:]) + "\' is not enough for \'" + args.run[0] + "\'"
            print "\'"+args.run[0]+"\'", "actually expects the folowing arguments: \'" + "\', \'".join(inspect.getargspec(globals()["do_" + args.run[0]]).args) + "\'"
            LOG.log_exception(e)
        except Exception as e:
            print "Something went wrong with the command, please"\
                  " refer to logs to find out what"
            LOG.log_exception(e)
    if run_results is not None:
        describe_results(run_results)
    captain_logs = os.path.join(config.get("basic", "logdir"),
                                config.get("basic", "logfile"))
    print
    print "-"*40
    print "For extra details and possible insights please refer to", captain_logs, "or to per-component logs in", config.get("basic", "logdir")+"/mcv"
    print


if __name__ == "__main__":
    main()
