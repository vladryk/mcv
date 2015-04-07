import ConfigParser
import os
import sys
import logger as LOG

# Base class for runners should be placed here.

nevermind = None

class Runner(object):

    def __init__(self):
        self.current_task = 1
        super(Runner, self).__init__()

    def _it_ends_well(self, scenario):
        raise NotImplementedError

    def scenario_is_fine(self, scenario):
        #I am totally usure if it is needed to check for file existence
        #as it is sort of a bad idea to expect that there is an issue in
        #a pre-build tool. however as we provide an end-user with ability
        #to change settings we may run into a typo in a config.
        #probably each line retrieved from a config should be checked for
        #sanity as typos manage to creep in and ruin everything. however
        #that is a daunting task so probably not every single line.
        # very basic test for scenario correctness. It is assumed that
        # scenarios shipped with the tool are okay and are working. However
        # a typo might crawl in and cause a malfunction.
        entry_point = os.path.dirname(__file__)  # should be modified
        where_is_wally = os.path.join(entry_point, self.identity,
                                      'tests', scenario)
        if os.path.exists(where_is_wally) and self._it_ends_well(scenario):
            return True
        return False

    def run_individual_task(self, task):
        """Runs a single task.

        This function has to be defined in a subclass!"""
        raise NotImplementedError

    def _prepare_output(self):
        print "Percent of %s tests run: " % self.identity,
        sys.stdout.write("  0%")
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()

    def _finalize_output(self):
        sys.stdout.write("\033[?25h\n\n")
        sys.stdout.flush()


    def _update_status(self):
        if self.total_checks != 0:
            current_percentage = str(self.current_task*100/self.total_checks)
        else:
            current_percentage = '--'
        try:
            sys.stdout.write('\b'*(len(current_percentage)+1))
            sys.stdout.write("%s%%" % current_percentage)
            sys.stdout.write("\033[?25l")
            sys.stdout.flush()
        except KeyboardInterrupt:
            print "\nInterrupted. Exiting"
        except Exception as e:
            print "\nUndefined exception", e
        self.current_task += 1

    def check_task_list(self, tasks):
        fine_to_run = filter(self.scenario_is_fine, tasks)
        rejected_tasks = [x for x in tasks if x not in fine_to_run]
        map(tasks.remove, rejected_tasks)
        LOG.log_fine(fine_to_run) if fine_to_run else \
             LOG.log_big_test_problem(self.identity)
        LOG.log_rejects(rejected_tasks) if rejected_tasks else nevermind

    def run_batch(self, tasks):
        """Runs a bunch of tasks."""
        self.check_task_list(tasks)
        self.total_checks = len(tasks)
        self._prepare_output()
        for task in tasks:
            self.run_individual_task(task)
            self._update_status()
        self._finalize_output()
        return self.test_failures

    def _evaluate_task_results(self, task_results):
        raise NotImplementedError

    def orient_self(self):
        self.directory = os.getcwd("");
