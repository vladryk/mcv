import logging

"""Here be thefunctions to run logging."""

logger = logging.getLogger(__name__)

def log_rejects(rejects):
    logger.warning("The following tasks have not been found: %s. Skipping "
                   "them" % ", ".join(rejects))

def log_fine(fines):
    logger.info("The following tests will be run: %s" % ", ".join(fines))

def log_big_test_problem(testgroup):
    logger.error("Looks like not a single test will be run for group %s"
                 % testgroup)

def log_running_task(task):
    logger.debug("Running task %s" % task)

def log_test_task_ok(task):
    logger.info("Task %s has completed successfully." % task)

def log_test_task_failure(task, result):
    logger.warning("Task %s has failed with the following error: %s" % (task, result))

def log_hi():
    logger.warning("Oh. Hi there!")

def log_starting_full_check():
    logger.info("Starting full test run")
