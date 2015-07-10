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


import logging

"""Here be thefunctions to run logging."""
# TODO: this starts looking ugly, should  be fixed whenever there is a
# a chance to do it.

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

def log_exception(e):
    logger.exception("Got the following exception: %s" % e)

def log_arbitrary(message):
    logger.debug(message)

def log_warning(message):
    logger.warning(message)
