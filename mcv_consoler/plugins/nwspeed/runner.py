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

import datetime
import traceback

from mcv_consoler.common import clients as Clients
from mcv_consoler.common.errors import NWSpeedError
from mcv_consoler.logger import LOG
import mcv_consoler.plugins.runner as run
from mcv_consoler.plugins.nwspeed import speed_tester as st
from mcv_consoler.utils import GET

LOG = LOG.getLogger(__name__)


class NWSpeedTestRunner(run.Runner):
    def __init__(self, access_data, path, *args, **kwargs):
        self.access_data = access_data
        self.identity = "nwspeed"
        self.config_section = "nwspeed"
        self.config = kwargs.get('config')
        self.test_failures = []
        self.path = path
        super(NWSpeedTestRunner, self).__init__()
        self.failure_indicator = NWSpeedError.NO_RUNNER_ERROR
        self.hw_nodes = []
        self.home = '/mcv'
        self.av_speed = 0

    def _evaluate_task_results(self, task_results):
        # We need to check 2 things:
        # 1. Average network speed from all nodes should be under threshold
        # 2. Each speed value should be higher than
        #    value from 1 point * range in percents (see MCV-288 description)
        res = True
        threshold = float(GET(self.config, 'threshold', 'nwspeed', 100))
        LOG.info('Threshold is %s MB/s' % threshold)
        if self.av_speed < threshold:
            res = False
            LOG.warning('Average network speed is under threshold')
            self.failure_indicator = NWSpeedError.LOW_AVG_SPEED
            return res
        percent_range = float(GET(self.config, 'range', 'nwspeed', 10))
        LOG.info('Threshold range is %s percents from average' % percent_range)
        range_speed = self.av_speed - (self.av_speed * (percent_range / 100.0))
        for speed in task_results:
            if speed < float(range_speed):
                res = False
                LOG.warning('One of speed test results is under the threshold')
                self.failure_indicator = NWSpeedError.LOW_NODE_SPEED
                break
        return res

    def _prepare_nodes(self):
        # Preparing HW node list. Using set for removing duplicates
        nova = Clients.get_nova_client(self.access_data)
        hw_nodes = {host.host_name for host in nova.hosts.list()}
        all_nodes = list(hw_nodes)
        LOG.debug('Discovered %s nodes' % len(all_nodes))

        nodes_limit = GET(self.config, 'nodes_limit', 'nwspeed', None)
        if nodes_limit is None:
            LOG.debug('Tests will be run on all nodes')
            return all_nodes

        limit = int(nodes_limit)
        nodes = all_nodes[:limit]
        LOG.debug('Node limit is %s' % limit)
        LOG.debug('Following nodes were selected for tests: %s' % nodes)
        return nodes

    def run_batch(self, tasks, *args, **kwargs):

        tasks, missing = self.discovery.match(tasks)
        self.test_not_found.extend(missing)

        try:
            self.hw_nodes = self._prepare_nodes()
            res = super(NWSpeedTestRunner, self).run_batch(tasks,
                                                           *args,
                                                           **kwargs)
            return res
        except Exception:
            LOG.error('Caught unexpected error, exiting. '
                      'Please check mcvconsoler logs')
            LOG.debug(traceback.format_exc())
            return False

    def generate_report(self, html, task):
        LOG.debug('Generating report in speed.html file')
        report = file('%s/%s.html' % (self.path, task), 'w')
        report.write(html)
        report.close()

    def run_individual_task(self, task, *args, **kwargs):
        # runs a set of commands
        if self.hw_nodes is None:
            LOG.error('Failed to measure speed - no HW nodes found')
            self.test_failures.append(task)
            return False
        LOG.debug('Start generating %s' % task)
        try:
            speed_class = getattr(st, task)
        except AttributeError:
            LOG.error('Incorrect task: %s' % task)
            self.test_not_found.append(task)
            return False
        try:
            reporter = speed_class(self.access_data, *args, **kwargs)
        except Exception:
            LOG.error('Error creating class %s. Please check mcvconsoler logs '
                      'for more info' % task)
            LOG.debug(traceback.format_exc())
            self.test_failures.append(task)
            return False

        res_all = ("<!DOCTYPE html>\n"
                   "<html lang=\"en\">\n"
                   "<head>\n"
                   "    <meta charset=\"UTF-8\">\n"
                   "    <title></title>\n"
                   "</head>\n"
                   "<body>\n")

        average_all = []

        time_start = datetime.datetime.utcnow()
        LOG.info("\nTime start: %s UTC\n" % str(time_start))

        for hw_node in self.hw_nodes:
            LOG.info("Measuring network speed on node %s" % hw_node)
            try:
                target_nodes = self.hw_nodes[:]
                target_nodes.remove(hw_node)
                # Getting html report and node average speed
                res, average = reporter.measure_speed(hw_node, target_nodes)
                res_all += res
                average_all.append(average)
            except RuntimeError:
                LOG.error('Failed to measure speed')
                try:
                    reporter.cleanup()
                except Exception:
                    LOG.warning('Unexpected cleanup error. '
                                'Please check mcvconsoler logs')
                    LOG.debug(traceback.format_exc())
                self.test_failures.append(task)
                return False
            except Exception:
                LOG.error('Failed to measure speed, caught unexpected error. '
                          'Please check mcvconsoler logs')
                LOG.debug(traceback.format_exc())
                try:
                    reporter.cleanup()
                except Exception:
                    LOG.warning('Unexpected cleanup error. '
                                'Please check mcvconsoler logs')
                    LOG.debug(traceback.format_exc())
                self.test_failures.append(task)
                return False

        time_end = datetime.datetime.utcnow()
        LOG.info("Time end: %s UTC" % str(time_end))
        time_of_tests = str(round((time_end - time_start).total_seconds(), 3)) + 's'
        self.time_of_tests[task] = {'duration': time_of_tests}

        self.av_speed = round(sum(average_all) / len(average_all), 2)
        res_all += '<br><h4> Overall average results - {} MB/s '.format(
            self.av_speed)

        res_all += "</body>\n</html>"
        self.generate_report(res_all, task)
        if self._evaluate_task_results(average_all):
            return True
        else:
            self.test_failures.append(task)
            return False
