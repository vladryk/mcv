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
import os
import traceback
from collections import namedtuple
from datetime import datetime

import mcv_consoler.common.config as app_conf
import mcv_consoler.plugins.runner as run
from mcv_consoler.common import clients as Clients
from mcv_consoler.common.errors import NWSpeedError
from mcv_consoler.plugins.nwspeed import speed_tester as st
from mcv_consoler.utils import GET
from mcv_consoler import exceptions

LOG = logging.getLogger(__name__)


Node = namedtuple('Node', ('fqdn', 'ip'))


class NWSpeedTestRunner(run.Runner):
    failure_indicator = NWSpeedError.NO_RUNNER_ERROR
    identity = 'nwspeed'
    config_section = 'nwspeed'

    def __init__(self, ctx):
        super(NWSpeedTestRunner, self).__init__(ctx)

        self.access_data = self.ctx.access_data
        self.config = self.ctx.config
        self.path = self.ctx.work_dir
        self.test_failures = []
        self.hw_nodes = []
        self.av_speed = 0

    def _evaluate_task_results(self, task_results):
        # We need to check 2 things:
        # 1. Average network speed from all nodes should be under threshold
        # 2. Each speed value should be higher than
        #    value from 1 point * range in percents (see MCV-288 description)
        res = True
        threshold = GET(self.config, 'threshold', 'nwspeed', 100, float)
        LOG.info('Threshold is %s MB/s' % threshold)
        if self.av_speed < threshold:
            res = False
            LOG.warning('Average network speed is under threshold')
            self.failure_indicator = NWSpeedError.LOW_AVG_SPEED
            return res
        percent_range = GET(self.config, 'range', 'nwspeed', 10, float)
        LOG.info('Threshold range is %s percents from average' % percent_range)
        range_speed = self.av_speed - (self.av_speed * (percent_range / 100.0))
        for speed in task_results:
            if speed < range_speed:
                res = False
                LOG.warning('One of speed test results is under the threshold')
                self.failure_indicator = NWSpeedError.LOW_NODE_SPEED
                break
        return res

    # TODO(ogrytsenko): this method is a copy/paste from another commit
    # gerrit:61573. When it is merged to master - be sure to remove this
    @staticmethod
    def _filter_nodes_by_status(nodes, status):
        for node in nodes:
            if node['status'] == status:
                yield node
            else:
                msg = 'Node \'%s\' has status: %s. Skipped from test'
                LOG.warning(msg, node['fqdn'], node['status'])

    def _prepare_nodes(self):
        cluster_id = GET(self.config, 'cluster_id', 'fuel', convert=int)
        fuel = Clients.get_fuel_client({})
        all_nodes = fuel.node.get_all(environment_id=cluster_id)
        LOG.debug('Discovered %s nodes', len(all_nodes))

        mgmt_net = app_conf.FUEL_MANAGEMENT_NETWORK_NAME
        res = list()
        for node in self._filter_nodes_by_status(all_nodes, 'ready'):
            mgmt_ip = fuel.get_node_address(node, network=mgmt_net)
            res.append(Node(node['fqdn'], mgmt_ip))

        limit = GET(self.config, 'nodes_limit', 'nwspeed', None, int)
        if limit is None:
            return res
        res = sorted(res)[:limit]
        LOG.debug('Node limit is %s', limit)
        LOG.debug('Following nodes were selected for tests: %s', res)
        return res

    def run_batch(self, tasks, *args, **kwargs):

        tasks, missing = self.discovery.match(tasks)
        self.test_not_found.extend(missing)

        self.hw_nodes = self._prepare_nodes()
        return super(NWSpeedTestRunner, self).run_batch(tasks, *args, **kwargs)

    def generate_report(self, html, task):
        html_file = '%s.html' % task
        html_path = os.path.join(self.path, html_file)
        LOG.debug('Generating report in %s file', html_file)
        with open(html_path, 'w') as report:
            report.write(html)

    def run_individual_task(self, task, *args, **kwargs):
        LOG.debug('Start generating %s' % task)
        runner_obj = None
        try:
            runner_cls = getattr(st, task)
            runner_obj = runner_cls(self.config, self.hw_nodes)
            runner_obj.init_ssh_conns()
        except AttributeError:
            LOG.error('Incorrect task: %s', task)
            self.test_not_found.append(task)
            return False
        except exceptions.AccessError as e:
            LOG.error(e.message)
            LOG.debug(traceback.format_exc())
            self.test_failures.append(task)
            if runner_obj:
                runner_obj.cleanup()
            return False

        report_all = ("<!DOCTYPE html>\n"
                   "<html lang=\"en\">\n"
                   "<head>\n"
                   "    <meta charset=\"UTF-8\">\n"
                   "    <title></title>\n"
                   "</head>\n"
                   "<body>\n")

        average_all = []

        time_start = datetime.utcnow()
        LOG.info("\nTime start: %s UTC\n", time_start)

        try:
            for node in self.hw_nodes:
                LOG.info("Measuring network speed on node %s" % node.fqdn)
                res = runner_obj.measure_speed(node)
                report, average = runner_obj.generate_report(node, res)
                average_all.append(average)
                report_all += report
        except Exception:
            LOG.error('Failed to measure speed, caught unexpected error. '
                      'Please check mcvconsoler logs', exc_info=1)
            self.test_failures.append(task)
            return False
        finally:
            runner_obj.cleanup()

        time_end = datetime.utcnow()
        LOG.info("Time end: %s UTC" % str(time_end))
        time_of_tests = (time_end - time_start).seconds
        self.time_of_tests[task] = {'duration': str(time_of_tests) + 's'}

        self.av_speed = round(sum(average_all) / len(average_all), 2)
        report_all += '<br><h4> Overall average results - {} MB/s '.format(
            self.av_speed)

        report_all += "</body>\n</html>"
        self.generate_report(report_all, task)
        if self._evaluate_task_results(average_all):
            return True
        else:
            self.test_failures.append(task)
            return False
