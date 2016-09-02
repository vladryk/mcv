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

from __future__ import division

import logging
import os
import traceback
from collections import namedtuple
from datetime import datetime
from functools import partial

from jinja2 import Environment, PackageLoader

from oslo_config import cfg

import mcv_consoler.common.config as app_conf
import mcv_consoler.plugins.runner as run
from mcv_consoler.common.errors import NWSpeedError
from mcv_consoler.plugins.nwspeed import speed_tester as st
from mcv_consoler import exceptions

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

Node = namedtuple('Node', ('id', 'fqdn', 'roles', 'ip'))


class NWSpeedTestRunner(run.Runner):
    failure_indicator = NWSpeedError.NO_RUNNER_ERROR
    identity = 'nwspeed'
    config_section = 'nwspeed'

    def __init__(self, ctx):
        super(NWSpeedTestRunner, self).__init__(ctx)
        self.ctx = ctx
        self.access_data = self.ctx.access_data
        self.path = self.ctx.work_dir.base_dir
        self.test_failures = []
        self.hw_nodes = []
        self.attempts = CONF.nwspeed.attempts
        self.thr = CONF.nwspeed.threshold
        self.pr = CONF.nwspeed.range

    def _prepare_nodes(self):
        cluster_id = CONF.fuel.cluster_id
        fuel = self.ctx.access.fuel
        all_nodes = fuel.node.get_all(environment_id=cluster_id)
        all_nodes = list(fuel.filter_nodes_by_status(all_nodes))
        LOG.debug('Discovered %s nodes', len(all_nodes))

        res = list()
        for node in all_nodes:
            mgmt_ip = fuel.get_node_address(
                node, network=app_conf.FUEL_MANAGEMENT_NETWORK_NAME)
            roles = tuple(node['roles'])
            res.append(Node(node['id'], node['fqdn'], roles, mgmt_ip))
        res.sort(key=lambda x: x.id)

        limit = CONF.nwspeed.nodes_limit
        if limit is None:
            return res

        res = res[:limit]
        LOG.debug('Node limit is %s', limit)
        LOG.debug('Following nodes were selected for tests: %s', res)
        return res

    def run_batch(self, tasks, *args, **kwargs):
        tasks, missing = self.discovery.match(tasks)
        self.test_not_found.extend(missing)

        self.hw_nodes = self._prepare_nodes()
        return super(NWSpeedTestRunner, self).run_batch(tasks, *args, **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
        time_start = datetime.utcnow()
        LOG.info("\nTime start: %s UTC\n", time_start)
        LOG.debug('Start generating %s', task)

        runner_obj = None
        try:
            runner_cls = getattr(st, task)
            runner_obj = runner_cls(self.ctx, self.hw_nodes)
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

        raw_results = dict()
        try:
            for node in self.hw_nodes:
                LOG.info("Measuring network speed on node %s" % node.fqdn)
                res = runner_obj.measure_speed(node, self.attempts)
                raw_results[node] = res
        except Exception:
            LOG.error('Failed to measure speed, caught unexpected error. '
                      'Please check mcvconsoler logs', exc_info=1)
            self.test_failures.append(task)
            return False
        finally:
            runner_obj.cleanup()
            time_end = datetime.utcnow()

        LOG.info("Time end: %s UTC", time_end)
        duration = (time_end - time_start).seconds
        self.time_of_tests[task] = {'duration': '{}s'.format(duration)}

        result_dict = self.process_results(raw_results)
        # store raw results
        self.dump_raw_results(task, result_dict)

        ret_val = self.validate_results(result_dict)
        self.generate_report(task, result_dict)

        if ret_val is not NWSpeedError.NO_ERROR:
            self.failure_indicator = ret_val
            self.test_failures.append(task)
            return False
        return True

    def process_results(self, raw_results):
        not_none = lambda i: i is not None
        ro = partial(round, ndigits=2)

        nodes = dict()
        for node in self.hw_nodes:
            nodes[node.fqdn] = dict(node._asdict())

        tests = list()
        for from_node, items in raw_results.iteritems():
            tmp = list()
            for to_node, attempts in items.iteritems():
                ff = filter(not_none, attempts)
                avg = len(ff) and ro(sum(ff) / len(ff))
                tests.append({
                    'from': from_node.fqdn,
                    'to': to_node,
                    'attempts': attempts,
                    'avg': avg,
                    'avg_gbs': ro(avg / 125),
                    'success': avg >= self.thr
                })
                tmp.append(avg)
            node_avg = len(tmp) and ro(sum(tmp) / len(tmp))
            nodes[from_node.fqdn]['avg_speed'] = node_avg
        avg = len(tests) and ro(sum(map(lambda s: s['avg'], tests))/len(tests))

        result_dict = {
            'nodes': nodes,
            'tests': tests,
            'total_avg': avg,
            'threshold': self.thr,
            'percent_range': self.pr,
        }
        return result_dict

    def validate_results(self, results_dict):
        LOG.info('Threshold is %s MB/s', self.thr)
        ret_code = NWSpeedError.NO_ERROR

        tolal_avg = results_dict['total_avg']
        LOG.info('Average network speed is %s MB/s', tolal_avg)
        if tolal_avg < self.thr:
            LOG.warning('Average network speed is under threshold')
            ret_code = NWSpeedError.LOW_AVG_SPEED

        th_range = tolal_avg - (self.pr * tolal_avg) / 100.0
        LOG.info('Threshold range is %s MB/s (%s%% lower than average)',
                 th_range, self.pr)

        msg = "Node '%s' average speed is %s MB/s"
        warn_msg = msg + ', less than threshold range'
        for fqdn, node in results_dict['nodes'].iteritems():
            node_avg = node['avg_speed']
            if node_avg < th_range:
                LOG.warn(warn_msg, fqdn, node_avg)
                ret_code = NWSpeedError.LOW_NODE_SPEED
            else:
                LOG.debug(msg, fqdn, node_avg)
        return ret_code

    def generate_report(self, task, result_dict):
        timestamp = datetime.utcnow().strftime('%h %d %H:%M')

        env = Environment(loader=PackageLoader('mcv_consoler', 'templates'))
        template = env.get_template('nwspeed_table.html')
        html = template.render(timestamp=timestamp, **result_dict)

        html_path = os.path.join(self.path, '%s.html' % task)
        LOG.debug('Generating report into file: %s', html_path)
        with open(html_path, 'w') as report:
            report.write(html)

