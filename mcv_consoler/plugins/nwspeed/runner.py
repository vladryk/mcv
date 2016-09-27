#    Copyright 2015-2016 Mirantis, Inc
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
from jinja2 import Environment
from jinja2 import PackageLoader
from oslo_config import cfg

from mcv_consoler.common import config as app_conf
from mcv_consoler.common.errors import NWSpeedError
from mcv_consoler import exceptions
from mcv_consoler.plugins.nwspeed import speed_tester as st
from mcv_consoler.plugins import runner as run

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
        self.nodes = list()
        self.controllers = list()
        self.attempts = CONF.nwspeed.attempts
        self.thr = CONF.nwspeed.threshold
        self.pr = CONF.nwspeed.range

    def _prepare_nodes(self):
        # see https://mirantis.jira.com/browse/MCV-228 for mode details

        cluster_id = CONF.fuel.cluster_id
        fuel = self.ctx.access.fuel

        all_nodes = fuel.node.get_all(environment_id=cluster_id)
        all_nodes = fuel.filter_nodes_by_status(all_nodes)
        LOG.debug('Discovered %s nodes', len(all_nodes))

        roles = CONF.nwspeed.roles
        if roles is not None:
            LOG.debug('Filtering nodes by role: %s', ', '.join(roles))
            all_nodes = fuel.filter_nodes_by_role(all_nodes, *roles)
            LOG.debug('%s nodes were filtered by role %s',
                      len(all_nodes), roles)

        res = list()
        for node in all_nodes:
            admin_ip = fuel.get_node_address(
                node, network=app_conf.FUEL_ADMIN_NETWORK_NAME)
            roles = tuple(node['roles'])
            res.append(Node(node['id'], node['fqdn'], roles, admin_ip))
        res.sort(key=lambda x: x.id)

        # FIXME(ogrytsenko): role 'controller' is hardcoded
        # Although it does exactly what was asked in task #MCV-228, it
        # still makes sense to move this to an 'mcv.conf'
        is_controller = lambda n: n.roles.__contains__('controller')
        self.controllers = filter(is_controller, res)
        LOG.debug('Discovered %s controllers', len(self.controllers))

        ctr_limit = CONF.nwspeed.controllers_limit
        if ctr_limit is not None:
            LOG.debug('Controllers limit is %s', ctr_limit)
            self.controllers = self.controllers[:ctr_limit]
        LOG.debug('Following controllers nodes were selected for test: %s',
                  self.controllers)

        node_limit = CONF.nwspeed.nodes_limit
        if node_limit is not None:
            LOG.debug('Node limit is %s', node_limit)
            self.nodes = res[:node_limit]
        else:
            self.nodes = res
        LOG.debug('Following nodes were selected for tests: %s', self.nodes)

    def run_batch(self, tasks, *args, **kwargs):
        tasks, missing = self.discovery.match(tasks)
        self.test_not_found.extend(missing)
        self._prepare_nodes()
        return super(NWSpeedTestRunner, self).run_batch(tasks, *args, **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
        time_start = datetime.utcnow()
        LOG.info("\nTime start: %s UTC\n", time_start)
        LOG.debug('Start generating %s', task)

        runner_obj = None
        try:
            runner_cls = getattr(st, task)
            runner_obj = runner_cls(self.ctx, self.controllers, self.nodes)
            runner_obj.init_ssh_conns()
        except AttributeError as e:
            LOG.debug('Error: %s', e.message, exc_info=True)
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
            for controller in self.controllers:
                LOG.info("Measuring network speed on node: %s",
                         controller.fqdn)
                res = runner_obj.measure_speed(controller, self.attempts)
                raw_results[controller] = res
        except Exception:
            LOG.error('Failed to measure speed, caught unexpected error. '
                      'Please check mcvconsoler logs', exc_info=True)
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
        all_nodes = set(self.nodes) | set(self.controllers)
        for node in all_nodes:
            nodes[node.fqdn] = dict(node._asdict())

        from_nodes, to_nodes = set(), set()

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
                    'success': avg >= self.thr and None not in attempts
                })
                tmp.append(avg)
                to_nodes.add(to_node)
            from_nodes.add(from_node.fqdn)
            node_avg = len(tmp) and ro(sum(tmp) / len(tmp))
            nodes[from_node.fqdn]['avg_speed'] = node_avg
        avg = len(tests) and ro(sum(map(lambda s: s['avg'],
                                        tests)) / len(tests))

        result_dict = {
            'nodes': nodes,
            'tests': tests,
            'from_nodes': list(from_nodes),
            'to_nodes': list(to_nodes),
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
        for node in self.controllers:
            node_avg = results_dict['nodes'][node.fqdn].get('avg_speed')
            if node_avg is None:
                continue
            if node_avg < th_range:
                LOG.warn(warn_msg, node.fqdn, node_avg)
                ret_code = NWSpeedError.LOW_NODE_SPEED
            else:
                LOG.debug(msg, node.fqdn, node_avg)
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
