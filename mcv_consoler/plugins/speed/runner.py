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

import datetime
import itertools
import logging
import os.path
# TODO(albartash): replace with traceback2
import traceback

from flask_table import Table, Col
from jinja2 import Template
from oslo_config import cfg

from mcv_consoler import exceptions
from mcv_consoler.common import context
from mcv_consoler.common.errors import SpeedError
from mcv_consoler.plugins import runner
from mcv_consoler.plugins.speed import resources
from mcv_consoler.plugins.speed import speed_tester as st
from mcv_consoler import utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class ObjTable(Table):
    attempt = Col('ATTEMPT')
    node = Col('NODE')
    action = Col('ACTION')
    speed = Col('RESULT')


class BlockTable(Table):
    attempt = Col('ATTEMPT')
    type = Col('TYPE')
    size = Col('BLOCK SIZE')
    node = Col('NODE')
    action = Col('ACTION')
    result = Col('RESULT')


class SpeedTestRunner(runner.Runner):
    failure_indicator = SpeedError.NO_RUNNER_ERROR
    identity = 'speed'
    config_section = 'speed'

    def __init__(self, ctx):
        super(SpeedTestRunner, self).__init__(ctx)
        work_dir = SpeedWorkDir.new_as_replacement(self.ctx.work_dir)
        context.add(self.ctx, 'work_dir', work_dir)

    def run_batch(self, tasks, *args, **kwargs):
        LOG.info('Threshold is %s Mb/s\n' % CONF.speed.threshold)
        LOG.info("Time start: %s UTC\n" % str(datetime.datetime.utcnow()))

        tasks, missing = self.discovery.match(tasks)
        self.test_not_found.extend(missing)

        flavor = CONF.speed.flavor_req
        avail_zone = CONF.speed.availability_zone
        tool_vm_image = CONF.speed.speed_image_path
        network = CONF.networking.network_name
        floating_net = CONF.networking.network_ext_name
        nodes_limit = CONF.speed.compute_nodes_limit

        with resources.Allocator(
                self.ctx, flavor, avail_zone, tool_vm_image,
                network, floating_net,
                nodes_limit=nodes_limit) as allocator:
            context.add(self.ctx, 'allocator', allocator)
            results = super(SpeedTestRunner, self).run_batch(
                tasks, *args, **kwargs)

        results['threshold'] = '{} Mb/s'.format(CONF.speed.threshold)
        LOG.info("\nTime end: %s UTC" % str(datetime.datetime.utcnow()))
        return results

    def _evaluate_task_results(self, task_results):
        res = True
        status = 'PASSED'
        for speed in task_results:
            if speed < CONF.speed.threshold:
                res = False
                LOG.warning('Average speed is under the threshold')
                status = 'FAILED'
                break
        LOG.info(' * %s' % status)
        return res

    def generate_report(self, result, task):
        # Append last run to existing file for now.
        # Not sure how to fix this properly
        LOG.debug('Generating report in speed.html file')
        # Form HTML report
        if task == 'ObjectStorageSpeed':
            table = ObjTable(result)
        else:
            table = BlockTable(result)

        table_html = table.__html__()
        path = os.path.join(os.path.dirname(__file__), 'speed_template.html')
        temp = open(path, 'r').read()
        template = Template(temp)
        res = template.render(table=table_html, name=task)

        report = file('%s/%s.html' % (self.ctx.work_dir.base_dir, task), 'wt')
        report.write(res)
        report.close()

    def run_individual_task(self, task, *args, **kwargs):
        LOG.debug('Start generating %s' % task)

        test_args = {
            'image_size': CONF.speed.image_size,
            'volume_size': CONF.speed.volume_size,
            'iterations': CONF.speed.attempts}
        try:
            speed_class = getattr(st, task)
        except AttributeError:
            raise exceptions.FrameworkError(
                'Invalid test "%s" name (speed plugin)'.format(task))
        try:
            reporter = speed_class(
                context.Context(self.ctx, runner=self), **test_args)
        except Exception:
            LOG.error('Error creating class %s. Please check mcvconsoler logs '
                      'for more info' % task)
            LOG.debug(traceback.format_exc())
            self.test_failures.append(task)
            return False

        res_all = []
        r_average_all = []
        w_average_all = []

        time_start = datetime.datetime.utcnow()
        for vm in self.ctx.allocator.target_vms:
            LOG.debug("Measuring speed on node %s" % vm.id)
            try:
                res, r_average, w_average = reporter.measure_speed(vm)
                res_all += res
                r_average_all.append(r_average)
                w_average_all.append(w_average)
            except Exception:
                self.test_failures.append(task)
                raise
            finally:
                try:
                    reporter.cleanup(vm)
                except Exception as e:
                    LOG.warning(
                        'Unhandled exception in %r.cleanup(): %s', reporter, e)
                    LOG.debug('Error details: ', exc_info=True)

        # store raw results
        self.dump_raw_results(task, res_all)

        time_end = datetime.datetime.utcnow()
        time_of_tests = '{:.3f}s'.format(
            (time_end - time_start).total_seconds())
        self.time_of_tests[task] = {'duration': time_of_tests}
        r_av = round(sum(r_average_all) / len(r_average_all), 2)
        w_av = round(sum(w_average_all) / len(w_average_all), 2)
        LOG.info('Average read speed for all nodes is %s Mb/s' % str(r_av))
        LOG.info('Average write speed for all nodes is %s Mb/s' % str(w_av))
        self.generate_report(res_all, task)

        if not self._evaluate_task_results([r_av, w_av]):
            self.test_failures.append(task)
            return False

        return True


class SpeedWorkDir(utils.WorkDir):
    _idx = itertools.count(utils.WorkDir.RES__LAST + 1)
    RES__LAST = RES_TOOL_VM_SSH_KEY = next(_idx)
    del _idx

    _resource_map = {
        RES_TOOL_VM_SSH_KEY: 'tool-vm.ssh.key'}
