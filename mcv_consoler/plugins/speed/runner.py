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

from ConfigParser import NoOptionError
import datetime
import os.path
# TODO(albartash): replace with traceback2
import traceback

from mcv_consoler.common.errors import SpeedError
from mcv_consoler.logger import LOG
import mcv_consoler.plugins.runner as run
from mcv_consoler.plugins.speed.prepare_instance import Preparer
from mcv_consoler.plugins.speed import speed_tester as st
from mcv_consoler.utils import GET
import mcv_consoler.common.config as app_conf

LOG = LOG.getLogger(__name__)


class SpeedTestRunner(run.Runner):
    def __init__(self, accessor, path, *args, **kwargs):
        self.access_data = accessor.os_data
        self.identity = "speed"
        self.config_section = "speed"
        self.config = kwargs.get('config')
        self.test_failures = []
        self.path = path
        super(SpeedTestRunner, self).__init__()
        self.failure_indicator = SpeedError.NO_RUNNER_ERROR
        self.node_ids = []
        self.home = '/mcv'

        # TODO(albartash): Make a single place for images!
        self.imagedir = '/home/mcv/toolbox/rally/images'

        self.threshold = GET(self.config,
                             'threshold',
                             'speed', str(app_conf.DEFAULT_SPEED_STORAGE))

    def _evaluate_task_results(self, task_results):
        res = True
        for speed in task_results:
            if speed < float(self.threshold):
                res = False
                LOG.warning('Average speed is under the threshold')
                LOG.info(" * FAILED")
                break
            else:
                LOG.info(" * PASSED")
        return res

    def get_preparer(self):
        return Preparer(self.access_data)

    def _prepare_vms(self):
        preparer = self.get_preparer()
        try:
            image_path = self.config.get('speed', 'cirros_image_path')
        except NoOptionError:
            LOG.debug('Use default image path')
            # TODO(albartash): extract it to common/config.py somehow
            image_path = os.path.join(self.imagedir,
                                      'cirros-0.3.1-x86_64-disk.img')

        try:
            flavor_req = self.config.get('speed', 'flavor_req')
        except NoOptionError:
            LOG.debug('Use default flavor requirements')
            flavor_req = 'ram:64,vcpus:1'
        supported_req = ['ram', 'vcpus', 'disk']
        flavor_req = dict((k.strip(), int(v.strip())) for k, v in
                          (item.split(':') for item in flavor_req.split(',')
                           ) if (k and v) and (k in supported_req))
        return preparer.prepare_instances(image_path, flavor_req)

    def _remove_vms(self):
        preparer = self.get_preparer()
        preparer.delete_instances()

    def run_batch(self, tasks, *args, **kwargs):
        res = {'test_failures': 1, 'test_success': 0, 'test_not_found': 0}
        LOG.info('Threshold is %s Mb/s\n' % self.threshold)
        LOG.info("Time start: %s UTC\n" % str(datetime.datetime.utcnow()))
        try:
            self.node_ids = self._prepare_vms()
            res = super(SpeedTestRunner, self).run_batch(tasks,
                                                         *args,
                                                         **kwargs)
            res['threshold'] = self.threshold + ' Mb/s'
            return res
        except RuntimeError:
            LOG.error('Environment preparation error')
            # TODO(albartash): It's a hard-hack. Refactor this place, please!
            # It just prevents us from 'No attribute __getitem__'
            return res
        except Exception:
            LOG.error('Caught unexpected error, exiting. '
                      'Please check mcvconsoler logs')
            LOG.debug(traceback.format_exc())
            # TODO(albartash): It's a hard-hack. Refactor this place, please!
            # It just prevents us from 'No attribute __getitem__'
            return res
        finally:
            try:
                LOG.info("\nTime end: %s UTC" % str(datetime.datetime.utcnow()))
                self._remove_vms()
            except Exception:
                LOG.error(
                    'Something went wrong when removing VMs. '
                    'Please check mcvconsoler logs')
                LOG.debug(traceback.format_exc())
                # TODO(albartash): It's a hard-hack.
                # Refactor this place, please!
                # It just prevents us from 'No attribute __getitem__'
                return res

    def generate_report(self, html, task):
        # Append last run to existing file for now.
        # Not sure how to fix this properly
        LOG.debug('Generating report in speed.html file')
        report = file('%s/%s.html' % (self.path, task), 'w')
        report.write(html)
        report.close()

    def run_individual_task(self, task, *args, **kwargs):
        # runs a set of commands
        if self.node_ids is None:
            LOG.error('Failed to measure speed - no test VMs was created')
            self.test_failures.append(task)
            return False
        i_s = GET(self.config, 'image_size', 'speed', '1G')
        v_s = GET(self.config, 'volume_size', 'speed', '1G')
        LOG.debug('Start generating %s' % task)
        try:
            speed_class = getattr(st, task)
        except AttributeError:
            LOG.error('Incorrect task')
            return False
        try:
            reporter = speed_class(self.access_data, image_size=i_s,
                                   volume_size=v_s, *args, **kwargs)
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

        r_average_all = []
        w_average_all = []

        compute_node_ids = self.node_ids
        compute_nodes_quantity = GET(self.config,
                                     'compute_nodes_limit',
                                     'speed')
        if compute_nodes_quantity is not None:
            try:
                compute_nodes_quantity = int(compute_nodes_quantity)
            except ValueError:
                LOG.error(
                    "Expected int type of "
                    "'compute_nodes_limit' parameter, but "
                    "got value {} instead.".format(compute_nodes_quantity))
                self.test_failures.append(task)
                return False
            compute_node_ids = self.node_ids[:compute_nodes_quantity]
            LOG.debug('Speed will be measured on {} compute nodes'.format(
                len(compute_node_ids)))
        else:
            LOG.debug('Speed will be measured on all compute nodes')

        for node_id in compute_node_ids:
            LOG.debug("Measuring speed on node %s" % node_id)
            try:
                res, r_average, w_average = reporter.measure_speed(node_id)
                res_all += res
                r_average_all.append(r_average)
                w_average_all.append(w_average)
            except RuntimeError:
                LOG.error('Failed to measure speed')
                try:
                    reporter.cleanup(node_id)
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
                    reporter.cleanup(node_id)
                except Exception:
                    LOG.warning('Unexpected cleanup error. '
                                'Please check mcvconsoler logs')
                    LOG.debug(traceback.format_exc())
                self.test_failures.append(task)
                return False

        r_av = round(sum(r_average_all) / len(r_average_all), 2)
        w_av = round(sum(w_average_all) / len(w_average_all), 2)
        res_all += ('<br><h4> Overall average results: read - {} MB/s, '
                    'write - {} MB/s:</h4>').format(r_av, w_av)

        res_all += "</body>\n</html>"
        self.generate_report(res_all, task)
        if self._evaluate_task_results([r_av, w_av]):
            return True
        else:
            self.test_failures.append(task)
            return False
