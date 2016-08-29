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
import os.path
# TODO(albartash): replace with traceback2
import traceback

from flask_table import Table, Col
from jinja2 import Template

from mcv_consoler.common.errors import SpeedError
from mcv_consoler.log import LOG
import mcv_consoler.plugins.runner as run
from mcv_consoler.plugins.speed.prepare_instance import Preparer
from mcv_consoler.plugins.speed import speed_tester as st
from mcv_consoler.utils import GET
import mcv_consoler.common.config as app_conf

LOG = LOG.getLogger(__name__)


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


class SpeedTestRunner(run.Runner):
    failure_indicator = SpeedError.NO_RUNNER_ERROR
    identity = 'speed'
    config_section = 'speed'

    def __init__(self, ctx):
        super(SpeedTestRunner, self).__init__(ctx)

        self.access_data = self.ctx.access_data
        self.path = self.ctx.work_dir
        self.config = self.ctx.config

        self.test_failures = []
        self.node_ids = []
        # TODO(albartash): Make a single place for images!
        self.imagedir = '/home/mcv/toolbox/rally/images'

        self.threshold = GET(self.config,
                             'threshold',
                             'speed', str(app_conf.DEFAULT_SPEED_STORAGE))
        self.preparer = Preparer(self.access_data, self.path)

    def _evaluate_task_results(self, task_results):
        res = True
        status = 'PASSED'
        for speed in task_results:
            if speed < float(self.threshold):
                res = False
                LOG.warning('Average speed is under the threshold')
                status = 'FAILED'
                break
        LOG.info(' * %s' % status)
        return res

    def _prepare_vms(self):
        avail_zone = GET(self.config, 'availability_zone', 'speed', 'nova')
        flavor_req = GET(self.config, 'flavor_req', 'speed', 'ram:1024,vcpus:1')
        image_path = GET(self.config, 'speed_image_path', 'speed',
                         app_conf.FEDORA_IMAGE_PATH)

        supported_req = ['ram', 'vcpus', 'disk']
        flavor_req = dict((k.strip(), int(v.strip())) for k, v in
                          (item.split(':') for item in flavor_req.split(',')
                           ) if (k and v) and (k in supported_req))
        return self.preparer.prepare_instances(image_path, flavor_req, avail_zone)

    def run_batch(self, tasks, *args, **kwargs):
        res = {'test_failures': [], 'test_success': [], 'test_not_found': []}
        LOG.info('Threshold is %s Mb/s\n' % self.threshold)
        LOG.info("Time start: %s UTC\n" % str(datetime.datetime.utcnow()))

        tasks, missing = self.discovery.match(tasks)
        self.test_not_found.extend(missing)

        try:
            self.node_ids = self._prepare_vms()
            res = super(SpeedTestRunner, self).run_batch(tasks,
                                                         *args,
                                                         **kwargs)
            res['threshold'] = self.threshold + ' Mb/s'
            return res
        except RuntimeError:
            LOG.error('Environment preparation error')
            return res
        except Exception:
            LOG.error('Caught unexpected error, exiting. '
                      'Please check mcvconsoler logs')
            LOG.debug(traceback.format_exc())
            return res
        finally:
            try:
                LOG.info("\nTime end: %s UTC" % str(datetime.datetime.utcnow()))
                self.preparer.delete_instances()
            except Exception:
                LOG.error(
                    'Something went wrong when removing VMs. '
                    'Please check mcvconsoler logs')
                LOG.debug(traceback.format_exc())
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

        report = file('%s/%s.html' % (self.path, task), 'w')
        report.write(res)
        report.close()

    def run_individual_task(self, task, *args, **kwargs):
        if not self.node_ids:
            LOG.error('Failed to measure speed - no test VMs was created')
            self.test_failures.append(task)
            return False

        kwargs['work_dir'] = self.path
        kwargs['image_size'] = GET(self.config, 'image_size', 'speed', '1G')
        kwargs['volume_size'] = GET(self.config, 'volume_size', 'speed', '1G')
        kwargs['iterations'] = GET(
            self.config, 'attempts', 'speed',
            default=app_conf.SPEED_STORAGE_ATTEMPTS_DEFAULT, convert=int)

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

        res_all = []

        r_average_all = []
        w_average_all = []

        time_start = datetime.datetime.utcnow()
        for node_id in self.node_ids:
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

        time_end = datetime.datetime.utcnow()
        time_of_tests = str(round((time_end - time_start).total_seconds(), 3)) + 's'
        self.time_of_tests[task] = {'duration': time_of_tests}
        r_av = round(sum(r_average_all) / len(r_average_all), 2)
        w_av = round(sum(w_average_all) / len(w_average_all), 2)
        LOG.info('Average read speed for all nodes is %s Mb/s' % str(r_av))
        LOG.info('Average write speed for all nodes is %s Mb/s' % str(w_av))
        self.generate_report(res_all, task)
        if self._evaluate_task_results([r_av, w_av]):
            return True
        else:
            self.test_failures.append(task)
            return False
