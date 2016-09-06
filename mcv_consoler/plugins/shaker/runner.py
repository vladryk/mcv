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
import json
import logging
import os
import shlex
import subprocess

from oslo_config import cfg

from mcv_consoler.common import clients as Clients
from mcv_consoler.common.errors import ShakerError
from mcv_consoler.common.errors import SpeedError
from mcv_consoler.plugins import runner
from mcv_consoler import utils
import mcv_consoler.common.config as app_conf

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class ShakerRunner(runner.Runner):
    failure_indicator = ShakerError.NO_RUNNER_ERROR
    identity = 'shaker'
    config_section = 'shaker'

    def __init__(self, ctx):
        super(ShakerRunner, self).__init__(ctx)

        # this object is supposed to live for one run
        # so let's leave it as is for now.
        self.test_failures = []

        self.homedir = '/home/mcv/toolbox/shaker'
        self.home = '/mcv'

    def _evaluate_task_result(self, task, resulting_dict):
        status = True
        errors = ''
        if type(resulting_dict) != dict:
            LOG.debug("Task %s has failed with the following error: %s" %
                      (task, resulting_dict))
            return False

        for i in resulting_dict['records']:
            try:
                if resulting_dict['records'][i]['status'] == 'error':
                    status = False
                    errors += '\n' + resulting_dict['records'][i]['stderr']
            except KeyError:
                pass

        return status

    def _get_task_path(self, task):
        # TODO(albartash): refactor this damn
        return 'plugins/shaker/tests/%s' % task

    def _run_shaker(self, task):
        LOG.debug("Running task %s" % task)
        # warning: at this point task must be transformed to a full path
        path_to_task = self._get_task_path(task)
        p = utils.run_cmd("rally task start " + path_to_task)

        # here out is in fact a command which can be run to obtain task results
        # thus it is returned directly.
        out = p.split('\n')[-4].lstrip('\t')
        return out

    def _get_task_result(self, task_id):
        # TODO(albartash): Fix the issue mentioned below:

        # this function is not using task id contrary to what it says,  but in
        # current state of affair direct command produced by rally. task_id
        # is left as is for now, but will be moved in future.
        # if asked kindly rally just spits resulting json directly to stdout
        p = utils.run_cmd(task_id)
        try:
            res = json.loads(p)[0]
            return res
        except ValueError:
            LOG.error("Gotten not-JSON object. Please see mcv-log")
            LOG.debug("Not-JSON object: %s", p)
            return "Not-JSON object"

    def run_batch(self, tasks, *args, **kwargs):
        return super(ShakerRunner, self).run_batch(tasks, *args, **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
        # runs a set of commands
        task_id = self._run_rally(task)
        task_result = self._get_task_result(task_id)
        if self._evaluate_task_result(task, task_result):
            return
        else:
            self.test_failures.append(task)


class ShakerOnDockerRunner(ShakerRunner):
    def __init__(self, ctx):
        super(ShakerOnDockerRunner, self).__init__(ctx)
        self.access_data = self.ctx.access_data
        self.path = self.ctx.work_dir.base_dir

        self.container_id = None
        self.image_name = CONF.shaker.image_name
        self.flavor_name = CONF.shaker.flavor_name
        self.output = None
        self.success = None
        self.threshold = CONF.network_speed.threshold
        self.heat = Clients.get_heat_client(self.access_data)

    def _check_shaker_setup(self):
        LOG.info("Start shaker-image-builder. Creating infrastructure. "
                 "Please wait...")
        cmd = "docker exec -t %s shaker-image-builder --image-name %s " \
              "--flavor-name %s" % (self.container_id, self.image_name,
                                    self.flavor_name)
        p = utils.run_cmd(cmd)
        if 'ERROR' in p:
            LOG.debug("shaker-image-builder failed")
            for stack in self.heat.stacks.list():
                if 'shaker' in stack.stack_name:
                    stack.delete()
            raise RuntimeError

        LOG.debug('Finish running shaker-image-builder.')

    def start_container(self):
        LOG.debug("Bringing up Shaker container with credentials")

        add_host = ""

        # TODO(albartash): Refactor this place!
        if self.access_data["auth_fqdn"] != '':
            add_host = "--add-host={fqdn}:{endpoint}".format(
                fqdn=self.access_data["auth_fqdn"],
                endpoint=self.access_data["public_endpoint_ip"])

        res = subprocess.Popen(
            ["docker", "run", "-d", "-P=true"] +
            [add_host] * (add_host != "") +
            ["-p", "5999:5999",
             "-e", "OS_AUTH_URL={}".format(self.access_data["auth_url"]),
             "-e", "OS_TENANT_NAME={}".format(self.access_data["tenant_name"]),
             "-e", "OS_USERNAME={}".format(self.access_data["username"]),
             "-e", "OS_PASSWORD={}".format(self.access_data["password"]),
             "-e", "OS_REGION_NAME={}".format(self.access_data["region_name"]),
             "-e", "SHAKER_EXTERNAL_NET={}".format(CONF.network_speed.network_ext_name or ""),
             "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
             "-e", "OS_INSECURE={}".format(self.access_data["insecure"]),
             # TODO(vokhrimenko): temporarily not used
             # "-e", "OS_CACERT=" + self.access_data["fuel"]["ca_cert"],
             "-v", "{}:{}".format(self.homedir, self.home), "-w", self.home,
             "-t", "mcv-shaker"],
            stdout=subprocess.PIPE,
            preexec_fn=utils.ignore_sigint).stdout.read()

        LOG.debug('Finish bringing up Shaker container. '
                  'ID = %s' % str(res))

    def _setup_shaker_on_docker(self):
        self.verify_container_is_up("shaker")
        self._check_shaker_setup()
        p = utils.run_cmd("docker ps")
        p = p.split('\n')
        for line in p:
            elements = line.split()
            if elements[1].find("shaker") != -1:
                self.container = elements[0]
                status = elements[4]
                LOG.debug('Container status: %s' % str(status))
                break

    def _run_shaker_on_docker(self, task):
        LOG.debug("Starting task %s" % task)

        # TODO(albartash): make port for Shaker configurable some day

        timeout = CONF.shaker.timeout
        agents_timeout = CONF.shaker.agents_timeout

        cmd = ("docker exec -t {cid} timeout {tout} shaker "
               "--agent-loss-timeout {agent_tout} "
               "--image-name {image} "
               "--flavor-name {flavor} "
               "--server-endpoint {sep}:5999 "
               "--agent-join-timeout 3600 "
               "--scenario {home}/tests/openstack/{task} "
               "--debug --output {task}.out "
               "--report-template json "
               "--report {task}.json "
               "--log-file {home}/log/shaker.log"
               ).format(cid=self.container,
                        tout=timeout,
                        agent_tout=agents_timeout,
                        image=self.image_name,
                        flavor=self.flavor_name,
                        sep=self.access_data['ips']["instance"],
                        task=task,
                        home=self.home)

        LOG.debug('Executing command: "%s"' % cmd)

        proc = subprocess.Popen(shlex.split(cmd),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                preexec_fn=utils.ignore_sigint)
        proc.communicate()

        if proc.returncode == 124:
            self.failure_indicator = ShakerError.TIMEOUT_EXCESS
            LOG.info('Process {} killed after {} seconds.\n'
                     'Report for this scenario was lost. '
                     'For more details - please see logs '.format(proc.pid, timeout))
            LOG.info(' * FAILED')
            LOG.info('-' * 60)
            LOG.debug('Timeout error occurred trying to execute shaker')
            for stack in self.heat.stacks.list():
                if 'shaker' in stack.stack_name:
                    stack.delete()
            return []

        cmd = ("docker exec -t %s shaker-report --input %s.out --report "
               "%s.html") % (self.container, task, task)
        p = utils.run_cmd(cmd)

        cmd = "sudo cp {homedir}/{task}.json {path}".format(
            homedir=self.homedir, task=task, path=self.path)
        p = utils.run_cmd(cmd)

        temp = open('%s/%s.json' % (self.path, task), 'r')
        p = temp.read()
        temp.close()
        try:
            result = json.loads(p)
        except ValueError:
            LOG.error("Gotten not-JSON object. Please see mcv-log")
            LOG.debug("Not-JSON object: %s, After command: %s", p, cmd)
            return "Not-JSON object"

        # store raw results
        self.dump_raw_results(task, result)

        cmd = "sudo cp {homedir}/{task}.html {path}".format(
            homedir=self.homedir, task=task, path=self.path)

        utils.run_cmd(cmd)

        return result

    def clear_shaker(self):
        if CONF.shaker.cleanup:
            LOG.info("Removing shaker's image and flavor")
            cmd = "docker exec -t %s shaker-cleanup --image-name %s " \
                  "--flavor-name %s" % (self.container_id, self.image_name,
                                        self.flavor_name)
            utils.run_cmd(cmd)

    def _get_task_result_from_docker(self, task_id):
        LOG.info("Retrieving task results for %s" % task_id)
        cmd = "docker exec -t %s %s" % (self.container, task_id)
        p = utils.run_cmd(cmd)

        if task_id.find("detailed") == -1:
            try:
                res = json.loads(p)[0]
                return res
            except ValueError:
                LOG.error("Gotten not-JSON object. Please see mcv-log")
                LOG.debug("Not-JSON object: %s, After command: %s", p, cmd)
                return "Not-JSON object"
        else:
            return p.split('\n')[-4:-1]

    def _parse_shaker_report(self, task, threshold):

        f = open('%s/%s.json' % (self.path, task), 'r')
        report = json.loads(f.read())
        f.close()

        test_case = ''
        for i in report['scenarios']:
            test_case += report['scenarios'][i]['description']

        speeds_dict = {}
        speeds = []
        for i in report['records']:
            try:
                _key = [_key for x in app_conf.SHAKER_REPORT_KEYS
                        for _key in report['records'][i]['stats'].keys()
                        if _key.startswith(x)][0]
                speed = report['records'][i]['stats'][_key]['avg']
                speeds.append(speed)
                speeds_dict[report['records'][i]['node']] = speed
            except KeyError:
                pass

        agents = []

        for i in report['agents']:

            if 'master' in i:
                tmp = set()

                master_node = report['agents'][i]['node']
                slave_node = report['agents'][i]['slave']['node']
                tmp.add(master_node)
                tmp.add(slave_node)
                spd = speeds_dict[master_node] / 1024.0

                agents.append({"speed": spd, "node": tmp})

        success = True & (len(speeds) > 0)

        for i in speeds:
            if (i < threshold * 1024):
                success = False

        ok = """
        <span class="label label-success">
          <span class="glyphicon glyphicon-ok" aria-hidden="true"></span>
          success
        </span>
        """

        error = """
        <span class="label label-danger">
          <span class="glyphicon glyphicon-stop" aria-hidden="true"></span>
          error
        </span>
        """

        if (success):
            status = ok
        else:
            status = error

        return test_case, speeds, agents, success, status

    def _generate_one_row_report(self, result, task, threshold):
        template = """
        <tr role="row">
          <td class="sorting_1">{test_case}</td>
          <td>{scenario}</td>
          <td>{speed}</td>
          <td>{node}</td>
          <td>
            <a href="./{task}.html">shaker report</a>
          </td>
          <td>{status}</td>
        </tr>
        """

        test_case, speeds, agents, success, status = self._parse_shaker_report(
            task, threshold)

        speed = ''
        if len(speeds):
            to_gb = min(speeds) / 1024.0
            speed = '%.2f' % to_gb
        LOG.info('Average speed is %s Gb/s' % speed)

        speed = ''
        node = ''

        for agent in agents:
            speed += '%.2f<br>' % agent['speed']
            for n in agent['node']:
                node += n + ', '
            node = node[:-2]
            node += '<br>'

        return template.format(test_case=test_case,
                               scenario=task,
                               speed=speed,
                               node=node,
                               task=task,
                               status=status), success

    def _generate_report_network_speed(self, threshold, task, output):
        LOG.debug('Generating report for network_speed tests')

        path = os.path.join(os.path.dirname(__file__),
                            'network_speed_template.html')
        temp = open(path, 'r')
        template = temp.read()
        temp.close()
        template = template.format(threshold=threshold, output=output)

        report = file('%s/%s.html' % (self.path, task), 'w')
        report.write(template)
        report.close()

    def run_batch(self, tasks, *args, **kwargs):
        try:
            self._setup_shaker_on_docker()
        except RuntimeError:
            LOG.debug('Caught RuntimeError. Probably Shaker failed to build '
                      'its infrastructure. Please check if you have an access'
                      ' to an Internet, or Shaker image is already '
                      'uploaded to Glance with your own.')
            tasks, missing = [], list(tasks)
        else:
            LOG.info('\nThreshold is %s Gb/s\n', self.threshold)
            self.output = ''
            LOG.info("Time start: %s UTC\n", datetime.datetime.utcnow())

            tasks, missing = self.discovery.match(tasks)

        self.test_not_found.extend(missing)

        result = super(ShakerOnDockerRunner, self).run_batch(
            tasks, *args, **kwargs)
        self._generate_report_network_speed(self.threshold,
                                            'network_speed',
                                            self.output)
        result['threshold'] = '{} Gb/s'.format(self.threshold)
        LOG.info("\nTime end: %s UTC", datetime.datetime.utcnow())
        self.clear_shaker()
        return result

    def run_individual_task(self, task, *args, **kwargs):
        self.success = True
        if task:
            LOG.info("Starting task %s" % task)
            self.failure_indicator = SpeedError.LOW_AVG_SPEED
            time_start = datetime.datetime.utcnow()
            try:
                task_result = self._run_shaker_on_docker(task)
            except subprocess.CalledProcessError as e:
                LOG.error("Task %s failed with: %s" % (task, e))
                # NOTE(albartash): Maybe, refactor this later
                task_result = None
            time_end = datetime.datetime.utcnow()
            time_of_tests = str(round((time_end - time_start).total_seconds(), 3)) + 's'
            self.time_of_tests[task] = {'duration': time_of_tests}

            if task_result == []:
                self.test_without_report.append(task)
                LOG.debug("Task {task} has failed without report".format(
                    task=task))
                return False

            check = self._evaluate_task_result(task, task_result)

            if not check:
                self.test_failures.append(task)
                LOG.debug("Task {task} has failed with {res}".format(
                    task=task, res=task_result))
                return False

            row, report_status = self._generate_one_row_report(
                task_result, task, self.threshold)
            self.output += row
            self.success &= report_status

            if self.success:
                LOG.info(' * PASSED')
            else:
                LOG.info('Average speed is less than threshold')
                LOG.info(' * FAILED')
                self.test_failures.append(task)
            LOG.info('-' * 60)

            return self.success

        else:
            LOG.info("Haven't found any tasks in your conf")
            return False
