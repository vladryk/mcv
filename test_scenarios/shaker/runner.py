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

import ConfigParser
import logging
import os
import subprocess
import shlex
import sys
from test_scenarios import runner
try:
    import json
except:
    import simplejson as json

import glanceclient as glance
from keystoneclient.v2_0 import client as keystone_v2

nevermind = None

config = ConfigParser.ConfigParser()
default_config = "/etc/mcv/mcv.conf"
LOG = logging


class ShakerRunner(runner.Runner):

    valid_staarten = ("yaml", "json")

    def __init__(self, accessor=None, config_location=None, *args, **kwargs):
        super(ShakerRunner, self).__init__()
        self.identity = "shaker"
        self.config_section = "shaker"
        self.test_failures = []  # this object is supposed to live for one run
                                 # so let's leave it as is for now.
        self.failure_indicator = 40

    def scenario_is_fine(self, scenario):
        return True

    def _it_ends_well(self, something):
        if something.split('.')[-1] in self.valid_staarten:
            return True
        return False

    def _evaluate_task_result(self, task, resulting_dict):
        # logs both success and problems in an uniformely manner.
        status = True
        errors = ''
        if resulting_dict == []:
            errors = 'Timeout Error with shaker. Process was killed.'
            LOG.warning("Task %s has failed with the following error: %s" % \
                        (task, errors))
            return False

        for i in resulting_dict['records']:
            try:
                if resulting_dict['records'][i]['status'] == 'error':
                    status = False
                    errors += '\n' + resulting_dict['records'][i]['stderr']
            except KeyError:
                pass

        if status:
            LOG.info("Task %s has completed successfully." % task)
        else:
            LOG.warning("Task %s has failed with the following error: %s" % \
                        (task, errors))
            return status
        return status

    def _get_task_path(self, task):
        # a quick and dirty way to find a task
        return 'test_scenarios/shaker/tests/%s' % task

    def _run_shaker(self, task):
        LOG.debug("Running task %s" % task)
        # important: at this point task must be transformed to a full path
        path_to_task = self._get_task_path(task)
        cmd = "rally task start %s" % path_to_task
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        # here out is in fact a command which can be run to obtain task results
        # thus it is returned directly.
        out = p.split('\n')[-4].lstrip('\t')
        return out

    def _get_task_result(self, task_id):
        # this function is not using task id contrary to what it says,  but in
        # current state of affair direct command produced by rally. task_id
        # is left as is for now, but will be moved in future.
        # if asked kindly rally just spits resulting json directly to stdout
        p = subprocess.check_output(task_id, shell=True,
                                    stderr=subprocess.STDOUT)
        res = json.loads(p)[0]  # actual test result as a dictionary
        return res

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

    def __init__(self, accessor, path, *args, **kwargs):
        self.config = kwargs["config"]
        self.container_id = None
        self.accessor = accessor
        self.path = path
        self.list_speed_tests = ['same_node.yaml', 'different_nodes.yaml',
                                 'floating_ip.yaml']
        super(ShakerOnDockerRunner, self).__init__()

    def get_glanceclient(self):
        self.key_client = keystone_v2.Client(
            username=self.accessor.access_data['os_username'],
            auth_url=self.config.get('basic', 'auth_protocol')+"://" + self.accessor.access_data["auth_endpoint_ip"] +
                     ":5000/v2.0/",
            password=self.accessor.access_data['os_password'],
            tenant_name=self.accessor.access_data['os_tenant_name'],
            insecure=True)
        image_api_url =self.key_client.service_catalog.url_for(
            service_type="image")
        self.glance = glance.Client(
            '1',
            endpoint=image_api_url,
            token=self.key_client.auth_token,
            insecure=True)

    def _check_shaker_setup(self):
        LOG.info("Checking Shaker setup. If this is the first run of "\
                 "mcvconsoler on this cloud go grab some coffee, it will "\
                 "take a while.")
        insecure = ""
        if self.config.get("basic", "auth_protocol") == "https":
            insecure = " --os-insecure"
        path = '/etc/toolbox/shaker'
        for f in os.listdir(path):
            if f.endswith(".ss.img"):
                path += '/' + f
                break
        if path.endswith('shaker'):
            LOG.error('No shaker image available')
            return
        LOG.debug('Authenticating in glance')
        self.get_glanceclient()
        i_list = self.glance.images.list()
        image = False
        for im in i_list:
            if im.name == 'shaker-image':
                image = True
        if not image:
            LOG.debug('Creating shaker image')
            self.glance.images.create(name='shaker-image', disk_format="qcow2",
                                      container_format="bare", data=open(path),
                                      min_disk=3, min_ram=512)
        else:
            LOG.debug("Shaker image exists")
        LOG.debug("Run shaker-image-builder")
        res = subprocess.Popen(["docker", "exec", "-it",
                                self.container_id,
                                "shaker-image-builder --image-name shaker-image" + insecure],
                                stdout=subprocess.PIPE).stdout.read()

    def start_shaker_container(self):
        LOG.debug( "Bringing up Shaker container with credentials")
        protocol = self.config.get('basic', 'auth_protocol')
        if self.config.get("basic", "auth_fqdn") != '':
            add_host = "--add-host="+self.config.get("basic", "auth_fqdn") +\
                       ":" + self.accessor.access_data["auth_endpoint_ip"]
        res = subprocess.Popen(["docker", "run", "-d", "-P=true",] +
                               [add_host]*(add_host != "") +
            ["-p", "5999:5999", "-e", "OS_AUTH_URL="+protocol+"://" +
            self.accessor.access_data["auth_endpoint_ip"] + ":5000/v2.0/",
            "-e", "OS_TENANT_NAME=" +
            self.accessor.access_data["os_tenant_name"],
            "-e", "OS_USERNAME=" + self.accessor.access_data["os_username"],
            "-e", "OS_PASSWORD=" + self.accessor.access_data["os_password"],
            "-e", "OS_REGION_NAME=" + self.accessor.access_data["region_name"],
            "-e", "KEYSTONE_ENDPOINT_TYPE=publicUrl",
            "-it", "mcv-shaker"], stdout=subprocess.PIPE).stdout.read()

    def _setup_shaker_on_docker(self):
        self.verify_container_is_up("shaker")
        self._check_shaker_setup()
        p = subprocess.check_output("docker ps", shell=True,
                                    stderr=subprocess.STDOUT)
        p = p.split('\n')
        for line in p:
            elements = line.split()
            if elements[1].find("shaker") != -1:
                self.container = elements[0]
                status = elements[4]
                break

    def _create_task_in_docker(self, task):
        cmd = "docker inspect -f '{{.Id}}' %s" % self.container
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        test_location = os.path.join(os.path.dirname(__file__), "tests", task)
        LOG.info("Preparing to task %s" % task)
        cmd = r"cp " + test_location +\
              " /var/lib/docker/aufs/mnt/%s/usr/local/lib/python2.7/"\
              "dist-packages/shaker/scenarios/networking/" %\
              p.rstrip('\n')
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        LOG.info("Successfully prepared to task %s" % task)


    def _run_shaker_on_docker(self, task):
        LOG.info("Starting task %s" % task)
        insecure = ""
        if self.config.get("basic", "auth_protocol") == "https":
            insecure = " --os-insecure"
        self.endpoint = self.accessor.access_data['auth_endpoint_ip']
        cmd = "docker exec -it %s shaker-image-builder --image-name " \
              "shaker-image" % self.container

        p = subprocess.check_output(cmd + insecure, shell=True, stderr=subprocess.STDOUT)

        if (task in self.list_speed_tests):
            self._create_task_in_docker(task)

        # Note: make port configurable
        timeout = self.config.get("shaker", "timeout")
        cmd = "docker exec -it %s timeout %s shaker --server-endpoint " \
              "%s:5999 --scenario " \
              "/usr/local/lib/python2.7/dist-packages/shaker/scenarios/networking/%s" \
              " --debug --output %s.out --report-template json --report " \
              "%s.json" % (self.container, timeout,
                           self.accessor.access_data["instance_ip"],
                           task, task, task)

        proc = subprocess.Popen(shlex.split(cmd + insecure),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        proc.communicate()
        # Note: TIMEOUT_RETCODE = 124
        if proc.returncode == 124:
            self.failure_indicator = 41
            LOG.info('Process #%d killed after %s seconds' % (proc.pid, timeout))
            LOG.debug('Timeout error occurred trying to execute shaker')
            return []

        cmd = "docker inspect -f   '{{.Id}}' %s" % self.container_id
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        container_id = p.rstrip('\n')

        cmd = "docker exec -it %s shaker-report --input %s.out --report " \
         "%s.html" % (self.container, task, task)
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

        cmd = "sudo cp %(pref)s/%(id)s/%(task)s.json %(pth)s" % \
                  {"pref": "/var/lib/docker/aufs/mnt", "id": container_id,
                   'task': task, "pth": self.path}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

        temp = open('%s/%s.json' % (self.path, task), 'r')
        p = temp.read()
        temp.close()
        result = json.loads(p)

        cmd = "sudo cp %(pref)s/%(id)s/%(task)s.html %(pth)s" % \
                  {"pref": "/var/lib/docker/aufs/mnt", "id": container_id,
                   'task': task, "pth": self.path}
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

        # Network speed test includes three scenario, function 'clear_image'
        # will run after completing all of scenarios
        if not (task in self.list_speed_tests):
            self.clear_shaker_image()
        return result

    def clear_shaker_image(self):
        clear_image = self.config.get('shaker', 'clear_image')
        if clear_image == 'True':
            i_list = self.glance.images.list()
            for im in i_list:
                if im.name == 'shaker-image':
                    self.glance.images.delete(im)

    def _get_task_result_from_docker(self, task_id):
        LOG.info("Retrieving task results for %s" % task_id)
        cmd = "docker exec -it %s %s" % (self.container, task_id)
        p = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        if task_id.find("detailed") == -1:
            res = json.loads(p)[0]  # actual test result as a dictionary
            return res
        else:
            return p.split('\n')[-4:-1]

    def _parse_shaker_report(self, task, threshold):

        f = open('%s/%s.json' % (self.path, task), 'r')
        report = json.loads(f.read())
        f.close()

        test_case = ''
        for i in report['scenarios']:
            test_case += report['scenarios'][i]['description']

        speeds = []
        for i in report['records']:
            try:
                if report['records'][i]['chart'][1][0] == "Mean TCP download":
                    speeds = report['records'][i]['chart'][1]
                    speeds.pop(0)
            except KeyError:
                pass

        nodes = set()

        for i in report['agents']:
            nodes.add(report['agents'][i]['node'])

        success = True & len(speeds)
        for i in speeds:
            if (i < float(threshold) * 1024):
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

        return test_case, speeds, nodes, success, status

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

        test_case, speeds, nodes, success, status = self._parse_shaker_report(
            task, threshold)
        speed = ''
        for i in speeds:
            to_gb = i / 1024
            speed += '%.2f' % to_gb + ', '
        speed = speed[:-2]

        line = '-' * 40
        LOG.info('\n%s' % line)
        LOG.info('Average speed is %s Gb/s' % speed)
        if (success):
            LOG.info('This scenario: SUCCESS')
        else:
            LOG.info('This scenario: FAILED')
            LOG.info('Average speed is less than threshold')
        LOG.info('%s\n' % line)

        node = ''
        for i in nodes:
            node += i + ', '
        node = node[:-2]

        return template.format(test_case=test_case,
                               scenario=task,
                               speed=speed,
                               node=node,
                               task=task,
                               status=status), success

    def _generate_report_network_speed(self, threshold, task, output):
        LOG.info('Generating report for network_speed tests')

        path = os.path.join(os.path.dirname(__file__), 'network_speed_template.html')
        temp = open(path, 'r')
        template = temp.read()
        temp.close()
        template = template.format(threshold=threshold, output=output)

        report = file('%s/%s.html' % (self.path, task), 'w')
        report.write(template)
        report.close()

    def run_batch(self, tasks, *args, **kwargs):
        self._setup_shaker_on_docker()
        return super(ShakerOnDockerRunner, self).run_batch(tasks, *args,
                                                           **kwargs)

    def run_individual_task(self, task, *args, **kwargs):
        if (task == 'network_speed'):
            self.failure_indicator = 22

            try:
                threshold = self.config.get('network_speed', 'threshold')
                LOG.info('Threshold is %s Gb/s' % threshold)
            except ConfigParser.NoOptionError:
                LOG.info('Default threshold is 7 Gb/s')
                threshold = 7

            output = ''
            success = True

            for internal_task in self.list_speed_tests:
                try:
                    task_result = self._run_shaker_on_docker(internal_task)
                except subprocess.CalledProcessError:
                    LOG.error("Task %s failed with: " % task, exc_info=True)

                check = self._evaluate_task_result(task, task_result)
                if not check:
                    self.clear_shaker_image()
                    self.test_failures.append(task)
                    LOG.debug("Task %s has failed with %s" % (task, task_result))
                    return False

                row, report_status = self._generate_one_row_report(task_result,
                    internal_task, threshold)
                output += row
                success &= report_status
            self._generate_report_network_speed(threshold, task, output)
            self.clear_shaker_image()

            if success:
                return True
            else:
                LOG.warning("Task %s has failed with %s" % (
                    task, '"Average network speed is less then threshold"'))
                self.test_failures.append(task)
                return False

        try:
            task_result = self._run_shaker_on_docker(task)
        except subprocess.CalledProcessError:
            task_result = False

        if type(task_result) == dict and\
                self._evaluate_task_result(task, task_result):
            return True
        else:
            LOG.debug("Task %s has failed with %s" % (task, task_result))
            self.test_failures.append(task)
            return False
