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

import os
import time
import yaml
import prettytable
import traceback

from datetime import datetime

from mcv_consoler.log import LOG
from mcv_consoler.utils import GET
from mcv_consoler.common import clients
from mcv_consoler.common import config
from mcv_consoler import exceptions

LOG = LOG.getLogger(__name__)


class Cleanup(object):
    def __init__(self, conf, os_data):
        self.config = conf
        self.os_data = os_data
        self.store = Store(self.config)
        self.started_resources = None
        self.finished_resources = None

        self._create_clients()

    def _create_clients(self):
        try:
            self.keystoneclient = clients.get_keystone_client(self.os_data)
            self.novaclient = clients.get_nova_client(self.os_data)
            self.cinderclient = clients.get_cinder_client(self.os_data)
            self.glanceclient = clients.get_glance_client(self.os_data)
            self.neutronclient = clients.get_neutron_client(self.os_data)
            self.heatclient = clients.get_heat_client(self.os_data)
        except Exception:
            LOG.debug(traceback.format_exc())
            raise exceptions.ClientsError(
                'Unable to create clients')

    def _get_list_of_resources(self):
        resources = {}
        try:
            # TODO(vokhrimenko): Need remove try-except after fix MCV-834
            try:
                resources['users'] = [
                    i.name for i in self.keystoneclient.users.findall()]
                resources['projects'] = [
                    i.name for i in self.keystoneclient.tenants.findall()]
            except Exception:
                LOG.warning("Can't get resources from Keystone")

            resources['flavors'] = [
                i.name for i in self.novaclient.flavors.findall()]
            resources['servers'] = [
                i.name for i in self.novaclient.servers.findall()]
            resources['keypairs'] = [
                i.name for i in self.novaclient.keypairs.findall()]
            resources['security_groups'] = [
                i.name for i in self.novaclient.security_groups.findall()]

            resources['volumes'] = [
                i.name for i in self.cinderclient.volumes.findall()]
            resources['volume_snapshots'] = [
                i.name or i.id for i in self.cinderclient.volume_snapshots.findall()]

            resources['images'] = [
                i.name for i in self.glanceclient.images.findall()]

            resources['routers'] = [
                i['name'] for i in self.neutronclient.list_routers()['routers']]
            resources['networks'] = [
                i['name'] for i in self.neutronclient.list_networks()['networks']]

            resources['stacks'] = [
                i.stack_name for i in self.heatclient.stacks.list()]

        except Exception:
            LOG.debug(traceback.format_exc())
            raise exceptions.OpenStackResourceAccessError(
                "Can't get lists of resources ")
        return resources

    @staticmethod
    def _filter_by_tags(resources):
        result = {}
        result_tag = {}
        tags = config.CLEANUP_TAGS
        for resource in resources:
            set_result_tag = set()
            set_result = set()
            for name in resources[resource]:
                for t in tags:
                    if t in name:
                        set_result_tag.add(name)
                        break
                else:
                    set_result.add(name)
            result_tag[resource] = list(set_result_tag)
            result[resource] = list(set_result)
        return result_tag, result

    def get_started_resources(self):
        self.started_resources = self._get_list_of_resources()
        self.store.save(self.started_resources)
        result_tag, result = self._filter_by_tags(self.started_resources)
        if result_tag:
            LOG.info("Before run tests, MCV found trash like as after tests")
            self.print_resources(result_tag)

    def get_finished_resources(self):
        self.finished_resources = self._get_list_of_resources()
        mcv_resources = self.compare_start_end_resources(self.started_resources,
                                                         self.finished_resources)
        result_tag, result = self._filter_by_tags(mcv_resources)
        if [i for i in result.values() if i]:
            LOG.info("MCV found new resources")
            self.print_resources(result)
        if [i for i in result_tag.values() if i]:
            LOG.info("MCV found trash like as after tests")
            self.print_resources(result_tag)
        try:
            LOG.debug("Try remove old cleanup's files")
            self.store.remove_outdated_files()
        except Exception:
            LOG.debug("Can't remove old cleanup's files")


    @staticmethod
    def print_resources(resources):
        LOG.info("Resources that have been found:")
        resource_table = prettytable.PrettyTable(["Resource", "Name"])
        for key in resources.iterkeys():
            if resources[key]:
                resource_table.add_row([key, ""])
                for name in resources[key]:
                    resource_table.add_row(["", name])
        resource_table.add_row(["", ""])
        resource_table.align = "l"
        print(resource_table)


    @staticmethod
    def compare_start_end_resources(start, end):
        LOG.debug("Start compare end-start resources")
        result = {}
        for key in end.iterkeys():
            result[key] = list(set(end[key]) - set(start[key]))
        return result

    def compare_yaml_resources(self, path):
        current_resources = self._get_list_of_resources()
        old_resources = self.store.read(path)
        mcv_resources = self.compare_start_end_resources(old_resources,
                                                         current_resources)
        result_tag, result = self._filter_by_tags(mcv_resources)
        if [i for i in result.values() if i]:
            LOG.info("MCV found new resources")
            self.print_resources(result)
        if [i for i in result_tag.values() if i]:
            LOG.info("MCV found trash like as after tests")
            self.print_resources(result_tag)
        try:
            LOG.debug("Try remove old cleanup's files")
            self.store.remove_outdated_files()
        except Exception:
            LOG.debug("Can't remove old cleanup's files")


class Store(object):
    def __init__(self, conf, path=config.CLEANUP_FILES_PATH):
        self.path = path
        time_now = datetime.utcnow().strftime('%Y_%m_%d_%H:%M')
        self.file_name = os.path.join(self.path, 'cleanup_%s.yaml' % time_now)
        self.days = GET(conf, 'days', 'cleanup', default=30, convert=int)
        self.cleanup_age_limit = GET(conf, 'days',
                                     'cleanup',config.CLEANUP_AGE_LIMIT,
                                      convert=int)


    def save(self, data):
        with open(self.file_name, 'w') as fp:
            yaml.dump(data, stream=fp, default_flow_style=False)

    def read(self, path):
        try:
            with open(path) as f:
                data = yaml.load(f.read())
        except Exception:
            raise exceptions.ReadOutdatedFileError(
                "Can't read resources from file: %s" % path)
        return data

    def remove_outdated_files(self):
        now = time.time()
        cutoff = now - (self.days * self.cleanup_age_limit)
        files = os.listdir(self.path)
        for f in files:
            path = os.path.join(self.path, f)
            if os.path.isfile(path):
                t = os.stat(path)
                c = t.st_ctime
                if c < cutoff:
                    os.remove(path)
