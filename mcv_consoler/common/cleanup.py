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

from datetime import datetime
import logging
import os
import prettytable
import time
import traceback
import yaml

from oslo_config import cfg

from mcv_consoler.common import config
from mcv_consoler import exceptions

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class Cleanup(object):
    def __init__(self, ctx):
        self.ctx = ctx
        self.store = Store()
        self.started_resources = None
        self.finished_resources = None

    def _get_list_of_resources(self):
        keystone = self.ctx.access.keystone
        nova = self.ctx.access.nova
        cinder = self.ctx.access.cinder
        glance = self.ctx.access.glance
        neutron = self.ctx.access.neutron
        heat = self.ctx.access.heat

        resources = {}
        try:
            # TODO(vokhrimenko): Need remove try-except after fix MCV-834
            try:
                resources['users'] = [
                    i.name for i in keystone.users.findall()]
                resources['projects'] = [
                    i.name for i in keystone.tenants.findall()]
            except Exception:
                LOG.warning("Can't get resources from Keystone")

            resources['flavors'] = [
                i.name for i in nova.flavors.findall()]
            resources['servers'] = [
                i.name for i in nova.servers.findall()]
            resources['keypairs'] = [
                i.name for i in nova.keypairs.findall()]
            resources['security_groups'] = [
                i.name for i in nova.security_groups.findall()]

            resources['volumes'] = [
                i.name or i.id for i in cinder.volumes.findall()]
            resources['volume_snapshots'] = [
                i.name or i.id for i in cinder.volume_snapshots.findall()]

            resources['images'] = [
                i.name for i in glance.images.findall()]

            resources['routers'] = [
                i['name'] for i in neutron.list_routers()['routers']]
            resources['networks'] = [
                i['name'] for i in neutron.list_networks()['networks']]

            resources['stacks'] = [
                i.stack_name for i in heat.stacks.list()]

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
        mcv_resources = self.compare_start_end_resources(
            self.started_resources, self.finished_resources)
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
    def __init__(self, path=config.CLEANUP_FILES_PATH):
        self.path = path
        time_now = datetime.utcnow().strftime('%Y_%m_%d_%H:%M')
        self.file_name = os.path.join(self.path, 'cleanup_%s.yaml' % time_now)
        self.cleanup_age_limit = CONF.cleanup.days * config.CLEANUP_AGE_LIMIT

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
        cutoff = now - self.cleanup_age_limit
        files = os.listdir(self.path)
        for f in files:
            path = os.path.join(self.path, f)
            if os.path.isfile(path):
                t = os.stat(path)
                c = t.st_ctime
                if c < cutoff:
                    os.remove(path)


class CleanUpWrapper(object):
    def __init__(self, ctx):
        self.clean_ctrl = Cleanup(ctx)

    def __enter__(self):
        self.clean_ctrl.get_started_resources()
        return self

    def __exit__(self, *exc_info):
        self.clean_ctrl.get_finished_resources()
