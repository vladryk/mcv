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

import logging
import os
import prettytable
import time
import traceback
import yaml
from copy import deepcopy
from datetime import datetime
from collections import namedtuple
from collections import OrderedDict

from oslo_config import cfg

from mcv_consoler.common import config
from mcv_consoler import exceptions

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

Resource = namedtuple('Resource', ('name', 'id'))
Removing_Resources = (
        ('heat', (('stacks', ''),)),
        ('nova', (('servers', ''), ('keypairs', ''), ('security_groups', ''), ('flavors', ''))),
        ('neutron', (('routers', 'delete_router'), ('networks', 'delete_network'))),
        ('cinder', (('volume_snapshots',), ('volumes',))),
        ('glance', (('images', ''),)),
        ('keystone', (('users', ''), ('tenants', '')))
    )


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
            # try:
            #     resources['users'] = [
            #         i.name for i in keystone.users.findall()]
            #     resources['tenants'] = [
            #         i.name for i in keystone.tenants.findall()]
            # except Exception:
            #     LOG.warning("Can't get resources from Keystone")

            resources['flavors'] = [
                Resource(i.name or i.id, i.id) for i in nova.flavors.findall()]

            resources['servers'] = [
                Resource(i.name or i.id, i.id) for i in nova.servers.findall()]

            resources['keypairs'] = [
                Resource(i.name or i.id, i.id) for i in nova.keypairs.findall()]

            resources['security_groups'] = [
                Resource(i.name or i.id, i.id) for i in nova.security_groups.findall()]

            #
            # resources['volumes'] = [
            #     i.name or i.id for i in cinder.volumes.findall()]
            # resources['volume_snapshots'] = [
            #     i.name or i.id for i in cinder.volume_snapshots.findall()]
            #
            # resources['images'] = [
            #     i.name for i in glance.images.findall()]
            #
            # resources['routers'] = [
            #     i['name'] for i in neutron.list_routers()['routers']]
            # resources['networks'] = [
            #     i['name'] for i in neutron.list_networks()['networks']]
            #
            # resources['stacks'] = [
            #     i.stack_name for i in heat.stacks.list()]

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
            for obj in resources[resource]:
                for t in tags:
                    if t in obj.name:
                        set_result_tag.add(obj)
                        break
                else:
                    set_result.add(obj)
            result_tag[resource] = list(set_result_tag)
            result[resource] = list(set_result)
        return result_tag, result

    @staticmethod
    def _namedtuple_to_tuple(data):
        for key in data:
            for pos in range(len(data[key])):
                data[key][pos] = tuple(data[key][pos])
        return data

    @staticmethod
    def _tuple_to_namedtuple(data):
        for key in data:
            for pos in range(len(data[key])):
                data[key][pos] = Resource(*data[key][pos])
        return data

    def get_started_resources(self):
        self.started_resources = self._get_list_of_resources()
        data_to_save = self._namedtuple_to_tuple(
            deepcopy(self.started_resources))
        self.store.save(data_to_save)
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
                for obj in resources[key]:
                    resource_table.add_row(["", obj.name])
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
        old_resources = self._tuple_to_namedtuple(self.store.read(path))
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

    def find_show_resources(self):
        if self.ctx.args.remove_trash is None:
            LOG.debug("Try find and save resources. "
                      "self.ctx.args.remove_trash == {}".format(
                        self.ctx.args.remove_trash))
            self.find_save_resources()
        else:
            LOG.debug("Try remove resources. "
                      "self.ctx.args.remove_trash == {}".format(
                        self.ctx.args.remove_trash))
            self._removing_trash(self.ctx.args.remove_trash)

    def find_save_resources(self):
        path = os.path.join(config.CLEANUP_FILES_PATH, 'cleanup.yaml')
        resources = self._get_list_of_resources()
        result_tag, result = self._filter_by_tags(resources)
        if CONF.cleanup.exclude_filter:
            result_tag = self._exclude_filter(result_tag)
        self.store.save(result_tag, path=path)
        if [i for i in result_tag.values() if i]:
            LOG.info("Resources below can be removed. You can change it in {}. "
                     "For removing resources - use this file".format(path))
            self.print_resources(result_tag)
        else:
            LOG.info("Trash hasn't been found" )

    @staticmethod
    def _exclude_filter(resources):
        data = {}
        for resource in resources:
            resources_set = set()
            for obj in resources[resource]:
                for exclude_name in config.EXCLUDE_RESOURCES:
                    if obj.name != exclude_name:
                        resources_set.add(obj)
            data[resource] = list(resources_set)
        return data

    def _removing_trash(self, path):
        resources = self._tuple_to_namedtuple(self.store.read(path))
        LOG.debug('Start removing of resources')
        for name_resource in Removing_Resources:
            name, _tuple = name_resource
            client = getattr(self.ctx.access, name)
            LOG.debug('Use {} - client for removing'.format(name))
            for i in _tuple:
                resource = getattr(client, i[0], client)
                LOG.debug('Use {} - resource for removing'.format(resource))
                remove = getattr(resource, i[1], 'delete')
                for obj in resources[i[0]]:
                    LOG.debug('Try remove: {}, {} '.format(obj.name, obj.id))
                    remove(obj.id)
                    time.sleep(1)



class Store(object):
    def __init__(self, path=config.CLEANUP_FILES_PATH):
        self.path = path
        time_now = datetime.utcnow().strftime('%Y_%m_%d_%H:%M')
        self.file_name = os.path.join(self.path, 'cleanup_%s.yaml' % time_now)
        self.cleanup_age_limit = CONF.cleanup.days * config.CLEANUP_AGE_LIMIT

    def save(self, data, path=None):
        file_name = path or self.file_name
        with open(file_name, 'w') as fp:
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
