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
import time

import novaclient.exceptions

from mcv_consoler.common import resource
from mcv_consoler.common import ssh
from mcv_consoler import exceptions
from mcv_consoler.plugins.speed import config
from mcv_consoler import utils

LOG = logging.getLogger(__name__)


class Allocator(object):
    """Class it aimed to act as a helper for speed plugin runner.

    It allocate resources and guarantee that this resources will be freed at
    the end. Despite any errors or exceptions.

    Main goal - create N VM, one on each compute host. Other resources
    required to create this VMs. Number of VMs can be less than number of
    compute hosts(controlled by nodes_limit argument). In this case it will
    sort existing compute hosts by their hostnames and use first N hosts.
    """

    def __init__(
            self, ctx, flavor, availability_zone, tool_vm_image, network,
            floating_net, nodes_limit=0):
        super(Allocator, self).__init__()
        self.ctx = ctx

        self.minimal_flavor = OSFlavor.new_from_requirements(flavor)
        self.availability_zone = availability_zone
        self.tool_vm_image = tool_vm_image
        self.network = network
        self.floating_network = floating_net
        self.nodes_limit = nodes_limit

        self.target_vms = []

        self.resource_pool = resource.Pool()
        # variable to handle exceptions during resource allocation
        self.error_during_allocation = False

    def __enter__(self):
        try:
            self._allocate()
        except Exception as e:
            LOG.error("Unhandled exception '%s' appeared during resource "
                      "allocating. Please inspect logs for more details. "
                      "All tests from this group will be skipped. ", e)
            self.resource_pool.terminate()
            self.error_during_allocation = True

        return self

    # noinspection PyUnusedLocal
    def __exit__(self, *exc_info):
        self.resource_pool.terminate()

    def _allocate(self):
        vm_image = self._upload_vm_image()
        flavor = self._create_os_flavor()
        keypair = self._create_os_keypair()
        secgroup = self._create_os_secgroup()
        network = self._lookup_network(self.network)
        network_ext = self._lookup_network(self.floating_network)
        computes = self._lookup_computes()

        nova = self.ctx.access.nova

        LOG.debug(
            'Going to boot %d VMs (image: %s)', len(computes), vm_image.name)

        vms = {}
        for host in computes:
            zone = ':'.join((self.availability_zone, host.host_name))
            vm_details = nova.servers.create(
                name=config.tool_vm_name,
                image=vm_image.id, flavor=flavor.id,
                key_name=keypair.name, availability_zone=zone,
                security_groups=[secgroup['name']],
                nics=[{'net-id': network.id}])
            vms[vm_details.id] = vm_details

        vms_ok, vms_fail = self._wait_for_vms(vms)
        vms_ok, vms_fail_floating, floating_ips = self._assign_floating_ips(
            vms_ok, network_ext)

        vms_fail.update(vms_fail_floating)
        for vm in vms_fail.values():
            nova.servers.delete(vm)
        for vm in vms_ok.values():
            self.resource_pool.add(resource.OSObjectResource(vm), True)
        for vm, addr in floating_ips.iteritems():
            self.resource_pool.add(resource.OSFloatingIPResource(
                addr, vm, self.ctx.access.neutron), True)
        if not vms_ok:
            raise exceptions.AccessError('There is no any usable compute host')

        self.target_vms[:] = vms_ok.values()

    def _upload_vm_image(self):
        LOG.debug('Check is %s in glance', config.tool_vm_image_name)

        glance = self.ctx.access.glance

        image = glance.images.findall(name=config.tool_vm_image_name)
        if image:
            LOG.info('Image for speed tests VM already present in cloud')
            return image[0]

        LOG.info('Uploading image to glance...')
        # raise exception if image does not exist
        if not os.path.exists(self.tool_vm_image):
            raise exceptions.FileResourceNotFoundError(
                "Image %s not found" % self.tool_vm_image)

        with open(self.tool_vm_image, 'rb') as payload:
            vm_image = glance.images.create(
                name=config.tool_vm_image_name, data=payload,
                disk_format="qcow2", container_format="bare", is_public=True)
        self.resource_pool.add(resource.OSObjectResource(vm_image), True)
        return vm_image

    def _create_os_flavor(self):
        nova = self.ctx.access.nova

        for flavor in nova.flavors.list():
            os_flavor = OSFlavor.new_from_os(flavor)
            if os_flavor != self.minimal_flavor:
                continue

            LOG.debug('Use existing flavor: %s', os_flavor.identity)
            return flavor

        LOG.debug('No suitable flavor was found. Creating new one.')
        defaults = [
            config.flavor_min_ram,
            config.flavor_min_vcpus,
            config.flavor_min_disk]
        flavor_attrs = ('ram', 'vcpus', 'disk')
        create_args = []
        for default, flavor_attrs in zip(defaults, flavor_attrs):
            value = getattr(self.minimal_flavor, flavor_attrs)
            if value is None:
                value = default
            create_args.append(value)

        flavor = nova.flavors.create(config.flavor_name, *create_args)
        self.resource_pool.add(resource.OSObjectResource(flavor), True)
        return flavor

    def _create_os_keypair(self):
        nova = self.ctx.access.nova

        name = config.tool_vm_keypair_name
        for idx in range(2):
            try:
                keypair = nova.keypairs.create(name)
            except self.ctx.access.nova_exc.Conflict:
                LOG.debug('Remove existing(outdated) keypair "%s"', name)
                nova.keypairs.get(name).delete()
                continue
            break
        else:
            raise exceptions.FrameworkError('Unable to create keypair object')

        self.resource_pool.add(resource.OSObjectResource(keypair), True)

        work_dir = self.ctx.work_dir
        key_path = work_dir.resource(
            work_dir.RES_TOOL_VM_SSH_KEY, lookup=False)
        ssh.save_private_key(key_path, keypair.private_key)

        self.resource_pool.add(resource.FileResource(key_path), True)

        return keypair

    def _create_os_secgroup(self):
        neutron = self.ctx.access.neutron

        current_secgroups = neutron.list_security_groups()
        current_secgroups = current_secgroups['security_groups']
        for secgroup in current_secgroups:
            if secgroup['name'] != config.secgroup_name:
                continue
            break
        else:
            payload = {'name': config.secgroup_name}
            payload = {'security_group': payload}
            secgroup = neutron.create_security_group(payload)
            secgroup = secgroup['security_group']
            secgroup_killer = resource.OSSecGroupRemove(self.ctx)
            self.resource_pool.add(
                resource.CallOnReleaseResource(secgroup, secgroup_killer),
                True)

            payload = {
                'direction': 'ingress',
                'protocol': 'tcp', 'port_range_max': 22, 'port_range_min': 22,
                'ethertype': 'IPv4',
                'security_group_id': secgroup['id']}
            payload = {'security_group_rule': payload}
            neutron.create_security_group_rule(payload)

        return secgroup

    def _lookup_network(self, name):
        try:
            network = self.ctx.access.nova.networks.find(label=name)
        except novaclient.exceptions.NotFound:
            raise exceptions.ConfigurationError(
                'There is no network {!r} in cloud'.format(name))
        return network

    def _lookup_computes(self):
        nova = self.ctx.access.nova

        computes = []
        for host in nova.hosts.list(zone=self.availability_zone):
            if host.service != 'compute':
                continue
            # FIXME(dobgun): check host status
            computes.append(host)

        if self.nodes_limit:
            total = len(computes)
            computes.sort(key=lambda x: x.host_name)
            computes = computes[:self.nodes_limit]
            LOG.debug(
                'Limit number of used compute hosts to %s (total %s)',
                len(computes), total)

        if not computes:
            raise exceptions.AccessError(
                'There is no any compute node in cloud.')

        return computes

    def _wait_for_vms(self, vms_all, sleep_time=10):
        nova = self.ctx.access.nova

        time_start = iteration_start = time.time()
        idx = 0
        fail, ok, wait = set(), set(), set(vms_all)
        while wait:
            if idx:
                sleep = iteration_start + sleep_time
                sleep -= time.time()
                sleep = max(sleep, 0)
                time.sleep(sleep)

            iteration_start = time.time()
            idx += 1

            LOG.debug(
                'Wait for %d VMs to become available (iteration %d)',
                len(wait), idx)

            for idnr in wait:
                try:
                    vm = nova.servers.get(idnr)
                except novaclient.exceptions.NotFound:
                    LOG.error(
                        'Created VM have been disappeared. vm.id=%s', idnr)
                    fail.add(idnr)
                    continue

                LOG.debug('VM %s status is %s' % (idnr, vm.status))

                boot_time = time.time() - time_start
                if vm.status == 'BUILD':
                    if config.tool_vm_create_tout < boot_time:
                        LOG.debug(
                            'VM %s is too long in BUILD state, mark it as'
                            ' failed', idnr)
                        fail.add(idnr)
                elif vm.status == 'ERROR':
                    fail.add(idnr)
                    LOG.warning('VM %s is failed to start', idnr)
                    LOG.warning(
                        'Skipping compute node %s', getattr(
                            vm, 'OS-EXT-SRV-ATTR:host'))
                    LOG.debug(
                        'You can check nova logs for more details about this '
                        'error.')
                elif vm.status != 'ACTIVE':
                    fail.add(idnr)
                    LOG.error('VM %s unexpected status %r', idnr, vm.status)
                else:
                    ok.add(idnr)

            wait -= ok
            wait -= fail

        ok = {x: vms_all[x] for x in ok}
        fail = {x: vms_all[x] for x in fail}
        return ok, fail

    def _assign_floating_ips(self, vms_all, network):
        access = self.ctx.access

        fail = set()
        floating_ips = dict()
        for vm in vms_all.values():
            try:
                # this try except catch EVERYTHING, be careful
                body = {"floatingip": {'floating_network_id': network.id}}
                addr = access.neutron.create_floatingip(body)
                ip_addr = addr['floatingip']['floating_ip_address']
                vm.add_floating_ip(ip_addr)
                floating_ips.update({vm: addr})
            except access.nova_exc.ClientException as e:
                # NOTE: This is not very accurate exception type.
                # ClientException is the top of exceptions hierarchy raised
                # by novaclient in case of unexpected http status code in
                # REST response.
                # But there are exception in novaclient defined outside of this
                # exceptions hierarchy. I believe that best solution - allow
                # them to raise, because they introduce serious problems in MCV
                # configuration or cloud state.
                LOG.error(
                    'VM %s can\'t create/assign floating ip: %s',
                    vm.id, str(e))
                fail.add(vm.id)

        vm_ok = {x: vms_all[x] for x in vms_all if x not in fail}
        vm_fail = {x: vms_all[x] for x in fail}
        return vm_ok, vm_fail, floating_ips


class OSFlavor(utils.ComparableMixin, object):
    vcpus = ram = disk = None
    idnr = None
    os_object = None

    _os_fields_map = {
        'idnr': 'id'}

    def __init__(self, payload):
        errors = set()
        for field in payload:
            if not field.startswith('_'):
                pass
            elif not hasattr(self, field):
                pass
            else:
                errors.add(field)
                continue

            setattr(self, field, payload[field])

        if errors:
            errors = sorted(errors)
            raise ValueError(
                'Invalid field(s): "{}"'.format('", "'.join(errors)))

    @classmethod
    def new_from_os(cls, obj):
        payload = {}
        for field in ('vcpus', 'ram', 'disk', 'idnr'):
            os_field = cls._os_fields_map.get(field, field)
            payload[field] = getattr(obj, os_field)
        payload['os_object'] = obj
        return cls(payload)

    @classmethod
    def new_from_requirements(cls, raw, field_sep=',', sep=':'):
        field_converters = {
            None: int}

        payload = {}
        errors = []
        for pair in raw.split(field_sep):
            pair = pair.strip()
            unpacked = pair.split(sep, 1)
            try:
                try:
                    field, value = [x.strip() for x in unpacked]
                except TypeError:
                    raise ValueError('Invalid field format'.format(pair))

                convert = field_converters.get(
                    field, field_converters[None])
                try:
                    value = convert(value)
                except (ValueError, TypeError) as e:
                    raise ValueError(
                        'Invalid field value: {}'.format(pair, e))
            except ValueError as e:
                errors.append('{} - {}'.format(pair, e))
                continue

            payload[field] = value

        if errors:
            raise ValueError(
                'Unable to parse flavor definition - {!r}:\n{}'.format(
                    raw, '\n'.join(errors)))

        return cls(payload)

    def get_field(self, field):
        os_field = self._os_fields_map.get(field, field)

        for obj, name in (
                (self, field),
                (self.os_object, os_field)):
            try:
                value = getattr(obj, name)
            except AttributeError:
                continue
            break
        else:
            raise AttributeError('There is no filed "{}" on {!r}'.format(
                field, self))

        return value

    @property
    def cmp_payload(self):
        return self.vcpus, self.ram, self.disk

    @property
    def identity(self):
        data = []
        for field in ('idnr', 'name', 'vcpus', 'ram', 'disk'):
            try:
                value = self.get_field(field)
                value = str(value)
            except AttributeError:
                continue
            data.append(':'.join((field, value)))
        return ','.join(data)
