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
import six
import traceback
import yaml

from oslo_config import cfg

from mcv_consoler.common import config as mcv_config
from mcv_consoler import exceptions
from mcv_consoler import utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


@six.add_metaclass(utils.Singleton)
class Quotas(object):

    def __init__(self, ctx):
        self.tenant_id = ctx.access.keystone.session.get_project_id()
        self.neutron = NeutronQuotas(self.tenant_id, ctx)
        self.start_quotas = self._get_save_quotas()

    def _get_save_quotas(self):
        data = {
            'neutron': self.neutron.start_neutron_quota,
        }

        time_now = datetime.utcnow().strftime('%Y_%m_%d_%H:%M')
        file_name = os.path.join(mcv_config.QUOTAS_FILES_PATH,
                                 'quotas_%s.yaml' % time_now)
        with open(file_name, 'w') as fp:
            yaml.dump(data, stream=fp, default_flow_style=False)
        return data


class NeutronQuotas(object):
    def __init__(self, tenant_id, ctx):
        self.neutron = ctx.access.neutron
        self.tenant_id = tenant_id
        self.start_neutron_quota = self._show_quota()
        self.set_default_quotas = True

    def _show_quota(self):
        try:
            quotas = self.neutron.show_quota(self.tenant_id)
        except Exception:
            LOG.error(traceback.format_exc())
            raise exceptions.OpenStackResourceAccessError(
                "Can't get neutron's quotas")
        return quotas

    def set_neutron_unlimit_quotas(self):
        if self.set_default_quotas:
            try:
                self.neutron.update_quota(
                    self.tenant_id,
                    body={'quota': mcv_config.NEUTRON_QUOTAS})
                self.set_default_quotas = False
                LOG.debug('Set unlimited quotas for Neutron')
            except Exception:
                LOG.error(traceback.format_exc())
                raise exceptions.UpdateQuotasError(
                    "Can't set unlimit quotas")
        else:
            LOG.debug('Unlimited quotas has been already set')

    def set_start_quota(self):
        if not self.set_default_quotas:
            try:
                self.neutron.update_quota(
                    self.tenant_id,
                    body={'quota': self.start_neutron_quota['quota']})
                self.set_default_quotas = True
                LOG.debug('Set starting quotas for Neutron')
            except Exception:
                LOG.error(traceback.format_exc())
                raise exceptions.UpdateQuotasError(
                    "Can't set starting quotas")
        else:
            LOG.debug('Default quotas has been already set')
