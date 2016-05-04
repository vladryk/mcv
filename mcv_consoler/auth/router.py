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


from mcv_consoler.common.config import DEBUG
from mcv_consoler.utils import GET


class Router(object):
    """Defines base class for Routing."""
    pass


class IRouter(Router):

    def __init__(self, **kwargs):
        super(Router, self).__init__()
        self.config = kwargs["config"]

    def get_os_data(self):
        """Extract OS data from configuration file."""

        protocol = GET(self.config, 'auth_protocol')
        endpoint_ip = GET(self.config, 'auth_endpoint_ip')
        auth_url_tpl = '{hprot}://{ip}:{port}/v{version}'
        tenant_name = GET(self.config, 'os_tenant_name')
        password = GET(self.config, 'os_password')
        insecure = (protocol == "https")
        nailgun_port = 8443 if insecure else 8000

        os_data = {'username': GET(self.config, 'os_username'),
                   'password': password,
                   'tenant_name': tenant_name,
                   'auth_fqdn': GET(self.config, 'auth_fqdn'),

                   'ips': {
                       'controller': GET(self.config, 'controller_ip'),
                       'endpoint': endpoint_ip,
                       'instance': GET(self.config, 'instance_ip')},

                   'fuel': {
                       'nailgun_host': GET(self.config, 'nailgun_host'),
                       'nailgun_port': nailgun_port,
                       'cluster_id': GET(self.config, 'cluster_id')},

                   'auth_url': auth_url_tpl.format(hprot=protocol,
                                                   ip=endpoint_ip,
                                                   port=5000,
                                                   version="2.0"),
                   'insecure': insecure,
                   'region_name': GET(self.config, 'region_name'),
                   # nova tenant
                   'project_id': tenant_name,
                   # nova and cinder passwd
                   'api_key': password,
                   'debug': DEBUG
                   }

        return os_data
