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

import os.path

from jinja2 import Environment
from jinja2 import FileSystemLoader

from logger import LOG
from common.config import DEBUG

LOG = LOG.getLogger(__name__)


class Reporter(object):

    def __init__(self, tpl_dir):

        if not os.path.isdir(tpl_dir):
            raise IOError('Folder "{fld}" does not exist!'.format(fld=tpl_dir))

        self.init_environment(tpl_dir)

    def init_environment(self, tpl_dir):
        """Initialize Jinja2 environment."""

        self.env = Environment(
            autoescape=False,
            loader=FileSystemLoader(tpl_dir),
            trim_blocks=False,
            auto_reload=DEBUG)

    def render(self, template, context={}):
        """Renders Jinja2 template with provided context."""

        return self.env.get_template(template).render(context)

    def save_report(self, outfile, template, context={}):
        """Renders Jinja2 template and save it into file."""

        report = self.render(template, context)

        try:
            fp = open(outfile, 'w')
            fp.write(report)
            fp.close()
        except IOError as e:
            LOG.error('Cannot store report at filesystem: {err_msg}.'.format(
                err_msg=str(e)))
            LOG.debug('Report is shown below:\n')
            LOG.debug(report)
