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

import logging

import re
from ConfigParser import NoSectionError, NoOptionError


LOG = logging.getLogger(__name__)

_custom_group_prefix = 'custom_test_group_'

# Look for a pair of tests that are not separated by ','
# Name of a test should not start with '#'
RE_TESTS_WITHOUT_COMMA = '([^#^\s^,]+\s+[^,]+[^\s^,]+)'

# case when two *.yaml scenarios stuck together, e.g. first.yamlsecond.yaml
# Test should not start with '#'
RE_YAMLS_WITHOUT_COMMA = '([^#^\s^,]+\.yaml[^\s^,]+\.yaml)'


# A hardcoded list of config options required by each particular scenario
all_require = (
    'basic.instance_ip',
)

auth_require = (
    'auth.auth_fqdn',
    'auth.os_username',
    'auth.os_password',
    'auth.region_name',
    'auth.os_tenant_name',
    'auth.auth_endpoint_ip',
)

required_by_runner = {
    'ostf': (
        'ostf.runner',
        'auth.auth_fqdn',
        'basic.mos_version',
        'fuel.cluster_id',
        'fuel.nailgun_host',
    ),
    'shaker': (
        'shaker.runner',
        'shaker.timeout',
    ),
    'speed': (
        'speed.runner',
    ),
    'nwspeed': (
        'nwspeed.runner',
    ),
    'resources': (
        'resources.runner',
    ),
    'rally': (
        'rally.runner',
        'rally.concurrency',
        'rally.gre_enabled',
        'rally.vlan_amount',
    ),
    'certification': (
        'certification.tenants_amount',
        'certification.users_amount',
        'certification.storage_amount',
        'certification.computes_amount',
        'certification.controllers_amount',
        'certification.network_amount',
        'certification.services',
    ),
    'workload': (
        'workload.concurrency',
        'workload.instance_count',
        'workload.file_size',
        'workload.workers_count',
        'basic.mos_version',
    ),
    'tempest': (
        'tempest.runner',
    ),
    # this does not depend on 'all_require' and 'auth_require'
    'selfcheck': (
        'selfcheck.runner',
    ),
}


class ConfigValidator(object):
    """ Validate options needed to run a particular test scenario. Also
    checks a lis of scenario tests for the wrong syntax and missing commas
    """
    _scenarios = 'single', 'group', 'full', 'name'
    _runners = required_by_runner.keys()

    t_missing = " - [{opt}] is required"
    t_missing_tool = " - [{opt}] is required for running '{tool}' tests"
    t_no_section = "Error: Section '[{sec}]' is missing in configuration file"
    t_missing_header = "Error: Configuration file {conf} is missing " \
                       "one(or several) required options: "

    def __init__(self, config, run_args):
        self.config = config
        self.args = run_args
        self.errors = list()
        self.missing = list()
        self._verified = set()
        self.conf_path = getattr(config, '_conf_path')
        self.line_printer = ConfLinePrettyPrinter(self.conf_path)

    @property
    def status(self):
        return len(self.errors + self.missing) == 0

    @property
    def custom_groups(self):
        if hasattr(self, '_custom'):
            return getattr(self, '_custom')
        ss, p = list(), _custom_group_prefix
        for s in self.config.sections():
            if s.startswith(p):
                ss.append(s.split(p)[-1])
        setattr(self, '_custom', tuple(ss))
        return getattr(self, '_custom')

    def get_section_items(self, section):
        try:
            return self.config.items(section)
        except NoSectionError:
            key = section,
            if key not in self._verified:
                self.errors.append(self.t_no_section.format(sec=section))
                self._verified.add(key)
            return list()

    def get_custom_section_items(self, name):
        key = _custom_group_prefix + name
        return self.get_section_items(key)

    def get_opt(self, section, option):
        try:
            return self.config.get(section, option)
        except NoSectionError:
            key = section,
            if key not in self._verified:
                self.errors.append(self.t_no_section.format(sec=section))
                self._verified.add(key)
        except NoOptionError:
            return None

    def get_simple(self, simple_name):
        """
        :param simple_name: section and option separated by '.'
        Example: 'basic.instance_ip'
        """
        section, option = simple_name.split('.', 1)
        return self.get_opt(section, option)

    def validate(self):
        scenario, group, runner = self.split_args()
        if self.errors:
            return self.status
        if scenario == 'single':
            self.check_runner(runner)
        elif scenario == 'group':
            self.check_config_strusture(group)
            self.check_custom_group(group)
        elif scenario == 'full':
            LOG.debug("Config validation for scenario '%s' is "
                      "not implemented" % scenario)
        return self.status

    def check_custom_group(self, custom_group):
        items = self.get_custom_section_items(custom_group)
        for runner, _ in items:
            if runner not in self._runners:
                continue
            self.check_runner(runner)

    def check_runner(self, runner):
        if runner not in self._runners:
            return self.errors.append('Error: Runner not found: %s' % runner)

        if runner == 'selfcheck':
            # selfcheck tests don't depend on 'all_require'
            self.check_items(runner, *required_by_runner[runner])
        else:
            self.check_items(None, *all_require)
            self.check_items(None, *auth_require)
            self.check_items(runner, *required_by_runner[runner])

    def check_items(self, tool=None, *items):
        for opt_name in items:
            if opt_name in self._verified:
                continue
            self._verified.add(opt_name)
            if self.get_simple(opt_name):
                continue
            # no, there is no such option, or it's empty
            if tool is None:
                template = self.t_missing
            else:
                template = self.t_missing_tool
            self.missing.append(template.format(opt=opt_name, tool=tool))

    def check_config_strusture(self, group):
        section_opts = self.get_custom_section_items(group)
        if not section_opts:
            return
        for tool, tests in section_opts:
            if tool not in self._runners:
                continue
            no_comma = re.findall(RE_TESTS_WITHOUT_COMMA, tests)
            bad_yamls = re.findall(RE_YAMLS_WITHOUT_COMMA, tests)
            for t in no_comma + bad_yamls:
                msg = self.line_printer.get_pretty(t)
                LOG.warning('Warning: ' + msg)

    def split_args(self):
        group = runner = None
        scenario = self.args[0]

        if scenario not in self._scenarios:
            expected = ', '.join(self._scenarios)
            self.errors.append("Error: incorrect test scenario '%s'. "
                               "Expected one of: %s" % (scenario, expected))
        elif scenario == 'single':
            runner = self.args[1]
        elif scenario == 'group':
            group = self.args[1]
        return scenario, group, runner

    def format_errors(self):
        for err_msg in self.errors:
            LOG.error(err_msg)
        if self.missing:
            LOG.error(self.t_missing_header.format(conf=self.conf_path))
        for msg in self.missing:
            LOG.warning(msg)


class ConfLinePrettyPrinter(object):

    pretty_msg = 'File {fname} [line {line}]\n\t{text}'
    default_hint_msg = "(this doesn't look like a valid test name. " \
                       "You might missed a comma)"

    def __init__(self, file_path):
        self.file_path = file_path

    @property
    def raw_file(self):
        """
        Stores a content of configuration file as a text.
        Do not read a whole config, unless needed
        """
        if hasattr(self, '_raw'):
            return getattr(self, '_raw')
        with open(self.file_path) as f:
            setattr(self, '_raw', f.read())
        return getattr(self, '_raw')

    def get_short(self, text):
        n = self._get_line_number(text)
        if n is None:
            return
        return 'File %s [line %s]' % (self.file_path, n)

    def get_pretty(self, text, hint=None, sep='\n'):
        """
        :param text: a piece of text to search in a file
        :param hint: optional. Put '' (empty string) to disable hint message
        :param sep: used to format a hint message

        Always returns string.
        If provided text was found in a file - returns a formatted message
        including a path to file and number of line where test located.
        Message is trailed by a hint (if provided)

        Returns the original text if didn't find anything
        """
        if hint is None:
            hint = self.default_hint_msg
        n = self._get_line_number(text)
        if n is None:
            return repr(text)
        res = self.pretty_msg.format(fname=self.file_path, line=n,
                                     text=repr(text))
        if hint != '':
            res = '{res}{sep}{hint}{sep}'.format(res=res, sep=sep, hint=hint)
        return res

    def _get_line_number(self, t):
        if '\\' in t:
            t = t.replace('\\', '\\\\')
        if '.' in t:
            t = t.replace('.', '\.')
        if '\n' in t:
            t = t.replace('\n', '\s+')
        res = re.search(t, self.raw_file)
        if res is None:
            return
        position = res.start()
        line_num = self.raw_file[:position].count('\n') + 1
        return line_num


def validate_conf(config, run_args):
    cv = ConfigValidator(config, run_args)
    LOG.debug('Validating config: %s' % cv.conf_path)
    cv.validate()
    all_good = cv.status
    if all_good:
        LOG.debug('Config looks fine')
    else:
        cv.format_errors()
    return all_good








