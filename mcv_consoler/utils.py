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
import itertools
import logging
import os
import re
import signal
import subprocess

from mcv_consoler import exceptions

LOG = logging.getLogger(__name__)

warnings = ('SNIMissingWarning',
            'InsecurePlatformWarning',
            'InsecureRequestWarning')


def ignore_sigint():
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def run_cmd(cmd, quiet=False):
    LOG.debug('Executing command: "%s"' % cmd)
    try:
        result = subprocess.check_output(cmd,
                                         shell=True,
                                         stderr=subprocess.STDOUT,
                                         preexec_fn=ignore_sigint)
    except subprocess.CalledProcessError as e:
        LOG.debug('ERROR: %s' % e.output)
        raise
    result = re.sub(r'/usr/local/.*(%s).*\n' % "|".join(warnings), '', result)
    result = re.sub(r'  (%s).*\n' % "|".join(warnings), '', result)
    quiet or LOG.debug('RESULT: "%s"' % result)
    return result


class WorkDir(object):
    _idx = itertools.count()
    RES_OS_SSH_KEY = next(_idx)
    RES_OS_OPENRC = next(_idx)
    RES__LAST = RES_FUELCLIENT_SETTINGS = next(_idx)
    del _idx

    _resource_map = {
        RES_OS_SSH_KEY: 'os-node.ssh.key',
        RES_OS_OPENRC: 'operc.sh',
        RES_FUELCLIENT_SETTINGS: 'fuelclient-settings.yaml'}

    def __init__(self, path, parent=None):
        self.base_dir = path
        self.parent = parent

        res_map, default = {}, {}
        for cls in reversed(type(self).__mro__):
            res_map.update(vars(cls).get('_resource_map', default))
        self._resource_map = res_map

    def resource(self, resource, lookup=True):
        try:
            suffix = self._resource_map[resource]
        except KeyError:
            raise exceptions.UnknownFileResourceError(
                'There is no resource {!r} into {!r}'.format(resource, self))
        return self.path(suffix, lookup)

    def path(self, suffix, lookup=True):
        path = os.path.join(self.base_dir, suffix)
        if not lookup:
            return path

        try:
            os.stat(path)
        except OSError:
            if not self.parent:
                raise exceptions.FileResourceNotFoundError(
                    'File lookup failed: {}'.format(suffix, [self.base_dir]))

            try:
                path = self.parent.path(suffix, lookup=lookup)
            except exceptions.FileResourceNotFoundError as e:
                e.args[1].insert(0, self.base_dir)
                raise

        return path


class TokenFactory(object):
    _token = None

    def __init__(self, auth, connect, obsolescence_boundary=600):
        self.auth = auth
        self.connect = connect
        self.obsolescence_boundary = datetime.timedelta(
            seconds=obsolescence_boundary)
        # force token allocate on first query
        self._etime = (datetime.datetime.utcnow() -
                       datetime.timedelta(seconds=1))

    def __call__(self):
        now = datetime.datetime.utcnow()
        if self._etime < now + self.obsolescence_boundary:
            self._allocate(now)
        return self._token

    def __str__(self):
        return self()

    def __unicode__(self):
        return self().decode('ascii')

    def _allocate(self, now):
        auth = {
            'username': self.auth['username'],
            'password': self.auth['password']}
        auth = {
            'tenantName': self.auth['tenant_name'],
            'passwordCredentials': auth}
        auth = {'auth': auth}
        auth = json.dumps(auth)

        cmd = (
            'curl --insecure --silent '
            '--header "Content-type: application/json" '
            '--data \'{payload}\' '
            '{url_base}/tokens'
        ).format(
            payload=auth,
            url_base=self.auth['public_auth_url'].rstrip('/'))

        try:
            proc = self.connect.exec_cmd(cmd, exc=True)
            payload = json.loads(proc.stdout)
            self._token = payload['access']['token']['id']
            expires = payload['access']['token']['expires']
            expires = datetime.datetime.strptime(expires, '%Y-%m-%dT%H:%M:%SZ')
        except (KeyError, ValueError, TypeError, exceptions.RemoteError) as e:
            raise exceptions.AccessError(
                'Unable to allocate OpenStack auth token: {}'.format(e))
        self._etime = expires


class TimeTrack(object):
    def __init__(self):
        self.metrics = {}

    def record(self, name=None):
        self.metrics[name] = m = TimeMetric()
        return m

    def query(self, name):
        try:
            m = self.metrics[name]
        except KeyError:
            raise exceptions.MissingDataError(
                'There is no time metric named {!r}'.format(name))
        return m


class TimeMetric(object):
    def __init__(self):
        self.start = self.end = self.value = None

    def __enter__(self):
        self.start = datetime.datetime.utcnow()
        return self

    def __exit__(self, *exc_info):
        self.end = datetime.datetime.utcnow()
        self.value = self.end - self.start


class LazyAttributeMixin(object):
    def lazy_attribute_handler(self, target):
        raise NotImplementedError


class LazyAttribute(object):
    name = None

    def __init__(self, target=None):
        self.target = target

    def __get__(self, instance, owner):
        if instance is None:
            return self

        self._detect_name(owner)

        target = self.target
        if target is None:
            target = self.name
        handler = instance.lazy_attribute_handler(target)

        setattr(instance, self.name, handler)

        return handler

    def _detect_name(self, owner):
        if self.name is not None:
            return

        for name in dir(owner):
            if getattr(owner, name) is not self:
                continue
            break
        else:
            raise TypeError(
                'Unable to detect descriptor name (class={!r} '
                'descriptor={!r})'.format(owner, self))

        self.name = name

    def __repr__(self):
        return '<{}(name={}, target={})>'.format(
            type(self), self.name, self.target)


class DummyContextWrapper(object):
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        pass
