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

import weakref


def add(ctx, field, value):
    setattr(ctx, field, value)


def is_part_of_context(ctx, field):
    return field in vars(ctx)


class Context(object):
    def __init__(self, parent, **payload):
        _self[self] = _ContextSelf(parent)
        for attr in payload:
            setattr(self, attr, payload[attr])

    def __getattr__(self, attr):
        data = _self[self]
        if data.parent is None:
            raise AttributeError('Context have no field {!r}'.format(attr))
        return getattr(data.parent, attr)


class _ContextSelf(object):
    def __init__(self, parent):
        self.parent = parent


_self = weakref.WeakKeyDictionary()
