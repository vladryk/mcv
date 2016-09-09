#    Copyright 2016 Mirantis, Inc
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

import errno
import os
import time
import weakref

from mcv_consoler import exceptions


class ResourceAbstract(object):
    is_alive = True

    def terminate(self, is_last_request):
        self.is_alive = False

    def kill(self):
        self.is_alive = False


class SubprocessResource(ResourceAbstract):
    _term_time = None

    def __init__(self, proc, term_tout=0, allow_kill=True):
        super(SubprocessResource, self).__init__()
        self.proc = proc
        self.terminate_tout = term_tout
        self.allow_kill = allow_kill

    def terminate(self, is_last_request):
        if not self._term_time:
            self.proc.terminate()
            self._term_time = time.time()

        if self.proc.poll() is not None:
            super(SubprocessResource, self).terminate(is_last_request)
            return

        if is_last_request:
            time_end = self._term_time + self.terminate_tout
            now = time.time()
            while now < time_end:
                if self.proc.poll() is not None:
                    break
                time.sleep(max(time_end - now, 0.5))
                now = time.time()
            else:
                raise exceptions.ResourceDestroyBlockCtrl

            super(SubprocessResource, self).terminate(is_last_request)

    def kill(self):
        if self.is_alive and self.allow_kill:
            try:
                self.proc.kill()
            except OSError as e:
                if e.errno != errno.ESRCH:
                    raise
        super(SubprocessResource, self).kill()


class ClosableResource(ResourceAbstract):
    def __init__(self, target):
        self.target = target

    def terminate(self, is_last_request):
        self._close()
        super(ClosableResource, self).terminate(is_last_request)

    def kill(self):
        self._close()
        super(ClosableResource, self).kill()

    def _close(self):
        if not self.is_alive:
            return
        self.target.close()


class FileResource(ResourceAbstract):
    def __init__(self, path, missing_ok=True):
        self.path = path
        self.missing_ok = missing_ok

    def terminate(self, is_last_request):
        try:
            os.unlink(self.path)
        except OSError as e:
            if not self.missing_ok or e.errno != errno.ENOENT:
                raise
        super(FileResource, self).terminate(is_last_request)


class OSObjectResource(ResourceAbstract):
    def __init__(self, target):
        self.target = target

    def terminate(self, is_last_request):
        self.target.delete()
        super(OSObjectResource, self).terminate(is_last_request)


class Pool(object):
    def __init__(self):
        self._space = []

    def add(self, resource, autonomous):
        if autonomous:
            ref = _HardLink(resource)
        else:
            ref = weakref.ref(resource)

        self._space.append(ref)

    def terminate(self, iterations=3):
        iterations = max(1, iterations)
        step = 0

        while step < iterations:
            step += 1

            time_slot = int(time.time() + 1)

            repeat = []
            while True:
                try:
                    ref, obj = self._pop()
                except IndexError:
                    break
                try:
                    obj.terminate(step + 1 == iterations)
                except exceptions.ResourceDestroyBlockCtrl:
                    repeat.append(ref)

            if repeat:
                self._space.extend(repeat)

                delay = time_slot - time.time()
                delay = max(delay, 0)

                time.sleep(delay)
                continue

            break

        else:
            self.kill()

    def kill(self):
        while True:
            try:
                ref, obj = self._pop()
            except IndexError:
                break

            obj.kill()

    def _pop(self):
        while True:
            ref = self._space.pop()

            obj = ref()
            if obj is None:
                continue
            if not obj.is_alive:
                continue

            return ref, obj


class _HardLink(object):
    def __init__(self, target):
        self.target = target

    def __call__(self):
        return self.target
