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
import shlex
import subprocess
import time

from mcv_consoler import utils


LOG = logging.getLogger(__name__)


class ProcessManager(object):
    """Manages subprocesses."""

    def __init__(self):
        self.processes = {}

    def run_standalone_process(self, cmd):
        """Executes 'cmd' command in shell and returns subprocess.poll().
        PID will also be stored within object instance for making a
        cleanup afterwards.
        If process was terminated, an error code will be returned.
        If process is alive, None will be returned.
        If 'cmd' is not of type of string, or process cannot be run,
        False will be returned."""

        if not isinstance(cmd, str):
            LOG.debug('Expected string, but {tp} found. Cannot execute command'
                      '"{cmd}"'.format(tp=str(type(cmd)), cmd=str(cmd)))
            return False

        try:
            # TODO(albartash): Do smth with printing and storing password
            # from sshpass!
            LOG.debug('Executing command: {cmd}'.format(cmd=cmd))

            proc = subprocess.Popen(shlex.split(cmd),
                                    shell=False,
                                    stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    preexec_fn=utils.ignore_sigint)

        except subprocess.CalledProcessError as e:
            LOG.debug('An error occured while running a process: '
                      '{msg}'.format(msg=str(e)))
            return False

        # NOTE(albartash): Sometimes proc.poll() won't return exit code but None even if
        # the process failed. We need a timer here.
        time.sleep(3)

        if proc.poll() is not None:
            LOG.debug('Process "{cmd}" has finished unexpectedly. Retcode = {code}.'.format(
                cmd=cmd, code=proc.poll()))
            return proc.poll()

        self.processes[proc.pid] = (proc, cmd)

        return proc.poll()

    def cleanup(self):
        """Terminates all processes started."""
        for pid in self.processes:
            try:
                LOG.debug('Terminating process: #{pid} of command "{cmd}" ...'.format(pid=pid,
                                                       cmd=self.processes[pid][1]
                                                       ))
                self.processes[pid][0].terminate()
                code = self.processes[pid][0].wait()
                LOG.debug('\nOK\n')
            except Exception as e:
                LOG.debug('An error while stopping process #{pid} of command "{cmd}". '
                          'Reason: "{error}".)'.format(pid=pid,
                                                       cmd=self.processes[pid][1],
                                                       error=str(e)))
