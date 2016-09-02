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
import time

import mcv_consoler.common.config as app_conf
from mcv_consoler.auth.router import Router
from mcv_consoler.auth.router import IRouter
from mcv_consoler.auth.router import CRouter
from mcv_consoler import utils

LOG = logging.getLogger(__name__)


class AccessSteward(object):
    def __init__(self, ctx, mode, **kwargs):
        self.ctx = ctx

        router_class = {
            app_conf.RUN_MODES[0]: IRouter,
            app_conf.RUN_MODES[1]: CRouter,
            # monkey fix until MRouter created
            app_conf.RUN_MODES[2]: CRouter}.get(mode, Router)
        self.router = router_class(self.ctx, **kwargs)

    def access_data(self):
        return self.router.os_data

    def check_docker_images(self):
        LOG.debug('Validating that all docker images required by '
                  'the application are available')

        sleep_total = 0
        sleep_for = app_conf.DOCKER_CHECK_INTERVAL
        timeout = app_conf.DOCKER_LOADING_IMAGE_TIMEOUT

        while True:
            if self.ctx.terminate_event.is_set():
                LOG.warning('Caught Keyboard Interrupt, exiting')
                return False

            if sleep_total >= timeout:
                LOG.warning('Failed to load one or more docker images. '
                            'Gave up after %s seconds. See log for more '
                            'details' % sleep_total)
                return False

            res = utils.run_cmd("docker images --format {{.Repository}}",
                                quiet=True)

            all_present = all(map(res.count, app_conf.DOCKER_REQUIRED_IMAGES))
            if all_present:
                LOG.debug("All docker images seem to be in place")
                return True

            by_name = lambda img: res.count(img) == 0
            not_found = filter(by_name, app_conf.DOCKER_REQUIRED_IMAGES)

            formatter = dict(
                sleep=sleep_for, total=sleep_total,
                max=timeout, left=timeout - sleep_total
            )
            LOG.debug('One or more docker images are not present: '
                      '{missing}.'.format(missing=', '.join(not_found)))
            LOG.debug('Going to wait {sleep} more seconds for them to load. '
                      'ETA: already waiting {total} sec; max time {max}; '
                      '{left} left'.format(**formatter))

            time.sleep(sleep_for)
            sleep_total += sleep_for

    def cleanup(self):
        self.router.cleanup()

    def check_and_fix_environment(self):
        if not self.check_docker_images():
            LOG.warning('Failed to load docker images. Exiting')
            return False
        return self.router.setup_connections()
