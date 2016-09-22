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
import time

import mcv_consoler.common.config as app_conf
from mcv_consoler.auth.router import Router
from mcv_consoler.auth.router import IRouter
from mcv_consoler.auth.router import CRouter
from mcv_consoler import exceptions
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

    def __enter__(self):
        self._recount_docker_images()
        self.router.setup_connections()

        return self

    def __exit__(self, *exc_info):
        self.router.cleanup()

    def access_data(self):
        return self.router.os_data

    def _recount_docker_images(self):
        # TODO(dbogun): why for this method here? It must be in router
        LOG.debug('Validating that all docker images required by '
                  'the application are available')

        now = time.time()
        time_end = now + app_conf.DOCKER_LOADING_IMAGE_TIMEOUT

        missing = app_conf.DOCKER_REQUIRED_IMAGES
        while now < time_end:
            if self.ctx.terminate_event.is_set():
                raise exceptions.EarlyExitCtrl

            available = utils.run_cmd(
                'docker images --format {{.Repository}}', quiet=True)
            available = available.split()
            available = set(available)
            missing = app_conf.DOCKER_REQUIRED_IMAGES - available
            if not missing:
                break

            missing = sorted(missing)
            LOG.debug(
                'One or more docker images are not present: "%s"',
                '", "'.join(missing))

            sleep_for = time_end - time.time()
            sleep_for = max(sleep_for, 0)
            sleep_for = min(sleep_for, 1)
            time.sleep(sleep_for)

            now = time.time()
        else:
            missing = sorted(missing)
            raise exceptions.FrameworkError(
                'Unable to locate docker image(s): "{}"'.format(
                    '", "'.join(missing)))

        LOG.debug('All docker images seem to be in place')
