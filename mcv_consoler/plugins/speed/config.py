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

import os

compute_login = 'root'

tool_vm_image = 'fedora-image'
tool_vm_login = 'fedora'
tool_vm_keypair = 'fedora-key'


def tool_vm_keypair_path(work_dir):
    return os.path.join(work_dir, '{}.rsa'.format(tool_vm_keypair))
