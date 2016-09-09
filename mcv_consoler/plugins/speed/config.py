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

flavor_name = 'mcv-speed-test'
flavor_min_ram = 1024
flavor_min_vcpus = 1
flavor_min_disk = 0

secgroup_name = 'mcv-speed-test'

tool_vm_name = 'mcv-speed-test'
tool_vm_image_name = 'mcv-fedora-image'
tool_vm_login = 'fedora'
tool_vm_keypair_name = 'fedora-key'
tool_vm_create_tout = 180
tool_vm_connect_tout = 180
