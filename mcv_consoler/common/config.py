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


# Enables DEBUG logging
DEBUG = False

# Project description
PROJECT_NAME = "mcvconsoler"

PROJECT_DESCRIPTION = """The main tool in Mirantis Cloudvalidation Project."""

RUN_DESCRIPTION = r"""Here is an example of running MCV Consoler:

    # mcvconsoler --run custom quick

    Also it is recommended to run the tool as a superuser, running it as an
    ordinary user might cause unexpected errors in strange places for odd
    tools.

    ...and in the darkness bind them, in the cloud where the instances lie."""

DEFAULT_CONFIG_FILE = "/etc/mcv/mcv.conf"
