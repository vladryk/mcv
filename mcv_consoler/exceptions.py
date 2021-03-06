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


class MCVException(Exception):
    pass


class EarlyExitCtrl(MCVException):
    pass


class FrameworkError(MCVException):
    pass


class ProgramError(FrameworkError):
    pass


class ConfigurationError(FrameworkError):
    pass


class UnknownFileResourceError(FrameworkError):
    pass


class FileResourceNotFoundError(FrameworkError):
    pass


class RemoteError(MCVException):
    pass


class AccessError(RemoteError):
    pass


class PortForwardingError(AccessError):
    pass


class MissingDataError(MCVException):
    pass


class ParseError(MCVException):
    pass


class ResourceDestroyBlockCtrl(MCVException):
    pass


class OpenStackResourceAccessError(AccessError):
    pass


class ReadOutdatedFileError(MCVException):
    pass


class ClientsError(MCVException):
    pass


class MountError(MCVException):
    pass


class UpdateQuotasError(MCVException):
    pass


class ResolveFqdn(MCVException):
    pass


class ExitDevMode(MCVException):
    pass
