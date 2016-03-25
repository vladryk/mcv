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


class BaseError(object):
    NO_ERROR = 0

    @staticmethod
    def range():
        raise NotImplementedError()


class CAError(BaseError):
    TOO_MANY_INSTANCES = 1
    KEYBOARD_INTERRUPT = 2
    TOO_FEW_ARGS = 3

    NO_RUNNER_ERROR = 10
    UNKNOWN_EXCEPTION = 11
    RUNNER_LOAD_ERROR = 12
    UNKNOWN_OUTER_ERROR = 13
    WRONG_CREDENTIALS = 14

    @staticmethod
    def range():
        return (1, 19)


class SpeedError(BaseError):
    LOW_AVG_SPEED = 22
    FAILED_TEST_LIMIT_EXCESS = 29

    @staticmethod
    def range():
        return (20, 29)


class ResoureError(BaseError):
    FAILED_TEST_LIMIT_EXCESS = 39

    @staticmethod
    def range():
        return (30, 39)


class ShakerError(BaseError):
    NO_RUNNER_ERROR = 40
    TIMEOUT_EXCESS = 41
    FAILED_TEST_LIMIT_EXCESS = 49

    @staticmethod
    def range():
        return (40, 49)


class RallyError(BaseError):
    NO_RUNNER_ERROR = 50
    FAILED_TEST_LIMIT_EXCESS = 59

    @staticmethod
    def range():
        return (50, 59)


class OSTFError(BaseError):
    NO_RUNNER_ERROR = 60
    UNSUPPORTED_MOS_VERSION = 61
    FAILED_TEST_LIMIT_EXCESS = 69

    @staticmethod
    def range():
        return (60, 69)


class TempestError(BaseError):
    NO_RUNNER_ERROR = 80
    TESTS_FAILED = 81
    VERIFICATION_FAILED = 83
    FAILED_TEST_LIMIT_EXCESS = 89

    @staticmethod
    def range():
        return (80, 89)


class ReservedError(BaseError):

    @staticmethod
    def range():
        return (90, 99)


class ComplexError(BaseError):
    SOME_SUITES_FAILED = 100

    @staticmethod
    def range():
        return (100, 100)
