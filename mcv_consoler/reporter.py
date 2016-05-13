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

from datetime import datetime

from mcv_consoler.logger import LOG
from mcv_consoler import utils

# The very basic one-page reporter for MCV. Answers the question 'why do you
# call it beta?'.

header = """ <!doctype html>

<html lang="en">
<head>
 <meta charset="utf-8">
 <meta name="description" content="MCV Report">
</head>

<body>
<h1>MCV run report %(datetime_of_run)s</h1>
<h3>General statistics</h3>
  <table>
    <tr><td>Successfull tests:</td><td align="right">&nbsp%(quapla)s</td></tr>
    <tr><td>Failed tests:</td><td align="right">&nbsp%(failure)s</td></tr>
  </table>
<h3>Detalization</h3>
<font color="green">Successfull tests</font>
<font color="red">Failed tests</font>
<font color="magenta">Not found tests</font><br>
"""

footer = """
</body>
</html>
"""

test_string = (' <li><b><a href="%(key)s/%(testname)s.html" '
               'style="color:%(fontcolor)s">%(testname)s</b></a></li>')

general_report = """
<h4>%(component_name)s</h4>
<ul>
%(component_list)s
</ul>
"""


class _Dispatcher(object):

    def __call__(self, key, file_location=None):
        inner_func = 'fix_' + key
        if not hasattr(self, inner_func):
            LOG.debug('Fix for \'%s\' report is not implemented.' % key)
            return
        return getattr(self, inner_func)(file_location)

    @staticmethod
    def fix_shaker(file_location):
        cmd = ("sed -i '/<div\ class=\"container\"\ id=\"container\">/"
               " a\  <li class=\"active\" style=\"list-style-type: none;\"><a "
               "href=\"../index.html\">Back to Index</a></li>' "
               "%s" % file_location)

        LOG.debug('Fixing Shaker report. Command: %s' % cmd)
        result = utils.run_cmd(cmd, quiet=True)
        LOG.debug('Result: %s' % str(result))


fix_dispatcher = _Dispatcher()


def brew_a_report(stuff, name="mcv_result.html"):
    result = ""
    good, bad, notfound = 0, 0, 0
    location = name.rstrip("/index.html")
    for key, value in stuff.iteritems():
        res = ""
        for el in value['results']['test_success']:
            res += test_string % {"fontcolor": "green",
                                  "testname": el,
                                  "key": key}

            fix_dispatcher(key, "{loc}/{key}/{testname}.html".format(
                loc=location, testname=el, key=key))

            good += 1

        for el in value['results']['test_not_found']:
            res += test_string % {"fontcolor": "magenta",
                                  "testname": el,
                                  "key": key}

            fix_dispatcher(key, "{loc}/{key}/{testname}.html".format(
                loc=location, testname=el, key=key))

            notfound += 1

        for el in value['results']['test_failures']:
            res += test_string % {"fontcolor": "red",
                                  "testname": el,
                                  "key": key}

            fix_dispatcher(key, "{loc}/{key}/{testname}.html".format(
                loc=location, testname=el, key=key))

            bad += 1

        result += general_report % {"component_name": key,
                                    "component_list": res}

    out = header % {
        "datetime_of_run": datetime.now().strftime("%a, %d %b %Y %H:%M:%S"),
        "quapla": str(good),
        "failure": str(bad)
    } + result + footer

    with open(name, "w") as f:
        f.write(out)
