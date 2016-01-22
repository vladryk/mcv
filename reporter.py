import time
import subprocess

import utils

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

test_string = """ <li><b><a href="%(key)s/%(testname)s.html" style="color:%(fontcolor)s">%(testname)s</b></a></li>
"""

general_report = """
<h4>%(component_name)s</h4>
<ul>
%(component_list)s
</ul>
"""

# TODO: this should be done less conceptually and more like fixing a template
# before passing it to container.
def fix_rally(file_location):
    cmd = "sed -i '412 a \     <a href=\"../index.html\">Back to Index</a>&nbsp;' %s" % file_location
    p = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT,
            preexec_fn=utils.ignore_sigint)

def fix_shaker(file_location):
    cmd = "sed -i '/<div\ class=\"container\"\ id=\"container\">/ a\  <li " \
    "class=\"active\" style=\"list-style-type: none;\"><a " \
    "href=\"../index.html\">Back to Index</a></li>' %s" % file_location
    p = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT,
            preexec_fn=utils.ignore_sigint)

fix_dispatcher = {"rally": fix_rally, "shaker": fix_shaker}

def brew_a_report(stuff, name="mcv_result.html"):
    result = ""
    good, bad, notfound = 0, 0, 0
    location = name.rstrip("/index.html")
    for key, value in stuff.iteritems():
        res = ""
        for el in value['results']['test_success']:
            res += test_string % {"fontcolor" :"green", "testname": el, "key": key}
            fix_dispatcher[key]("%(loc)s/%(key)s/%(testname)s.html" % {"loc": location, "testname": el, "key": key})
            good += 1
        for el in value['results']['test_not_found']:
            res += test_string % {"fontcolor" :"magenta", "testname": el, "key": key}
            fix_dispatcher[key]("%(loc)s/%(key)s/%(testname)s.html" % {"loc": location, "testname": el, "key": key})
            notfound += 1
        for el in value['results']['test_failures']:
            res += test_string % {"fontcolor" :"red", "testname": el, "key": key}
            fix_dispatcher[key]("%(loc)s/%(key)s/%(testname)s.html" % {"loc": location, "testname": el, "key": key})
            bad += 1
        result += general_report % { "component_name": key,
                                     "component_list": res,}

    out = header % {"datetime_of_run": time.strftime("%a, %d %b %Y %H:%M:%S",
                                                      time.gmtime()),
                     "quapla" : str(good), "failure": str(bad),
                     } + result + footer
    with open(name, "w") as f:
        f.write(out)
