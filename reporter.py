import time

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
    <tr><td>Not found tests:</td><td align="right">&nbsp%(notfound)s</td></tr>
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

#test_string = """ <li><b><font color="%(fontcolor)s">%(testname)s</b></font></li>
#"""
test_string = """ <li><b><a href="%(key)s/%(testname)s.html" style="color:%(fontcolor)s">%(testname)s</b></a></li>
"""
general_report = """
<h4>%(component_name)s</h4>
<ul>
%(component_list)s
</ul>
"""

def brew_a_report(stuff, name="mcv_result.html"):
    result = ""
    good, bad, notfound = 0, 0, 0
    location = name.rstrip("/index.html")
    for key, value in stuff.iteritems():
        res = ""
        for el in value['results']['test_success']:
            res += test_string % {"fontcolor" :"green", "testname": el, "key": key}
            good += 1
        for el in value['results']['test_not_found']:
            res += test_string % {"fontcolor" :"magenta", "testname": el, "key": key}
            notfound += 1
        for el in value['results']['test_failures']:
            res += test_string % {"fontcolor" :"red", "testname": el, "key": key}
            bad += 1
        result += general_report % { "component_name": key,
                                     "component_list": res,}

    out = header % {"datetime_of_run": time.strftime("%a, %d %b %Y %H:%M:%S",
                                                      time.gmtime()),
                     "quapla" : str(good), "failure": str(bad),
                     "notfound":str(notfound),} + result + footer
    with open(name, "w") as f:
        f.write(out)
