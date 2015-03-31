MCV Consoler
============

MCV Consoler is a tool which purpose is to provide a central access
point to various tools used in cloud validation. The only tool supported
so far is Rally. Other tools will be added whenever the basic functionality
of Consoler is agreed upon.

The way to run a set of tests is to place them to [custom_group_groupname]
in the config file used for running Consoler. When this is done it is
possible to invoke this set of tests by running

    $ mcvconsoler --run custom groupname

At the moment the only output provided by the Consoler is a notice whether
the tests were successfull or not. Everything else is stored in a corresponding
logfile. The only cloud that could be tested so far is a MOS cloud as several of
default tests are made under certain assumptions valid only for MOS clouds.
It is planned to expand the test set when it is more obvious which tests are
necessary.
