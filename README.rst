MCV Consoler
============

MCV Consoler is a tool which purpose is to provide a central access
point to various tools used in cloud validation.

For now Consoler supports tests from a set of tools:
    * Rally:
      - Scale testing
      - Certification Task
      - Workload tests:
          - Wordpress
          - BigData
    * OSTF:
      - MOS 6.1
      - MOS 7.0
      - MOS 8.0
    * Shaker:
      - Network speed
    * Tempest
    * Speed:
      - Block storage speed
      - Object storage speed
    * Resources:
      - General Resource search
      - Error Resource search

The way to run a set of tests is to place them to [custom_test_group_groupname]
in the config file used for running Consoler. When this is done it is
possible to invoke this set of tests by running:

    $ mcvconsoler --run group <groupname>

For more information, please contact MCV project Team:
    mirantis-cloud-validation-all@gmail.com
