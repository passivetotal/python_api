PassiveTotal Python
===================

Build Status
------------

.. image:: https://travis-ci.org/passivetotal/python_api.svg
    :target: https://travis-ci.org/passivetotal/python_api

.. image:: https://img.shields.io/pypi/dm/passivetotal.svg
    :target: https://pypi.python.org/pypi/passivetotal/

.. image:: https://img.shields.io/pypi/v/passivetotal.svg
   :target: https://pypi.python.org/pypi/passivetotal

.. image:: https://img.shields.io/badge/passivetotal-2.7-blue.svg
    :target: https://pypi.python.org/pypi/passivetotal/

.. image:: https://img.shields.io/pypi/l/passivetotal.svg
    :target: https://pypi.python.org/pypi/passivetotal/

.. image:: https://readthedocs.org/projects/passivetotal/badge/?version=latest
    :target: https://readthedocs.org/projects/passivetotal/?badge=latest

Introduction
------------

*Python client for RiskIQ's PassiveTotal API services*

**passivetotal** provides a Python client library implementation into RiskIQ API
services. The library currently provides support for the following services:

- Passive DNS queries and filters
- WHOIS queries (search and details)
- SSL Certificates (search and details)
- Account configuration
- Site actions (tagging, classifying, etc.)

Command-line scripts
--------------------

The following command line scripts are installed with the library:

- **pt-config**: utility to set or query API configuration options for the
  library (username and API key).
- **pt-info**: client to query for your local account information and services.
- **pt-client**: primary client to issue queries against PassiveTotal services
  including passive DNS, WHOIS, SSL certificates, etc.

See the *Usage* section for more information.

Installation
------------

From the downloaded source distribution::

    $ python setup.py install

Or from PyPI::

    $ pip install passivetotal [--upgrade]

The package depends on the Python Requests_ library.
If Requests is not installed, it will be installed as a dependency.

.. _Requests: http://docs.python-requests.org/

Setup
-----

First-time setup requires configuring your API token and private key for authentication::

    $ pt-config setup <USERNAME> <API_KEY>

At any time, the current API configuration parameters can be queried using the same utility::

    $ pt-config show

Configuration parameters are stored in **$HOME/.config/passivetotal/api_config.json**.

Upgrades
--------

Our libraries support Python 3 through futures. On certain platforms, this causes issues when doing upgrades of the library. When performing an update, use the following:

    sudo pip install passivetotal --upgrade --ignore-installed six 

Usage
-----

Every command-line script has several sub-commands that may be passed to it. The
commands usage may be described with the ``-h/--help`` option.

For example::

    $ pt-client -h
    usage: pt-client [-h] {action,pdns,whois,ssl} ...

    PassiveTotal Command Line Client

    positional arguments:
      {action,pdns,whois,ssl}
        pdns                Query passive DNS data
        whois               Query WHOIS data
        ssl                 Query SSL certificate data
        action              Query and input feedback

    optional arguments:
      -h, --help            show this help message and exit

Every sub-command has further help options:::

    $ pt-client pdns -h
    usage: pt-client pdns [-h] --query QUERY [--sources SOURCES [SOURCES ...]]
                          [--end END] [--start START] [--timeout TIMEOUT]
                          [--unique] [--format {json,text,csv,stix,table,xml}]

    optional arguments:
      -h, --help            show this help message and exit
      --query QUERY, -q QUERY
                            Query for a domain, IP address or wildcard
      --sources SOURCES [SOURCES ...]
                            CSV string of passive DNS sources
      --end END, -e END     Filter records up to this end date (YYYY-MM-DD)
      --start START, -s START
                            Filter records from this start date (YYYY-MM-DD)
      --timeout TIMEOUT, -t TIMEOUT
                            Timeout to use for passive DNS source queries
      --unique              Use this to only get back unique resolutons
      --format {json,text,csv,stix,table,xml}
                            Format of the output from the query

All commands will have the ``--format`` option to return raw responses in a number
of different formats, which often contain more information than present in the
default, human readable format.

Documentation
-------------

For more information you can find documentation in the 'docs' directory, check
the Github wiki, or readthedocs_.

.. _readthedocs: https://passivetotal.readthedocs.org
