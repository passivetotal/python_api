# RiskIQ PassiveTotal Python Library

## Build Status
[![build status](https://travis-ci.org/passivetotal/python_api.svg)](https://travis-ci.org/passivetotal/python_api)
[![doc status](https://readthedocs.org/projects/passivetotal/badge/?version=latest)](https://readthedocs.org/projects/passivetotal/?badge=latest)
[![pypi downloads](https://img.shields.io/pypi/dm/passivetotal.svg)](https://pypi.python.org/pypi/passivetotal/)
[![pypi version](https://img.shields.io/pypi/v/passivetotal.svg)](https://pypi.python.org/pypi/passivetotal)
[![license](https://img.shields.io/pypi/l/passivetotal.svg)](https://pypi.python.org/pypi/passivetotal/)

## Introduction

This Python library provides an interface to the RiskIQ PassiveTotal Internet
intelligence database and the RiskIQ Illuminate Reputation Score. 

Security researchers and network defenders use RiskIQ PassiveTotal to map threat 
actor infrastructure, profile hostnames & IP addresses, discover web technologies 
on Internet hosts.

Capabilites of this library include:
* Credential management - protect API keys from accidental disclosure
* Object analyzer - analyze hosts without knowing which API endpoints to use
* CLI for quick queries and package configuration
* Low-level wrappers for all PassiveTotal API endpoints

To learn more about RiskIQ and start a free trial, visit [https://community.riskiq.com](https://community.riskiq.com)

## Getting Started

### Install the PassiveTotal Library
The PassiveTotal Python library is available in pip under the package name `passivetotal`. 
Consider setting up a [virtual environment](https://docs.python.org/3/library/venv.html), then run:
```
pip install passivetotal
```

### Obtain API Keys
Queries to the API must be authenticated with a PassiveTotal API key.

1. Log in (or sign up) at [community.riskiq.com](https://community.riskiq.com)
2. Access your profile by clicking the person icon in the upper-right corner of the page.
3. Click on "Account Settings"
4. Under "API Access", click "Show" to reveal your API credentials.

The identifier for your API account is alternatively called a "username", a "user", or
an "API key". Look for an email address and use that value when prompted for your 
"API username".

The "API Secret" is a long string of characters that should be kept secure. It is
the primary authentication method for your API account. 

Your PassiveTotal account may have a separate "API Secret" for your organization - when 
available, **always use your organization key** unless you have a specific reason not to.


### Build a Config File
The optimal way to store your API credentials is inside a config file managed by
this library's command line tools. 

The library references the config file by default when creating new API connections, 
setting up the analyzer module, or running command line tools.

Run the command setup command with your username to get started:
```
pt-config setup user@example.com
```

Enter the API secret key when prompted, then press enter. The complete configuration
will then print out so you can confirm the values.

To see other configuration options, including options for an HTTP proxy, enter:
```
pt-config setup -h
```


### Choose an Interface
This library enables interaction with the PassiveTotal API through several distinct
interfaces. Choose the one that best fits your use case.

*If you're not sure where to start, use the Object Analyzer.*

### Object Analyzer
```python
>>> from passivetotal import analyzer
>>> analyzer.init()
>>> age = analyzer.Hostname('riskiq.com').whois.age
>>> print('Domain is {} days old'.format(age))
Domain is 5548 days old
>>> analyzer.set_date_range(days_back=30)
>>> pdns = analyzer.Hostname('api.passivetotal.org').ip.resolutions
>>> for record in pdns.sorted_by('lastseen'):
        print(record)
A "staging-api.passivetotal.org" [ 465 days] (2019-12-11 to 2021-03-21)
A "api.passivetotal.org" [ 459 days] (2019-12-18 to 2021-03-22)
```
**Benefits**
* Ideal starting point for new scripts and product integrations.
* Works well in interactive Python environments such as Jupyter.
* Does not require familiarity with specific API endpoints. 
* Stores results within object instances to faciliate declarative interactions
  and offer an intuitive syntax.

**Caveats**
* May not have complete coverage for every API endpoint.
* Opinionated: default values are optimized for efficient queries and
  common investigative pathways.
* API queries run automatically when properties are first accessed, 
  which may result in excessive API query usage.


### Command Line
Access the CLI with the `pt-client` command. Run the command without options to
see a list of available commands. 

Most CLI commands only output JSON; if you need more robust output options,
consider writing a script with the `analyzer` module.


### Request Wrappers
Use these low-level interfaces when you know exactly which API endpoints you need
to query and what parameters they require. These are still preferred over making
API requests directly with `requests` or `urllib` because they benefit from
the credential management and config file mechanism described above. 

Wrappers should exist for every PassiveTotal API endpoint, but availability may
lag behind when new features are implemented. If you cannot locate a wrapper for
your preferred endpoint, use an instance of the `passivetotal.GenericRequest` class.


## Additional Resources

Library docs: https://passivetotal.readthedocs.io/

RiskIQ Product Support: https://info.riskiq.net/
