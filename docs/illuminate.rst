RiskIQ Illuminate
=================

Reputation Scoring
------------------

The RiskIQ Illuminate platform provides dynamic reputation scoring on IPs
and hostnames based on real-world activity, indicators, and behaviors.

This library provides access to reptuation scores through the object analyzer
(recommended), the command line interface, or  the low-level request wrappers.

Review the :doc:`getting-started` guide for details on setting up your
credentials and development environment.


Hostname and IP Reputation Analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: python

    >>> from passivetotal import analyzer
    >>> analyzer.init()
    >>> reputation = analyzer.Hostname('2020-windows.com').reputation
    >>> print(reputation)
    72 (SUSPICIOUS)
    >>> print(analyzer.IPAddress('123.213.1.23').reputation.score)
    88
    >>> analyzer.IPAddress('123.213.1.23').reputation.rules
    [{'name': 'Third Party Blocklist (vo)',
      'description': 'Threat Type: SERVICE SCANNER',
      'severity': 5,
      'link': None},
     {'name': 'Open ports observed',
      'description': 'The number of open ports may indicate maliciousness',
      'severity': 3,
     'link': None}]


The ``Hostname`` and ``IPAddress`` analyzer objects provide a ``reputation`` 
property that returns an instance of a `ReputationScore` object. That 
object can be treated directly like a string or an integer, or you can 
access the properties directly. 

.. autoclass:: passivetotal.analyzer.hostname.Hostname
    :members: reputation

.. autoclass:: passivetotal.analyzer.ip.IPAddress
    :members: reputation


Reputation Score CLI
^^^^^^^^^^^^^^^^^^^^
The ``pt-client`` command line script provides quick access to reputation profiles
on one or more hosts in several formats. To get started, view the help for the 
illuminate command:

.. code-block:: console

   (venv) % pt-client illuminate --help
   usage: passivetotal illuminate [-h] [--reputation] [--format {json,csv,text}] [--brief] query [query ...]

   positional arguments:
   query                 One or more hostnames or IPs

   optional arguments:
   -h, --help            show this help message and exit
   --reputation          Get hostname or IP reputation from RiskIQ Illuminate.
   --format {json,csv,text}
                           Format of the output from the query
   --brief               Create a brief output; for reputation, prints score and classification only

Use ``--reputation`` and pass a space-separated list of hostnames or IPs as the query parameter.

The default format is "json" - for interactive use, try ``--format=text``:

.. code-block:: console

   (venv) % pt-client illuminate --reputation --format=text 2020-windows.com
   2020-windows.com  72 (SUSPICIOUS)
      Registrant email provider (severity 3)
         Domain is registered with an email provider that is
         more likely to register malicious domains
      Registrar (severity 3)
         Domains registered with this registrar are more likely
         to be malicious

The ``--brief`` option produces a more compact output with one result per line, which is also
useful with the ``--format=csv`` parameter to prepare a compact dataset for import into another
product. 

Pass multiple hostnames or IPs at the end of the command (separated by spaces) to
analyze multiple hosts at one time.



Reputation Request Wrapper
^^^^^^^^^^^^^^^^^^^^^^^^^^

Use the low-level ``Illuminate`` request wrapper for direct queries to the
API.

.. autoclass:: passivetotal.libs.illuminate.IlluminateRequest
    :members: get_reputation



Intelligence Profiles (CTI)
---------------------------

The RiskIQ Illuminate platform offers a Cyber Threat Intelligence (CTI) module that
delivers insights into adversary threat infrastructure organized around a set of
purpose-built intelligence profiles, each with a curated set of indicators.

The `analyzer` module provides the optimal interface to query the CTI dataset, but
low-level request wrappers are also available. See below for the API reference docs.

Review the :doc:`getting-started` guide for details on setting up your
credentials and development environment.

**Important: this module must be specifically enabled for your API credentials.** 


Intel Profiles
^^^^^^^^^^^^^^

For most use cases, start with the list of RiskIQ Illuminate intel profiles. These
are returned as a `RecordList` type that can be iterated and filtered like a regular list.

.. code-block:: python

    >>> from passivetotal import analyzer
    >>> analyzer.init()
    >>> intel_profiles = analyzer.illuminate.IntelProfiles.load()
    >>> for profile in intel_profiles:
    ...     print(profile.id, profile.title, profile.indicatorcount_riskiq)
    

Intel Profiles are identified with a unique string in the `id` parameter. Once you know
the profile you want to focus on, you can instantiate it directly using that id.

.. code-block:: python

    >>> profile = analyzer.illuminate.IntelProfile('apt33')
    >>> print(profile.pretty)
    { 'id': 'apt33',
      'indicatorcount_osint': 33333,
      'indicatorcount_riskiq': 55555,
      'tags_raw': [ {'countryCode': None, 'label': 'Malicious'},
                    {'countryCode': 'us', 'label': 'Target: USA'}],
      'title': 'APT33'}

**Module Reference**

.. autoclass:: passivetotal.analyzer.illuminate.IntelProfiles
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.IntelProfile
    :members:
    :inherited-members:


Indicator Lists
^^^^^^^^^^^^^^^

The RiskIQ research team curates lists of indicators associated with each intel
profile, some sourced from open-source intelligence, and others surfaced directly
from RiskIQ proprietary datasets. 

There are several ways to obtain the list of indicators associated with a specific
intel profile.

Obtain the list of indicators directly as a property of an `IntelProfile`:

.. code-block:: python

    >>> profile = analyzer.illuminate.IntelProfile('apt33')
    >>> for indicator in profile.indicators:
    ...    print(indicator.pretty)

For more granular control, call the `get_indicators()` method and set additional
parameters supported by the API to narrow the list:

.. code-block:: python

    >>> profile = analyzer.illuminate.IntelProfile('apt33')
    >>> indicators = profile.get_indicators(sources='riskiq')
    >>> len(indicators)
    55555

Or, skip the intel profile entirely and go straight to the indicator list.

.. code-block:: python

    >>> ioc_list = analyzer.illuminate.IntelProfileIndicatorList('apt33')
    >>> ioc_list.load_all_pages()
    >>> len(ioc_list)
    55555

The underlying API calls require pagination, but the analyzer module handles 
that automatically when you access either the `indicators` property or call
`get_indicators()` directly on the profile objects. Here, we are using the 
`load_all_pages()` method to populate the list directly. 

Like other analyzer objects, indicators are returned in an `analyzer.RecordList` object, 
which provides a number of mechanisms for filtering and viewing the records. If you
only need the values of the indicators, you can quickly access them as a plain Python
list:

.. code-block:: python

    >>> profile = analyzer.illuminate.IntelProfile('apt33')
    >>> indicators = profile.get_indicators(sources='riskiq')
    >>> indicators.values
    ['.....'] 
    >>> indicators.only_riskiq.values
    ['.....']
    >>> indicators.filter_in(type='domain,ip').values
    ['.....']


**Module Reference**

.. autoclass:: passivetotal.analyzer.illuminate.IntelProfileIndicatorList
    :members:
    :inherited-members:

    .. automethod:: __init__


.. autoclass:: passivetotal.analyzer.illuminate.IntelProfileIndicator
    :members:
    :inherited-members:



Search By Indicator
^^^^^^^^^^^^^^^^^^^

The CTI API provides a mechanism to search for intel profiles by the value of
an indicator. You can query the API directly for any of the indicator types
stored in the RiskIQ dataset, or you can access the list as a property of
`analyzer.Hostname` or `analyzer.IPAddress` objects.

To search the API directly, use the 
`passivetotal.analyzer.illuminate.IntelProfiles.find_by_indicator()` static method:

.. code-block:: python

    >>> results = analyzer.illuminate.IntelProfiles.find_by_indicator('threat_actor@gmail.com')
    >>> len(results)
    1
    >>> print(results[0].title)
    APT123
    >>> for ioc in results[0].indicators:
    ...    print(ioc)


Or, if you are working with a hostname or IP address, access the `intel_profiles`
property to obtain the profile list. Be sure to test the length of the list before accessing
properties to avoid runtime exceptions.

.. code-block:: python

    >>> if len(analyzer.IPAddress('123.123.123.123').intel_profiles) > 0:
    ...     print(intel_profiles.pretty)




