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


Reputation Score Reference
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.illuminate.ReputationScore
    :members:



Attack Surface Intelligence
---------------------------

RiskIQ Illuminate offers Attack Surface Intelligence (ASI) that delivers prioritized
insights on an organization's attack surface, including impact assets (observations).

ASI is available to licensed users of the RiskIQ Illuminate API.

The `analyzer` module provides an easy-to-use overlay to interact with the Attack Surface
API endpoints and quickly obtain a list of impacted hosts.

Review the :doc:`getting-started` guide for details on setting up your
credentials and development environment.



Your Attack Surface
^^^^^^^^^^^^^^^^^^^

An essential use case for the RiskIQ Illuminate ASI API is to understand your own 
organization's attack surface. 

.. code-block:: python

    >>> from passivetotal import analyzer
    >>> analyzer.init()
    >>> my_asi = analyzer.illuminate.AttackSurface.load()
    >>> my_asi
    <AttackSurface #99901 "RiskIQ, Inc.">
    >>> my_asi.name
    'RiskIQ, Inc.'
    >>> my_asi.high_priority_observation_count
    0

For a complete reference of the properties available in an AttackSurface object, see
:class:`passivetotal.analyzer.illuminate.AttackSurface`

Attack Surfaces contain a list of insights organized by priority. Insights are included
in the response even if there are no impacted assets, but it is easy to filter the list
to focus on only the insights with "observations". 

.. code-block:: python

    >>> for insight in my_asi.medium_priority_insights:
            print(insight.name, insight.observation_count)
    ASI: CVE-2021-123 Potential vulnerability 0
    ...
    ASI: Multiple vulnerabilities in System X 1
    >>> for insight in my_asi.medium_priority_insights.only_active_insights:
            print(insight.name)
    ASI: Multiple vulnerabilities in System Q

Insight lists are of type
:class:`passivetotal.analyzer.illuminate.AttackSurfaceInsights` and contain a list of
:class:`passivetotal.analyzer.illuminate.AttackSurfaceInsight` objects. Each of
these objects provide properties to filter, sort, and render a list of insights.
See the API reference below or click the class references here to see other options.

You can obtain the entire list of insights across all three priority
levels (high, medium, and low) at once. Use the 
:class:`passivetotal.analyzer.illuminate.AttackSurface.all_insights` or 
:class:`passivetotal.analyzer.illuminate.AttackSurface.all_active_insights` properties 
to get the complete list.


Attack Surface Observations
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Attack Surface Observations are assets related to a given insight within the context of a
specific Attack Surface. Assets typically include IPs and hostnames, and include the "first seen" and
"last seen" dates that describe when RiskIQ detected an indication  the asset was potentially impacted.

Observations are available in the `observations` property of an AttackSurfaceInsight.

.. code-block:: python

    >>> insights = my_asi.medium_priority_insights.only_active_insights
    >>> first_insight = insights[0]
    >>> for observation in first_insight:
            print(observation.type)
            print(observation.name)
    HOST
    subdomain.passivetotal.org

Notice we filtered the list to only include active insights. If you skip this step, be prepared to
catch `AnalyzerAPIError` exceptions thrown by the API when there are no observations available
for a given insight.

The list of observations is returned as a
:class:`passivetotal.analyzer.illuminate.AttackSurfaceObservations` object that includes a list of
:class:`passivetotal.analyzer.illuminate.AttackSurfaceObservation` objects. Like nearly all
`analyzer` objects, these objects can be easily rendered as a Python dictionary for integration
with other systems using the `as_dict` property.

.. code-block:: python

    >>> insights = my_asi.medium_priority_insights.only_active_insights
    >>> first_insight = insights[0]
    >>> observations = first_insight.observations.as_dict
    >>> observations
    {'records': [{'type': 'HOST', 'name': 'subdomain.passivetotal.org', 'firstseen': '2021-02-03 04:05:06', 'lastseen': '2021-06-07 08:09:10'}]}



Third-Party Attack Surfaces
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Third-Party ASI module of Illuminate provides access to the Attack Surfaces of other organizations
(aka "vendors"). Your API credentials must be specifically licensed to access third-party Attack Surfaces.

To obtain a list of Attack Surfaces, use the `load()` method of the
:class:`passivetotal.analyzer.illuminate.AttackSurfaces` class.

.. code-block:: python

    >>> vendor_attack_surfaces = analyzer.illuminate.AttackSurfaces.load()
    >>> for vendor_asi in vendor_attack_surfaces:
            print(vendor_asi.name, vendor_asi.high_priority_observation_count)
    Example Vendor, Inc 13
    SaaS Provider 0
    Solutions Systems 9

Use the `filter_substring` method and standard Python index notation to get a single
vendor's attack surface (assuming only one vendor matches your substring search).

.. code-block:: python

    >>> vendor_attack_surfaces = analyzer.illuminate.AttackSurfaces.load()
    >>> vendor_asi = vendor_attack_surfaces.filter_substring(name='example vendor')[0]
    >>> print(vendor_asi.name)
    Example Vendor, Inc.

The :class:`passivetotal.analyzer.illuminate.AttackSurface` objects returned in this list 
provide the same functionality as the objects described above that represent your own attack surface.
Use the same techniques to enumerate the insights and observations (assets) for a vendor ASI.

.. code-block:: python

    >>> vendor_attack_surfaces = analyzer.illuminate.AttackSurfaces.load()
    >>> for vendor_asi in vendor_attack_surfaces:
            if vendor_asi.high_priority_observation_count > 0:
                print(vendor_asi.name)
                for insight in vendor_asi.high_priority_insights.only_active_insights:
                    print('--- {0.name}'.format(insight))
    Example Vendor, Inc
    --- ASI: CVE 123
    --- ASI: CVE 445
    SaaS Provider
    --- [Potential] Expired items
    Solutions Systems
    --- Deprecated Technologies



ASI Reference
^^^^^^^^^^^^^

    .. autoclass:: passivetotal.analyzer.illuminate.AttackSurfaces
        :members:
        :inherited-members:

    .. autoclass:: passivetotal.analyzer.illuminate.AttackSurface
        :members:
        :inherited-members:

    .. autoclass:: passivetotal.analyzer.illuminate.AttackSurfaceInsights
        :members:
        :inherited-members:
    
        .. automethod:: __init__
    
    .. autoclass:: passivetotal.analyzer.illuminate.AttackSurfaceInsight
        :members:
        :inherited-members:

    .. autoclass:: passivetotal.analyzer.illuminate.AttackSurfaceObservations
        :members:
        :inherited-members:

    .. autoclass:: passivetotal.analyzer.illuminate.AttackSurfaceObservation
        :members:
        :inherited-members:




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
are returned as a :class:`passivetotal.analyzer.illuminate.IntelProfiles` type that 
can be iterated and filtered like a regular list.

.. code-block:: python

    >>> from passivetotal import analyzer
    >>> analyzer.init()
    >>> intel_profiles = analyzer.illuminate.IntelProfiles.load()
    >>> for profile in intel_profiles:
    ...     print(profile.id, profile.title, profile.indicatorcount_riskiq)
    

Each record in the list is of type :class:`passivetotal.analyzer.illuminate.IntelProfile`

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



Indicator Lists
^^^^^^^^^^^^^^^

The RiskIQ research team curates lists of indicators associated with each intel
profile, some sourced from open-source intelligence, and others surfaced directly
from RiskIQ proprietary datasets. 

There are several ways to obtain the list of indicators associated with a specific
intel profile. Each method will return an object of type
:class:`passivetotal.analyzer.illuminate.IntelProfileIndicator`
that can be iterated like a standard list and also offers several built-in methods
and properties to filter, sort, and render the list. 

Obtain the list of indicators directly as a property of an
:class:`passivetotal.analyzer.illuminate.IntelProfile`:

.. code-block:: python

    >>> profile = analyzer.illuminate.IntelProfile('apt33')
    >>> for indicator in profile.indicators:
    ...    print(indicator.pretty)

Each indicator is of type
:class:`passivetotal.analyzer.illuminate.IntelProfileIndicator`

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

If you only need the values of the indicators, you can quickly access them as a 
plain Python list with the `values` property:

.. code-block:: python

    >>> profile = analyzer.illuminate.IntelProfile('apt33')
    >>> indicators = profile.get_indicators(sources='riskiq')
    >>> indicators.values
    ['.....'] 
    >>> indicators.only_riskiq.values
    ['.....']
    >>> indicators.filter_in(type='domain,ip').values
    ['.....']




Search By Indicator
^^^^^^^^^^^^^^^^^^^

The CTI API provides a mechanism to search for intel profiles by the value of
an indicator. You can query the API directly for any of the indicator types
stored in the RiskIQ dataset, or you can access the list as a property of
`analyzer.Hostname` or `analyzer.IPAddress` objects.

To search the API directly, use the 
:class:`passivetotal.analyzer.illuminate.IntelProfiles.find_by_indicator()` static method:

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




CTI Reference
^^^^^^^^^^^^^

    .. autoclass:: passivetotal.analyzer.illuminate.IntelProfiles
        :members:
        :inherited-members:

    .. autoclass:: passivetotal.analyzer.illuminate.IntelProfile
        :members:
        :inherited-members: tuple

    .. autoclass:: passivetotal.analyzer.illuminate.IntelProfileIndicatorList
        :members:
        :inherited-members:
    
        .. automethod:: __init__
    
    .. autoclass:: passivetotal.analyzer.illuminate.IntelProfileIndicator
        :members:
        :inherited-members:
