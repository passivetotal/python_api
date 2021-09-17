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
    >>> my_asi = analyzer.AttackSurface()
    >>> my_asi
    <AttackSurface #99901 "RiskIQ, Inc.">
    >>> my_asi.name
    'RiskIQ, Inc.'
    >>> my_asi.high_priority_observation_count
    0

For a complete reference of the properties available in an AttackSurface object, see
:class:`passivetotal.analyzer.illuminate.asi.AttackSurface`

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
:class:`passivetotal.analyzer.illuminate.asi.AttackSurfaceInsights` and contain a list of
:class:`passivetotal.analyzer.illuminate.asi.AttackSurfaceInsight` objects. Each of
these objects provide properties to filter, sort, and render a list of insights.
See the API reference below or click the class references here to see other options.

You can obtain the entire list of insights across all three priority
levels (high, medium, and low) at once. Use the 
:class:`passivetotal.analyzer.illuminate.asi.AttackSurface.all_insights` or 
:class:`passivetotal.analyzer.illuminate.asi.AttackSurface.all_active_insights` properties 
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
:class:`passivetotal.analyzer.illuminate.asi.AttackSurfaceObservations` object that includes a list of
:class:`passivetotal.analyzer.illuminate.asi.AttackSurfaceObservation` objects. Like nearly all
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
:class:`passivetotal.analyzer.illuminate.asi.AttackSurfaces` class.

.. code-block:: python

    >>> vendor_attack_surfaces = analyzer.illuminate.AttackSurfaces.load()
    >>> for vendor_asi in vendor_attack_surfaces:
            print(vendor_asi.name, vendor_asi.high_priority_observation_count)
    Example Vendor, Inc 13
    SaaS Provider 0
    Solutions Systems 9

Or, if you already know the RiskIQ ID of the third-party vendor you want to load, pass
it as a parameter to the top-level `analyzer.AttackSurface()` method we used to load our
own attack surface.

.. code-block:: python

    >>> vendor_asi = analyzer.AttackSurface('12345') # load by ID
    >>> print(vendor_asi.name)
    Example Vendor, Inc.

You can also load an attack surface by name, if you use a string that is precise enough
to find exactly one vendor. 

.. code-block:: python

    >>> vendor_asi = analyzer.AttackSurface('ample') # load by name match
    >>> print(vendor_asi.name)
    Example Vendor, Inc.


This will load the entire list of attack surfaces
before searching - use it sparingly and primarily in interactive use. Automated processes
should load vendor attack surfaces by ID whenever possible.


The :class:`passivetotal.analyzer.illuminate.asi.AttackSurface` objects returned in this list 
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


Examples & Notebooks
^^^^^^^^^^^^^^^^^^^^

`Jupyter Notebook <https://github.com/passivetotal/python_api/blob/master/examples/notebooks/Attack%20Surface%20%26%20Vulnerability%20Intelligence%20-%20RiskIQ%20API.ipynb>`_



ASI Reference
^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.illuminate.asi.AttackSurfaces
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.asi.AttackSurface
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.asi.AttackSurfaceInsights
    :members:
    :inherited-members:

    .. automethod:: __init__

.. autoclass:: passivetotal.analyzer.illuminate.asi.AttackSurfaceInsight
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.asi.AttackSurfaceObservations
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.asi.AttackSurfaceObservation
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
are returned as a :class:`passivetotal.analyzer.illuminate.cti.IntelProfiles` type that 
can be iterated and filtered like a regular list.

.. code-block:: python

    >>> from passivetotal import analyzer
    >>> analyzer.init()
    >>> intel_profiles = analyzer.illuminate.IntelProfiles.load()
    >>> for profile in intel_profiles:
    ...     print(profile.id, profile.title, profile.indicatorcount_riskiq)
    

Each record in the list is of type :class:`passivetotal.analyzer.illuminate.cti.IntelProfile`

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
:class:`passivetotal.analyzer.illuminate.cti.IntelProfileIndicator`
that can be iterated like a standard list and also offers several built-in methods
and properties to filter, sort, and render the list. 

Obtain the list of indicators directly as a property of an
:class:`passivetotal.analyzer.illuminate.cti.IntelProfile`:

.. code-block:: python

    >>> profile = analyzer.illuminate.IntelProfile('apt33')
    >>> for indicator in profile.indicators:
    ...    print(indicator.pretty)

Each indicator is of type
:class:`passivetotal.analyzer.illuminate.cti.IntelProfileIndicator`

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
:class:`passivetotal.analyzer.illuminate.cti.IntelProfiles.find_by_indicator()` static method:

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



Examples & Notebooks
^^^^^^^^^^^^^^^^^^^^

`Jupyter Notebook <https://github.com/passivetotal/python_api/blob/master/examples/notebooks/Cyber%20Threat%20Intelligence%20(CTI)%20-%20RiskIQ%20API.ipynb>`_


CTI Reference
^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.illuminate.cti.IntelProfiles
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.cti.IntelProfile
    :members:
    :inherited-members: tuple

.. autoclass:: passivetotal.analyzer.illuminate.cti.IntelProfileIndicatorList
    :members:
    :inherited-members:

    .. automethod:: __init__

.. autoclass:: passivetotal.analyzer.illuminate.cti.IntelProfileIndicator
    :members:
    :inherited-members:



Vulnerability Intelligence
--------------------------

RiskIQ's Vulnerability Intelligence (Vuln Intel) provides a practical picture of vulnerability risk, focused 
on a specific Attack Surface (your own or a third-party vendor). It returns a list of "CVEs"
(Common Vulnerabilities and Exposures) each identified by a name and offering a list of 
assets known to be vulnerable to the exploits or weaknesses described in the vuln report.


CVEs for your Attack Surface
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In the analyzer module, Vuln Intel is offered primarily through the ``cves`` property of an 
Attack Surface.

.. code-block:: python

    >>> cves = analyzer.AttackSurface().cves
    >>> for cve in cves:
    ...    print(cve)
    

Each record can be printed as a string, but like other ``analyzer`` objects, it offers a rich
set of properties to display and iterate through the list of CVEs. See the reference for the
:class:`passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVEs` object that represents the
list of CVEs, and reference the 
:class:`passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVE` object for details on each CVE.


CVEs for Third Parties
^^^^^^^^^^^^^^^^^^^^^^

Use the same ``cves`` property of a third-party vendor attack surface to discover which
CVEs they may be vulnerable to. In this example, we load an attack surface for vendr ID
"12345".

.. code-block:: python

    >>> cves = analyzer.AttackSurface(12345).cves
    >>> for cve in cves:
    ...    print(cve)



CVE Observations (Assets)
^^^^^^^^^^^^^^^^^^^^^^^^^

Each AttackSurfaceCVE object offers an ``observations`` property that delivers a list of
assets (typically IPs or hosts) within a given attack surface that are known to be impacted
by the CVE. The list is returned as type
:class:`passivetotal.analyzer.illuminate.vuln.AttackSurfaceObservations` and contains a list of
:class:`passivetotal.analyzer.illuminate.vuln.AttackSurfaceObservation` objects. 

.. code-block:: python

    >>> cves = analyzer.AttackSurface(12345).cves
    >>> scored_cves = cves.filter_fn(lambda c: c.score > 80).sorted_by('score',True)
    >>> highest_scored_cve = scored_cves[0]
    >>> for observation in highest_scored_cve.observations:
    ...    print(observation)

In this example, we used the ``filter_fn`` method available on most list-like ``analyzer`` objects
to apply a function similar to the Python ``filter()`` method. This helps us find one CVE to focus
on, which will then give us a list of observations.


Vulnerability Articles
^^^^^^^^^^^^^^^^^^^^^^

If you already know the identifier for a CVE article, you can access the complete details of
the article, including the description, date published, other scores, and a top-level assessment
of how exposed your attack surface is to the CVE. 

Each article is of type
:class:`passivetotal.analyzer.illumiante.vuln.VulnArticle`

.. code-block:: python

    >>> vuln_article = analyzer.illuminate.VulnArticle.load('CVE-2021-23017')
    >>> print(vuln_article.description)
    ...    'This is a known weakness in...'
    >>> print(vuln_article.observation_count)
    130
    >>> for observation in vuln_article.observations:
    ...    print(observation.name, observation.firstseen, observation.lastseen)

Here, the ``observation_count`` property gives us the number of assets in the primary
attack surface associated with our API key that are known to be impacted by this vulnerability.
We use the ``observation`` property to obtain the list, which contains a list of
:class:`passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVEObservation` objects.

For third-parties, use the ``impacts`` property to see how many of your third-party vendors'
attack surfaces are impacted by the vulnerability. Each impacted attack surface provides an
``observations`` property to obtain the list of impacted assets.

.. code-block:: python

    >>> vuln_article = analyzer.illuminate.VulnArticle.load('CVE-2021-23017')
    >>> for vendor in vuln_article.attack_surfaces:
    ...    print(vendor)
    >>> impacted_vendor = focus_article.attack_surfaces.filter_substring(vendor_name='union')[0]
    >>> for observation in impacted_vendor.observations:
    ...    print(observation.name, observation.firstseen, observation.lastseen)



Examples & Notebooks
^^^^^^^^^^^^^^^^^^^^

The example `Jupyter Notebook for Attack Surface Intelligence <https://github.com/passivetotal/python_api/blob/master/examples/notebooks/Attack%20Surface%20%26%20Vulnerability%20Intelligence%20-%20RiskIQ%20API.ipynb>`_
includes a section on how to access CVEs, observations and articles on the primary attack surface
and third-party attack surfaces.


Vuln Reference
^^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVEs
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVE
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVEObservations
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVEObservation
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVEComponents
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVEComponent
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.illuminate.vuln.VulnArticle
    :members:
    :inherited-members: