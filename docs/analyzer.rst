Analyzer Module
===============

The ``passivetotal.analyzer`` module provides high-level objects that directly
map to the most common starting points in security investigations, including
hostnames & IP addresses. Key features include:

#. API abstraction enables direct property access without knowing which endpoint 
   to query.
#. On-demand API queries load data as needed and persist the data in the object 
   instance.
#. List-like results objects are easy to iterate and provide useful filters.
#. Object instances stored as class members, ensuring efficient re-use of API 
   results and enabling method chaining on complex result sets.
#. Helpful string and repr views to quickly inspect objects in an interactive
   environment.

Initialization
--------------
The analyzer module must be initialized before it can be used. This can be as
simple as calling the ``init()`` method at the module level:

.. code-block:: python

    from passivetotal import analyzer
    analyzer.init()

This will read the API configuration setup by the ``pt-setup`` command line script
and prepare request wrappers for use in subsequent calls.

No other configuration is required to begin using the analyzer module, but you
should review the module reference to become aware of configuration options that
would normally be set in specific API calls.


Hostname Analysis
-----------------
**Example Usage**

.. code-block:: python

   >>> from passivetotal import analyzer
   >>> analyzer.init()
   >>> host = analyzer.Hostname('riskiq.net')
   >>> registrant = host.whois.organization
   >>> print(registrant.organization)
   RiskIQ UK Limited

.. autoclass:: passivetotal.analyzer.Hostname
   :members:
   :inherited-members:


IP Analysis
-----------
**Example Usage**
   
.. code-block:: python
   
   >>> from passivetotal import analyzer
   >>> analyzer.init()
   >>> ip = analyzer.IPAddress('35.189.71.51')
   >>> print(ip.summary)
   22 records available for 35.189.71.51
   >>> for record in ip.resolutions:
           print(record)
   A "trafficplus.name" [   6 days ] (2021-01-01 to 2021-03-01)


.. autoclass:: passivetotal.analyzer.IPAddress
   :members:
   :inherited-members:


Module Reference
----------------
.. automodule:: passivetotal.analyzer
    :members:
   

Summary Data
------------
Hostnames and IPs offer a `summary` property that provides insight into how many
records are available across multiple PassiveTotal datasets, along with a few key
metrics about the host. 

Summary data offers an ideal starting point for hostname and IP analysis. The counts
directly inform security research and may guide subsequent searches.

.. autoclass:: passivetotal.analyzer.summary.HostnameSummary
   :members:
   :inherited-members:

.. autoclass:: passivetotal.analyzer.summary.IPSummary
   :members:
   :inherited-members:


Whois Records
-------------
The `whois` property for host names returns the DomainWhois record for
the registered domain name portion of the host name. 

.. code-block:: python

   >>> from passivetotal import analyzer
   >>> analyzer.init()
   >>> print(analyzer.Hostname('riskiq.net').whois.registrant.organization)
   RiskIQ UK Limited

Whois data varies widely across Internet registrars and registries, and although 
the API tries to normalize and parse the data into fields, your code should always be
prepared for missing or malformed data. Access the `raw` record for the API response 
directly as a Python dict or use the `record` property to get the raw Whois response.

The RiskIQ PassiveTotal API can  search Whois records by field to find related
domain names with the same contact information. Use the `records` property of
supported fields (any property that returns type `WhoisField`).

.. code-block:: python

   >>> from passivetotal import analyzer
   >>> analyzer.Hostname('riskiq.net').whois.organization.records.domains
   {Hostname('riskiq.com'), Hostname('riskiq.net'), Hostname('riskiqeg.com')}


.. autoclass:: passivetotal.analyzer.whois.DomainWhois
   :members:
   :inherited-members:

.. autoclass:: passivetotal.analyzer.whois.WhoisField
   :members:
   :inherited-members:

.. autoclass:: passivetotal.analyzer.whois.WhoisContact
   :members:
   :inherited-members:



Threat Intel Articles
---------------------
RiskIQ publishes threat intelligence articles with lists of IOCs (indicators of
compromise). Using the Analyzer module, you can retrieve the entire list of
currently published articles, or only those articles that are associated with an
IP or hostname. 

**Fetch all articles**

.. code-block:: python

   >>> from passivetotal import analyzer
   >>> analyzer.init()
   >>> articles = analyzer.AllArticles()
   >>> for article in articles[0:3]: # retrieve the first 3 articles
           print(article)
   Threat Roundup for April 23 to April 30
   PortDoor: New Chinese APT Backdoor Attack Targets Russian Defense Sector
   UNC2447 SOMBRAT and FIVEHANDS Ransomware: A Sophisticated Financial Threat
   
**Get articles for an IP and list other IOCs.**

.. code-block:: python

   >>> from passivetotal import analyzer
   >>> analyzer.init()
   >>> for article in analyzer.IPAddress('23.95.97.59').articles:
           print(article.title)
           print('  HOSTNAMES:')
           for hostname in article.hostnames:
               print(f'    {hostname}')
           print('  IPs:')
           for ip in article.ips:
               print(f'    {ip}')
   Alert (AA20-302A) - Ransomware Activity Targeting the Healthcare and Public Health Sector
   HOSTNAMES:
       biillpi.com
       chishir.com
       dns1.yastatic.cf
       ...
   IPs:
       195.123.240.219
       195.123.241.12
       195.123.242.119
       ...
   ...

.. autoclass:: passivetotal.analyzer.articles.AllArticles
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.articles.Article
    :members:
    :inherited-members:


Pandas Integration
------------------

The `analyzer` module contains an optional integration with the Pandas_ Python 
library. `pandas` is a robust data analytics toolset that integrates especially
well with Jupyter Notebooks. Even if you don't plan to use the more sophisticated
features `pandas` offers, the vastly improved display of `analyzer` results in
notebooks is well worth enabling the integration. 

To get started, install the `pandas` Python package, ideally in a
`virtual environment <https://docs.python.org/3/library/venv.html>`_:

``pip install pandas``

Nearly all `analyzer` objects offer results formatted as a Pandas `DataFrame`,
which is the standard two-dimensional (tabluar) data format in Pandas. You can access
the data with the `as_df` property or by calling the `to_dataframe()` method on an 
analyzer object. For example:

``analyzer.Hostname('riskiq.net').summary.as_df``

If this is the last line of a cell in a Jupyter notebook, and you run that
cell, you'll get a one-line tabular output with the summary data in columns. 

To view a list of pDNS records:

``analyzer.Hostname('riskiq.net').resolutions.as_df``

Internally, the `as_df` property calls `to_dataframe()` on each object with
no parameters, which results in a default rendering of the dataframe. Some objects,
like :class:`passivetotal.analyzer.illuminate.ReputationScore`, offer additional options
in their implementation of `to_dataframe()`. For example:
``analyzer.Hostname('jquery.su').reputation.to_dataframe(explode_rules=True)``

This will show the reputation score with one row for each rule returned by the
Reputation API. It uses the pandas `DataFrame.explode` method to unstack a list into
a set of rows and columns, hence the parameter name `explode_rules`.

Pandas dataframes are easily exported as CSV and offer capabilities to perform
SQL-style joins and Excel-style VLOOKUPs. Consult the docs to learn what's possible.


.. _Pandas: https://pandas.pydata.org/docs/index.html




Using Record Lists
------------------
Several attributes of Hostnames and IPs return lists of records from the API. The
analyzer module delivers these as list-like objects that can be looped through
like regular Python lists. They also provide analytic methods to sort
and filter records in meaningful ways.

Under normal usage, it should not be necessary to instantiate these objects
directly. You will interact with them through the properties of higher-level
objects like Hostnames and IPs.


Passive DNS Record Lists
^^^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.pdns.PdnsResolutions
   :members:
   :inherited-members:


.. autoclass:: passivetotal.analyzer.pdns.PdnsRecord
    :members:
    :inherited-members:


SSL Certificate Record Lists
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.ssl.Certificates
   :members:
   :inherited-members:


.. autoclass:: passivetotal.analyzer.ssl.CertificateRecord
   :members:
   :inherited-members:


.. autoclass:: passivetotal.analyzer.ssl.CertHistoryRecord
   :members:
   :inherited-members:


.. autoclass:: passivetotal.analyzer.ssl.CertificateField
   :members:
   :inherited-members:

Services Record Lists
^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.services.Services
   :members:
   :inherited-members:

.. autoclass:: passivetotal.analyzer.services.ServiceRecord
   :members:
   :inherited-members:

Hostpairs Record Lists
^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.hostpairs.HostpairHistory
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.hostpairs.HostpairRecord
    :members:
    :inherited-members:

Web Component Record Lists
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.components.ComponentHistory
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.components.ComponentRecord
    :members:
    :inherited-members:

Cookies Record Lists
^^^^^^^^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.cookies.CookieHistory
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.cookies.CookieRecord
    :members:
    :inherited-members:

Trackers Record Lists
^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: passivetotal.analyzer.trackers.TrackerHistory
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.trackers.TrackerRecord
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.trackers.TrackerSearchResults
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.trackers.TrackerSearchRecord
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.trackers.Tracker
    :members:
    :inherited-members:


Whois Record Lists
^^^^^^^^^^^^^^^^^^
.. autoclass:: passivetotal.analyzer.whois.WhoisRecords
    :members:
    :inherited-members:


Articles Lists
^^^^^^^^^^^^^^
.. autoclass:: passivetotal.analyzer.articles.ArticlesList
    :members:
    :inherited-members:

Malware Lists
^^^^^^^^^^^^^^
.. autoclass:: passivetotal.analyzer.enrich.MalwareList
    :members:
    :inherited-members:

.. autoclass:: passivetotal.analyzer.enrich.MalwareRecord
    :members:
    :inherited-members:

Project Lists
^^^^^^^^^^^^^^
    .. autoclass:: passivetotal.analyzer.projects.ProjectList
        :members:
        :inherited-members:
    
    .. autoclass:: passivetotal.analyzer.projects.Project
        :members:
        :inherited-members:

Artifact Lists
^^^^^^^^^^^^^^
    .. autoclass:: passivetotal.analyzer.projects.ArtifactList
        :members:
        :inherited-members:
    
    .. autoclass:: passivetotal.analyzer.projects.Artifact
        :members:
        :inherited-members: