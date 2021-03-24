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

Module Reference
----------------
.. automodule:: passivetotal.analyzer
   :members:


Hostname Analysis
-----------------
**Example Usage**

.. code-block:: python

   >>> from passivetotal import analyzer
   >>> host = analyzer.Hostname('riskiq.net')
   >>> registrant = host.whois.organization
   >>> print(registrant.organization)
   RiskIQ UK Limited

.. autoclass:: passivetotal.analyzer.Hostname
   :members:


IP Analysis
-----------
**Example Usage**
   
.. code-block:: python
   
   >>> from passivetotal import analyzer
   >>> ip = analyzer.IPAddress('35.189.71.51')
   >>> print(ip.summary)
   22 records available for 35.189.71.51
   >>> for record in ip.resolutions:
           print(record)
   A "trafficplus.name" [   6 days ] (2021-01-01 to 2021-03-01)


.. autoclass:: passivetotal.analyzer.IPAddress
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

.. autoclass:: passivetotal.analyzer.whois.DomainWhois
   :members:
   :inherited-members:



Using Record Lists
------------------
Several attributes of Hostnams and IPs return lists of records from the API. The
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