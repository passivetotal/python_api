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


