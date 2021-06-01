Request Wrappers
================

These low-level wrappers provide direct access to specific PassiveTotal API
endpoints. To determine which wrapper to use, review the
`API documentation <https://api.passivetotal.org/index.html>`_ 
for a specific dataset, then select a wrapper with a similar name.

Call the `from_config()` class method to obtain an instance of a request wrapper 
pre-configured with your API credentials (as set by the pt-config CLI command):

.. code-block:: python
    :linenos:

    from passivetotal import WhoisRequest
    whois_req = WhoisRequest.from_config()

Each wrapper class in this module can be directly imported from the `passivetotal`
module for convenience.


Account Client
--------------
.. autoclass:: passivetotal.libs.account.AccountClient
    :members:
    :show-inheritance:

Actions Request
---------------
.. autoclass:: passivetotal.libs.actions.ActionsClient
    :members:
    :show-inheritance:

Articles Request
----------------
.. autoclass:: passivetotal.libs.articles.ArticlesRequest
    :members:
    :show-inheritance:

Artifacts Request
-----------------
.. autoclass:: passivetotal.libs.artifacts.ArtifactsRequest
    :members:
    :show-inheritance:

Attribute Request
-----------------
.. autoclass:: passivetotal.libs.attributes.AttributeRequest
    :members:
    :show-inheritance:

Cards Request
-------------
.. autoclass:: passivetotal.libs.cards.CardsRequest
    :members:
    :show-inheritance:

Cookies Request
---------------
.. autoclass:: passivetotal.libs.cookies.CookiesRequest
    :members:
    :show-inheritance:

DNS Request
-----------
.. autoclass:: passivetotal.libs.dns.DnsRequest
    :members:
    :show-inheritance:

Generic Request
---------------
.. autoclass:: passivetotal.libs.generic.GenericRequest
    :members:
    :show-inheritance:

Projects Request
----------------
.. autoclass:: passivetotal.libs.projects.ProjectsRequest
    :members:
    :show-inheritance:

Illuminate Request
------------------
.. autoclass:: passivetotal.libs.illuminate.IlluminateRequest
    :members:
    :show-inheritance:

Services Request
----------------
.. autoclass:: passivetotal.libs.services.ServicesRequest
    :members:
    :show-inheritance:

SSL Request
-----------
.. autoclass:: passivetotal.libs.ssl.SslRequest
    :members:
    :show-inheritance:
    
WHOIS Request
-------------
.. autoclass:: passivetotal.libs.whois.WhoisRequest
    :members:
    :show-inheritance:

Enrichment Request
------------------
.. autoclass:: passivetotal.libs.enrichment.EnrichmentRequest
    :members:
    :show-inheritance: