WHOIS Results
=============

WHOIS is availble in two different ways with the PassiveTotal client. Users can get WHOIS details, or run searches against specific fields.

.. code-block:: python
    :linenos:

    from passivetotal.libs.whois import WhoisRequest
    from passivetotal.libs.whois import WhoisResponse

    client = WhoisRequest.from_config()
    raw_results = client.get_whois_details(
        query="www.passivetotal.org"
    )

    loaded = WhoisResponse(raw_results)
    print loaded.text


WhoisRequest
------------

.. autoclass:: passivetotal.libs.whois.WhoisRequest
    :members:
    :show-inheritance:

WhoisResponse
-------------

.. autoclass:: passivetotal.libs.whois.WhoisResponse
    :members:
    :show-inheritance: