DNS Results
===========

Passive DNS results come in two primary flavors, full results and unique results. Each class makes use of a respective wrapper class for each record to make working with content easy. Additionally, once loaded into the result wrapper, you can easily get data out in a number of formats.

.. code-block:: python
    :linenos:

    from passivetotal.libs.dns import DnsRequest
    from passivetotal.libs.dns import DnsResponse

    client = DnsRequest.from_config()
    raw_results = client.get_passive_dns(
        query="www.passivetotal.org",
        sources="riskiq"
    )

    loaded = DnsResponse(raw_results)
    print loaded.table


DnsResponse
-----------
.. autoclass:: passivetotal.libs.dns.DnsResponse
    :members:
    :show-inheritance:

DnsRecord
---------
.. autoclass:: passivetotal.libs.dns.DnsRecord
    :members:
    :show-inheritance:

DnsUniqueResponse
-----------------
.. autoclass:: passivetotal.libs.dns.DnsUniqueResponse
    :members:
    :show-inheritance:

UniqueDnsRecord
---------------
.. autoclass:: passivetotal.libs.dns.UniqueDnsRecord
    :members:
    :show-inheritance: