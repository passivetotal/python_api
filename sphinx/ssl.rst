SSL Results
===========

SSL certificates are availble in three different ways with the PassiveTotal client. Users can get SSL certificate details, run searches against specific fields or get the history of a specific SSL certificate.

.. code-block:: python
    :linenos:

    from passivetotal.libs.ssl import SslRequest
    from passivetotal.libs.ssl import SslResponse

    client = SslRequest.from_config()
    raw_results = client.get_ssl_certificate_details(
        query="www.passivetotal.org"
    )

    loaded = SslResponse(raw_results)
    print loaded.table


SslRequest
----------

.. autoclass:: passivetotal.libs.ssl.SslRequest
    :members:
    :show-inheritance:

SslHistoryReponse
-----------------

.. autoclass:: passivetotal.libs.ssl.SslHistoryReponse
    :members:
    :show-inheritance:

HistoryRecord
-------------

.. autoclass:: passivetotal.libs.ssl.HistoryRecord
    :members:
    :show-inheritance: