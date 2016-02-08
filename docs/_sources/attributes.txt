Attribute Results
=================

Attributes bring the power of page content and other details gleaned from Internet-scanning into your hands. Over time, as more datasets are released, attributes will be one of the primary mechanisms for querying or interacting with that data.

.. code-block:: python
    :linenos:

    from passivetotal.libs.attributes import AttributeRequest
    from passivetotal.libs.attributes import AttributeResponse

    client = AttributeRequest.from_config()
    raw_results = client.get_host_attribute_trackers(
        query="www.passivetotal.org"
    )

    loaded = AttributeResponse(raw_results)
    print loaded.table

AttributeResponse
-----------------
.. autoclass:: passivetotal.libs.attributes.AttributeResponse
    :members:
    :undoc-members:
    :show-inheritance:

GeneticAttributeRecord
----------------------
.. autoclass:: passivetotal.libs.attributes.GeneticAttributeRecord
    :members:
    :show-inheritance:
