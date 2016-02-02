Developers
==========

This client library was built with developers in mind. Our goal was to provide our clients with an easy way to use PassiveTotal data inside their own tools or organizations. Below is a walkthrough of building a simple tool to output WHOIS emails for a list of passive DNS domains. Additionally, check out our source code for "pt-client" in order to see how we used the libraries available to you to build our CLI tool.

Building a Simple Tool
----------------------

Lets say you are doing research on an IP address and want to understand who registered the domains that have the top number of resolutions over time. Going about that inside the PassiveTotal web interface would be tedious and difficult, but easy in code.

For this tool, we are going to need a few system libraries, the DNS and WHOIS libraries as well as their result counterparts. We can begin by importing like this:

.. code-block:: python
    :linenos:

    import sys
    from passivetotal.libs.dns import DnsClient
    from passivetotal.libs.dns import DnsUniqueResult
    from passivetotal.libs.whois import WhoisClient
    from passivetotal.libs.whois import WhoisResult

Next, we want to grab the IP address from the user directly as an argument on the command line, then look up all the unique domain names that have associated with it.

.. code-block:: python
    :linenos:

    query = sys.argv[1]

    # look up the unique resolutions
    client = DnsClient.from_config()
    raw_results = client.get_unique_resolutions(
        query=query
    )

    # load the result into our class
    loaded = DnsUniqueResult(raw_results)

Our "loaded" variable now has the contents of the unique passive DNS call and comes with a few helper methods. The goal now is to loop over the top 3 results and perform a WHOIS look-up on them in order to get the registrant email address.

.. code-block:: python
    :linenos:

    whois_client = WhoisClient.from_config()
    for record in loaded.get_records()[:3]:
        raw_whois = whois_client.get_whois_details(
            query=record.resolve
        )
        whois = WhoisResult(raw_whois)
        print record.resolve, whois.contactEmail

Well, that was easy. The full copy of the code should look like the following:

.. code-block:: python
    :linenos:

    import sys
    from passivetotal.libs.dns import DnsClient
    from passivetotal.libs.dns import DnsUniqueResult
    from passivetotal.libs.whois import WhoisClient
    from passivetotal.libs.whois import WhoisResult

    query = sys.argv[1]

    # look up the unique resolutions
    client = DnsClient.from_config()
    raw_results = client.get_unique_resolutions(
        query=query
    )

    loaded = DnsUniqueResult(raw_results)

    whois_client = WhoisClient.from_config()
    for record in loaded.get_records()[:3]:
        raw_whois = whois_client.get_whois_details(
            query=record.resolve
        )
        whois = WhoisResult(raw_whois)
        print record.resolve, whois.contactEmail

If you wanted, you could begin extending this script more or cleaning it up a bit by placing some of the lookups inside of functon calls. Additionally, we could constrain the user input to only accepting IP addresses. Our library comes with some helpful utilities and checking if a value is an IP address is one of them.

.. code-block:: python
    :linenos:

    from passivetotal.common.utilities import is_ip

    query = sys.argv[1]
    if not is_ip(query):
        raise Exception("This script only accepts valid IP addresses!")
        sys.exit(1)

For more ideas or help in using our libraries, check out our source code on Github.