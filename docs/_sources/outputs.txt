Output Formats
==============
Each dataset library supports a number of different output formats. These are accessible inside of the command line tools using the "--format" switch, but can also be accessed when developing your own tools. At the time of writing this documentation, many of the dataset libraries support the following formats: XML, JSON, STIX, text, table, and CSV. Our goal was to remove the trouble of formatting all the data yourself and instead focusing on doing your own research.

Text
----
pt-client pdns --query passivetotal.org --sources=riskiq --format=text

.. code-block:: text

    [*] Query: passivetotal.org
    [*] First Seen: 2014-04-16 02:12:09
    [*] Last Seen: 2016-01-29 21:15:02
    [*] Total Records: 26
    [*] Records:
    => First Seen           Last Seen               Resolution      Sources
    => 2016-01-05 01:39:57  2016-01-29 21:15:02     54.153.123.93   riskiq
    => 2016-01-05 00:00:02  2016-01-25 17:00:01     52.8.228.23     riskiq
    => 2016-01-05 01:39:57  2016-01-25 09:07:41     54.153.123.93   riskiq
    => 2016-01-05 00:00:02  2016-01-24 17:00:01     52.8.228.23     riskiq

Table
-----
pt-client pdns --query passivetotal.org --sources=riskiq --format=table

.. code-block:: text

    firstSeen            lastSeen             recordHash                                                        resolve          source
    -------------------  -------------------  ----------------------------------------------------------------  ---------------  --------
    2016-01-05 01:39:57  2016-01-29 21:15:02  d19d3cb8026c07e84791d883dd98483b66640b9fc42b74196597a6b85c22bb18  54.153.123.93    riskiq
    2016-01-05 00:00:02  2016-01-25 17:00:01  28cdf5e5bed46f8f73d9cc91b87eb33bbd2ab7977cd63f9472826b3f99c1a2ad  52.8.228.23      riskiq
    2016-01-05 01:39:57  2016-01-25 09:07:41  09e08ff92cfa093c4455ba2abccb1ac30053b763e13673dacc6c9db90c152c41  54.153.123.93    riskiq
    2016-01-05 00:00:02  2016-01-24 17:00:01  0474c83de81c3b25cff311d4924608e16a2228e55d9edd70da94fa661afde000  52.8.228.23      riskiq

CSV
---
pt-client pdns --query passivetotal.org --sources=riskiq --format=csv

.. code-block:: text

    firstSeen, lastSeen, recordHash, resolve, source
    2016-01-05 01:39:57, 2016-02-02 04:15:02, e3a9bb4ab8e324b0878c6399c93f2ee4cb1ddf048e5b0851668f5ff402f7bbe4, 54.153.123.93, riskiq
    2016-01-05 00:00:02, 2016-01-25 17:00:01, 28cdf5e5bed46f8f73d9cc91b87eb33bbd2ab7977cd63f9472826b3f99c1a2ad, 52.8.228.23, riskiq
    2016-01-05 00:00:02, 2016-01-25 17:00:01, 11f8f6ef801ef8c2ccc368b948392916384ebd5285928f7960782a7133a5df85, 54.153.123.93, riskiq, passivetotal.org
    2016-01-05 00:00:02, 2016-01-25 17:00:01, 28cdf5e5bed46f8f73d9cc91b87eb33bbd2ab7977cd63f9472826b3f99c1a2ad, 52.8.228.23, riskiq

STIX
----
pt-client pdns --query passivetotal.org --sources=riskiq --format=stix

.. code-block:: text

    <stix:STIX_Package
            xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
            xmlns:cybox="http://cybox.mitre.org/cybox-2"
            xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
            xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
            xmlns:example="http://example.com"
            xmlns:indicator="http://stix.mitre.org/Indicator-2"
            xmlns:stix="http://stix.mitre.org/stix-1"
            xmlns:stixCommon="http://stix.mitre.org/common-1"
            xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="example:Package-bf7c0664-5ec1-4ed9-b53b-985c8e952195" version="1.2">
        <stix:STIX_Header>
            <stix:Description>Passive DNS resolutions associated with passivetotal.org during the time periods of  2014-04-16 02:12:09 - 2016-01-29 21:15:02</stix:Description>
        </stix:STIX_Header>
        <stix:Indicators>
            <stix:Indicator id="example:indicator-f839a8fe-6fbc-4f08-aa0e-e11656406100" timestamp="2016-02-02T06:06:53.894284+00:00" xsi:type='indicator:IndicatorType'>
                <indicator:Title>Observed from 2016-01-05 01:39:57 - 2016-01-29 21:15:02</indicator:Title>
                <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
                <indicator:Description>Passive DNS data collected and aggregated from PassiveTotal services.</indicator:Description>
                <indicator:Short_Description>Resolution observed by riskiq.</indicator:Short_Description>
                <indicator:Observable id="example:Observable-44341837-418a-4e24-b1ab-13fafd86ccd8">
                    <cybox:Object id="example:Address-6e8fe132-bf88-4d25-bb55-6044d96c128a">
                        <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr">
                            <AddressObj:Address_Value condition="Equals">54.153.123.93</AddressObj:Address_Value>
                        </cybox:Properties>
                    </cybox:Object>
                </indicator:Observable>
            </stix:Indicator>
        </stix:Indicators>
    </stix:STIX_Package>

JSON
----
pt-client pdns --query passivetotal.org --sources=riskiq --format=json

.. code-block:: text

    {
        "totalRecords": 26,
        "records": [
            {
                "source": [
                    "riskiq"
                ],
                "resolve": "107.170.89.121",
                "lastSeen": "2014-04-16 02:12:09",
                "firstSeen": "2014-04-16 02:12:09",
                "recordHash": "ebad20bf05d81e2e5e9075ee4d3b93d663f7a7e492792d0ac1c2cdaa49a78711"
            }
        ],
        "lastSeen": "2016-01-29 21:15:02",
        "pager": null,
        "firstSeen": "2014-04-16 02:12:09",
        "queryValue": "passivetotal.org"
    }

XML
---
pt-client pdns --query passivetotal.org --sources=riskiq --format=xml

.. code-block:: text

    <?xml version="1.0" encoding="UTF-8"?>
    <root>
        <totalRecords type="int">26</totalRecords>
        <records type="list">
            <item type="dict">
                <source type="list">
                    <item type="str">riskiq</item>
                </source>
                <resolve type="str">54.153.123.93</resolve>
                <lastSeen type="str">2016-01-29 21:15:02</lastSeen>
                <firstSeen type="str">2016-01-05 01:39:57</firstSeen>
                <recordHash type="str">d19d3cb8026c07e84791d883dd98483b66640b9fc42b74196597a6b85c22bb18</recordHash>
            </item>
        </records>
        <lastSeen type="str">2016-01-29 21:15:02</lastSeen>
        <pager type="null"/>
        <firstSeen type="str">2014-04-16 02:12:09</firstSeen>
        <queryValue type="str">passivetotal.org</queryValue>
    </root>

