Introduction
============
In order to use the PassiveTotal libraries, you must have a PassiveTotal account. Registration is free and can be done before installation by going to https://www.passivetotal.org/register. Once verified, you will be able to access your account settings and begin running queries.

Quick Start
-----------
The PassiveTotal library provides several different ways to interact with data. The easiest way to get started with the API is to use our built-in command line interface. Once installed, queries can be run directly from the command line with no need to write code or make any configuration changes.


1. Install the library using pip or the local setup file:

``pip install passivetotal`` or ``python setup.py install``

2. Copy the API key from your PassiveTotal `account <https://www.passivetotal.org/account_settings/>`_

3. Use the pt-config tool to set your API key:

``pt-config setup <your-username> <your-api-key>``

4. Grab some passive DNS data:

``pt-client pdns --query www.passivetotal.org --sources=pingly --format=table``


Library Organization
--------------------
This library is organized in such a way that users can pick and choose the data they wish to interact with. Each primary data type we reference in our API and CLI tool is available for individual use. In fact, our CLI tool is built on the same libraries exposed to you!

Each data type has an API abstraction that will get the raw data from the API and a corresponding results class that can load the results into a Python object. Loading results into the result objects provide you with flexible ways to interact and export the result data.