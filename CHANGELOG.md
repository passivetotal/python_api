# Changelog

## v2.4.0

#### Enhancements:

- Early implementation of exception handling for SSL properties; analyzer.
  AnalyzerError now available as a base exception type.
- SSL certs will now populate their own `ip` property, accessing the
  SSL history API when needed to fill in the details.
- New `iphistory` property of SSL certs to support the `ip` property and
  give direct access to the historial results.
- Used the `tldextract` Python library to expose useful properties on Hostname
  objects such as `tld`, `registered_domain`, and `subdomain`
- Change default days back for date-aware searches to 90 days (was 30)
- Reject IPs as strings for Hostname objects
- Ensure IPs are used when instantiating IPAddress objects
- Defang hostnames (i.e. `analyzer.Hostname('api[.]riskiq[.]net')` )
- Support for Articles as a property of Hostnames and IPs, with autoloading
  for detailed fields including indicators, plus easy access to a list of all
  articles directly from `analyzer.AllArticles()`
- Support for Malware as a property of Hostnames and IPs
- Better coverage of pretty printing and dictionary representation across
  analyzer objects.


#### Bug Fixes:

- Exception handling when no details found for an SSL certificate.
- Proper handling of None types that may have prevented result caching

---