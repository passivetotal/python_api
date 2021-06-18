# Changelog

## v2.5.0

#### Enhancements:

- Raise `AnalyzerAPIError` when a non-200 response is returned from the API.
- Add SSL hash field to list of SSL fields in dictionary output for more convenient
  integrations.
- Add firstseen and lastseen dates to SSL Certificate records.
- Optional support for the Pandas data analysis library. Adds as_df property to all
  Analyzer objects to render the object as a Pandas dataframe. 
- Add option to specify module-level date ranges with `datetime` objects for
  easier integration with other libraries.
- Subdomain API support with the `subdomains` property of Hostname objects.



#### Bug Fixes

- `is_ip()` regex fix to avoid matching on hostnames with embedded IPs.
- Fixed broken `available` property on summary objects.
- Fixed missing publish date on Articles




## v2.4.2

#### Enhancements:

- Throw `AnalyzerError` when a hostname cannot be resolved to an IP
- Add links to summary card as_dict method



#### Bug Fixes

- Added missing docstring for `services` property
- Fixed various issues with `as_dict` property to ensure only serializable
  types made it into the dictionary. 
- Ensured Projects would load by GUID regardless of visiblity.
- Removed a partially-implemented __str__ method in `MalwareList` method
- Ensured all __str__ methods in `analyzer` objects always return a string
- Upserting an artifact triggered an API error when setting a tag
- Ensure `summary` property returns ints, not None, when fields are missing
- Properly handle defanged ip addresses 
- Exclude Nones from sets in various properties to avoid problems with `NoneTypes`


## v2.4.1

#### Enhancements:

- Added an `as_dict` property across all Analyzer objects to simplify integration
  with other systems. Returns a dictionary representation of the object or the list.
- New `projects` attribute on IPAddress and Hostname objects returns list of projects
  that contain that host as an artifact. 
- New `analyzer.set_project()` method on the Analyzer module to set an active project
  by name or guid, and new `add_to_project()` methods on Analyzer objects to quickly
  add the object to the active project.
- Direct methods on new `Project` and `Artifact` objects to directly manipulate monitoring
  status and tags.


#### Bug Fixes:

- Added missing ArtifactsRequest to package-level imports



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