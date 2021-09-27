# Changelog

## v2.5.6

#### Bug fixes

- Fixed issue that broke Illuminate ASI and Vuln Intel analyzer modules in Python 3.7 and 
  earlier due to a missing param on the lru_cache decorator required in those versions.
- Fixed default end date behavior in analyzer to include a full day rather than stopping at
  midnight "today". Was causing records with a last-seen date equal to the current date
  to be excluded from analyzer record list objects (including pDNS, certificates, and 
  anything else that supported date-bounded queries).

  

## v2.5.5

#### Enhancements

- Support for new RiskIQ Illuminate Vulnerability Intelligence API endpoints in core API library.
- New `cves` property of AttackSurface objects finds vulnerabilities impacting assets within that
  attack surface. Works identically for the primary (your own) attack surface and third-party
  attack surfaces.
- New `AttackSurfaceCVEs` record list to contain a list of `AttackSurfaceCVE` objects, with properties
  to access the vulnerability report, RiskIQ priority score, and list of impacted assets.
- New `VulnArticle` object to provide details on a CVE and discover the list of third-party vendors
  with assets impacted by the vuln. Custom views in the article's `to_dataframe()` method render
  dataframes focused on article references, component detections, and third-party impacts.
- New helper method `analyzer.AttackSurface()` to directly load an attack surface. Works without params to load
  the main attack surface, with an ID to load a third-party vendor attack surface by ID, or with a string
  to find an attack surface by vendor name. 
- Re-organized Illuminate-specific code in the `analyzer` module into distinct files located under a
  subpackage. Existing imports in client code should not be impacted. 


#### Pull Requests

- Publishes pull request #38 "Remove ez_setup dependancy."




## v2.5.4

#### Enhancements

- Removed strict checking on tracker type to permit querying by arbitrary tracker types. Updated list
  of common trackers. Added searchType param to docs to reflect API's capability of returning either
  hostnames or addresses.
- New methods to search trackers in the `analyzer` module, including `tracker_references` property on
  `Hostname` and `IPAddress` objects to find other sites referencing the focus host in their tracker
  values.
- New `analyzer.Tracker` top-level entity with `observations_by_ip` and `observations_by_hostname`
  properties to find other hosts with the same tracker type and value. 
- New `filter_fn` method on all RecordList objects enables filtering a list by an arbitrary function.
  Helps reduce code duplication and enables more advanced filtering. 
- Monitoring API endpoint support in the core library, and new `alerts` property on 
  project artifacts to easily retrieve the list of new alerts for an artifact in a project.
  Handles pagination automatically and returns results in new analyzer objects to enable
  standard filtering and data representation (i.e. `as_dict` and `as_df`).
- Small change to the `get_object` method to tolerate passing it objects that are already
  `analyzer.Hostname` or `analyzer.IPAddress` objects.
- New `is_ip` and `is_hostname` methods on both `Hostname` and `IPAddress` objects to simplify
  code that operates against a list of hosts that may include objects of both types.
- New methods on Tracker search results and Hostpair results to exclude records with hostnames, 
  domains or tlds in a given list. This helps refine results to focus on "foreign" sites and enables direct
  application of proven phishing site detection use cases.



#### Bug Fixes

- Fixed incorrect constant reference in trackers API (by removing strict checking on
  tracker type).
- Fixed broken `age` property on Articles that was also causing `as_df` and `as_dict` to fail.
  Likely caused by missing time zone info in dates returned from the API. 



## v2.5.3

#### Enhancements

- Better support for unit tests in client libraries with ability to set a 
  session to override default request methods.
- Add flexibility to library class instantiation to prefer keyword parameters
  over config file keys. 
- Support for new `create_date` Articles API data field and query parameter. Enables
  searching for most recent articles instead of returning all of them at once, and
  provides visiblity to situations where an article published in the past was recently
  added to the Articles collection. 


#### Breaking Changes

- Previously, calls to `analyzer.AllArticles()` would return all articles without a date
  limit. Now, it will return only articles created after the starting date set with
  `analyzer.set_date_range()`. The current module-level default for all date-bounded queries
  is 90 days back, so now this function will return all articles created in the last 90 days.
- `age` property of an Article analyzer object is now based on `create_date` instead of publish
  date.


#### Bug Fixes

[ none ]



## v2.5.2

#### Enhancements

- Send new request headers for metrics and troubleshooting with the `set_context`
  method on the `analyzer` module and within the core API request libs.
- Abstract package version into a distinct file to consolidate updates and ensure
  consistency across docs and pypi. Add `get_version` method to `analyzer` module
  for easy access to the current version number.


#### Bug Fixes




## v2.5.1

#### Enhancements

- Adds support for the Illuminate CTI module with Intel Profile API library
  calls and `analzyer` objects. Includes support for all API parameters and
  handles pagination automatically.
- Adds support for Illuminate Attack Surface Intelligence including third-party
  attack surfaces. 
- Ability to filter all RecordList analyzer objects by a list of values using
  new `filter_in` method.
- Ability to filter all RecordList analyzer objects by a case-insensitive
  substring search using new `filter_substring` method. Especially useful for
  filtering a list of Attack Surface Insights or Attack Surface Third-Party vendors.



#### Bug Fixes

- Filter methods on RecordList objects now consistently return lists instead of
  filters.
- Property return NotImplemented type for base methods.
- Ensure strings are returned for firstseen / lastseen dates in certificates
  property. Was causing json encoding errors when trying to encode
  `certificates.as_dict`.
- Add missing `duration` property to pDNS `resolutions.as_dict`
- Fixed save_to_project() API call; was broken after introduction of new API 
  exception types.




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