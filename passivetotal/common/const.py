WHOIS_VALID_FIELDS = ['domain', 'email', 'name', 'organization',
                      'address', 'phone', 'nameserver']
WHOIS_SECTIONS = ['admin', 'tech', 'registrant']
WHOIS_SECTION_FIELDS = ['section', 'query', 'city', 'country', 'email', 'name',
                        'organization', 'postalCode', 'state', 'street']

SSL_VALID_FIELDS = ["issuerSurname", "subjectOrganizationName",
                    "issuerCountry", "issuerOrganizationUnitName",
                    "fingerprint", "subjectOrganizationUnitName",
                    "serialNumber", "subjectEmailAddress",
                    "subjectCountry", "issuerGivenName",
                    "subjectCommonName", "issuerCommonName",
                    "issuerStateOrProvinceName", "issuerProvince",
                    "subjectStateOrProvinceName", "sha1", "sslVersion",
                    "subjectStreetAddress", "subjectSerialNumber",
                    "issuerOrganizationName", "subjectSurname",
                    "subjectLocalityName", "issuerStreetAddress",
                    "issuerLocalityName", "subjectGivenName",
                    "subjectProvince", "issuerSerialNumber",
                    "issuerEmailAddress"]

CLASSIFICATION_VALID_VALUES = ['malicious', 'suspicious', 'non-malicious',
                               'unknown']
ACTIONS = 'actions'
ACTIONS_CLASSIFICATION = 'classification'
ACTIONS_DYNAMIC_DNS = 'dynamic-dns'
ACTIONS_EVER_COMPROMISED = 'ever-compromised'
ACTIONS_MONITOR = 'monitor'
ACTIONS_SINKHOLE = 'sinkhole'
ACTIONS_TAG = 'tags'
ENRICHMENT = 'enrichment'
