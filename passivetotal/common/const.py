WHOIS_VALID_FIELDS = ['domain', 'email', 'name', 'organization'
                      'address', 'phone', 'nameserver']
WHOIS_SECTIONS = ['admin', 'tech', 'registrant']
WHOIS_SECTION_FIELDS = ['section', 'query', 'city', 'country', 'email', 'name',
                        'organization', 'postalCode', 'state', 'street']

SSL_VALID_FIELDS = ["issuer_surname", "subject_organizationName",
                    "issuer_country", "issuer_organizationUnitName",
                    "fingerprint", "subject_organizationUnitName",
                    "serialNumber", "subject_emailAddress",
                    "subject_country", "issuer_givenName",
                    "subject_commonName", "issuer_commonName",
                    "issuer_stateOrProvinceName", "issuer_province",
                    "subject_stateOrProvinceName", "sha1", "sslVersion",
                    "subject_streetAddress", "subject_serialNumber",
                    "issuer_organizationName", "subject_surname",
                    "subject_localityName", "issuer_streetAddress",
                    "issuer_localityName", "subject_givenName",
                    "subject_province", "issuer_serialNumber",
                    "issuer_emailAddress"]

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
