from datetime import datetime
import pprint
from passivetotal.analyzer._common import RecordList, Record, FirstLastSeen, AnalyzerError
from passivetotal.analyzer import get_api, get_config, get_object



class Certificates(RecordList):
    
    """List of historical SSL certificates."""

    def _get_shallow_copy_fields(self):
        return []

    def _get_sortable_fields(self):
        return ['firstseen','lastseen', 'duration']
    
    def parse(self, api_response):
        self._records = []
        for result in api_response.get('results',[]):
            self._records.append(CertHistoryRecord(result))
    
    @property
    def newest(self):
        """Most recently seen :class:`CertificateRecord`."""
        return self.sorted_by('lastseen', True)[0]
    
    @property
    def oldest(self):
        """Earliest seen :class:`CertificateRecord`."""
        return self.sorted_by('firstseen')[0]
    
    @property
    def expired(self):
        """Filtered list of :class:`Certificates` that have expired."""
        return self.filter(expired=True)
    
    @property
    def not_expired(self):
        """Filtered list of :class:`Certificates' that have not expired."""
        return self.filter(expired=False)



class CertificateField:

    """A field on an SSL certificate. 

    Print or cast as string to access the value directly.

    In addition to a simple key/value mapping, this class also provides a
    `certificates` property that searches the API for other SSL certificates
    that match the key/value pair of the instance.
    """

    _instances = {}

    def __new__(cls, name, value):
        if type(value) == list:
            hashable_value = tuple(value) # make immutable
        else:
            hashable_value = value
        valuehash = hash(hashable_value)
        by_name = cls._instances.get(name)
        if not by_name:
            cls._instances[name] = {}
        self = cls._instances[name].get(valuehash)
        if not self:
            self = cls._instances[name][valuehash] = object.__new__(cls)
            self._name = name
            self._value = value
            self._certificates = None
        return self
    
    def __str__(self):
        if not self._value:
            return ''
        if type(self._value) == list:
            return ','.join(self._value)
        return self._value
    
    def __repr__(self):
        return "CertificateField('{0.name}','{0.value}')".format(self)
    
    def _api_search(self):
        """Use the 'SSL' request wrapper to perform an SSL certificate search by field."""
        if type(self._value) == list:
            raise ValueError('Cannot search a list')
        try:
            response = get_api('SSL').search_ssl_certificate_by_field(query=self._value, field=self._name)
        except Exception:
            raise AnalyzerError
        self._certificates = Certificates(response)
        return self._certificates
    
    @property
    def name(self):
        """Name of the field."""
        return self._name
    
    @property
    def value(self):
        """Value of the field.

        May return a list if the name is 'subjectAlternativeName'.
        """
        if type(self._value) == list and self._name == 'subjectAlternativeNames':
            return [CertificateField('subjectAlternativeName', altname) for altname in self._value ]
        return self._value
    
    @property
    def certificates(self):
        """List of :class:`Certificates` that match the key/value of this field."""
        if self._certificates==None:
            self._api_search()
        return self._certificates



class CertificateRecord(Record, FirstLastSeen):

    """SSL Certificate record.
    
    This base class is suited for API responses with complete certificate details.
    """

    _instances = {}
    _fields = ['issuerCountry','subjectCommonName','subjectOrganizationName','subjectGivenName','subjectSurname',
               'fingerprint','issuerStateOrProvinceName','issuerCommonName','subjectLocalityName',
               'issuerDate','subjectEmailAddress','subjectProvince','subjectStateOrProvinceName',
               'issuerEmailAddress','subjectSerialNumber','issuerProvince','issuerOrganizationUnitName',
               'serialNumber','issuerSurname','issuerStreetAddress','issuerLocalityName',
               'subjectStreetAddress','issuerSerialNumber','issuerOrganizationName',
               'sslVersion','expirationDate','issuerGivenName','subjectCountry','subjectAlternativeNames']

    def __new__(cls, record):
        recordhash = record['sha1']
        self = cls._instances.get(recordhash)
        if self is None:
            self = cls._instances[recordhash] = object.__new__(cls)
            self._sha1 = record.get('sha1')
            self._values = {}
            if 'fingerprint' in record: # test if record has details
                self._cert_details = record
                self._has_details = True
            else:
                self._cert_details = {}
                self._has_details = False
        return self
    
    def _ensure_details(self):
        return
    
    def _get_field(self, fieldname):
        self._ensure_details()
        value = self._values.get(fieldname)
        if not value:
            self._values[fieldname] = CertificateField(fieldname, self._cert_details.get(fieldname))
        return self._values[fieldname]
    
    def _api_get_ip_history(self):
        try:
            response = get_api('SSL').get_ssl_certificate_history(query=self.hash)
        except Exception as e:
            raise AnalyzerError
        self._ip_history = response['results'][0]
        return self._ip_history
    
    def _get_dict_fields(self):
        fields = self.__class__._fields
        fields.extend(['days_valid','expired'])
        return fields
    
    @property
    def iphistory(self):
        """Get the direct API response for a history query on this certificates hash.
        
        For most use cases, the `ips` property is a more direct route to get the list
        of IPs previously associated with this SSL certificate.
        """
        if getattr(self, '_ip_history', None) is not None:
            return self._ip_history
        return self._api_get_ip_history()
    
    @property
    def ips(self):
        """Provides list of :class:`passivetotal.analyzer.IPAddress` instances
        representing IP addresses associated with this SSL certificate."""
        history = self.iphistory
        ips = []
        if history['ipAddresses'] == 'N/A':
            return ips
        for ip in history['ipAddresses']:
            try:
                ips.append(get_object(ip,'IPAddress'))
            except AnalyzerError:
                continue
        return ips

    @property
    def hash(self):
        """Certificate hash value."""
        return self._sha1
    
    @property
    def sha1(self):
        """Certificate hash value (alias for `hash`)."""
        return self.hash

    @property
    def issuerCountry(self):
        """Certificate issuer country.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerCountry')
    
    @property
    def issuerDate(self):
        """Certificate issue date field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerDate')
    
    @property
    def date_issued(self):
        """Date & time the certificate was issued.
        
        :rtype: datetime
        """
        if self.issuerDate.value is None:
            return None
        return datetime.strptime(self.issuerDate.value, '%b %d %H:%M:%S %Y %Z')
    
    @property
    def days_valid(self):
        """Number of days the certificate is valid.

        Returns the timedelta between date_expires and date_issued.
        :rtype: int
        """
        if self.date_expires is None or self.date_issued is None:
            return None
        interval = self.date_expires - self.date_issued
        return interval.days
    
    @property
    def subjectCommonName(self):
        """Certificate subject common name field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectCommonName')
    
    @property
    def subjectSurname(self):
        """Certificate subject surname field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectSurname')
    
    @property
    def subjectOrganizationUnitName(self):
        """Certificate subject organizational unit name field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectOrganizationUnitName')
    
    @property
    def subjectGivenName(self):
        """Certificate subject given name field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectGivenName')

    @property
    def fingerprint(self):
        """Certificate fingerprint field.
        
        :rtype: CertificateField
        """
        return self._get_field('fingerprint')
    
    @property
    def issuerStateOrProvinceName(self):
        """Certificate issuer state or province name field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerStateOrProvinceName')
    
    @property
    def issuerCommonName(self):
        """Certificate issuer common name field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerCommonName')
    
    @property
    def issuerGivenName(self):
        """Certificate issuer given name field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerGivenName')
    
    @property
    def subjectLocalityName(self):
        """Certificate subject locality name field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectLocalityName')
    
    @property
    def subjectOrganizationName(self):
        """Certificate subject organization name field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectOrganizationName')
    
    @property
    def issueDate(self):
        """Certificate issue date field.
        
        :rtype: CertificateField
        """
        return self._get_field('issueDate')
    
    @property
    def subjectEmailAddress(self):
        """Certificate subject email address field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectEmailAddress')
    
    @property
    def subjectProvince(self):
        """Certificate subject province field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectProvince')
    
    @property
    def subjectStateOrProvinceName(self):
        """Certificate subject state or province name field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectStateOrProvinceName')
    
    @property
    def issuerEmailAddress(self):
        """Certificate issuer email address field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerEmailAddress')
    
    @property
    def subjectSerialNumber(self):
        """Certificate subject serial number field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectSerialNumber')
    
    @property
    def issuerProvince(self):
        """Certificate issuer province field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerProvince')
    
    @property
    def issuerOrganizationUnitName(self):
        """Certificate issuer orgnaizational unit name field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerOrganizationUnitName')
    
    @property
    def serialNumber(self):
        """Certificate issuer serial number field.
        
        :rtype: CertificateField
        """
        return self._get_field('serialNumber')
    
    @property
    def issuerSurname(self):
        """Certificate issuer surname field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerSurname')
    
    @property
    def issuerStreetAddress(self):
        """Certificate issuer street address field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerStreetAddress')
    
    @property
    def issuerLocalityName(self):
        """Certificate issuer locality name field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerLocalityName')
    
    @property
    def expirationDate(self):
        """Certificate expiration date field.
        
        :rtype: CertificateField
        """
        return self._get_field('expirationDate')
    
    @property
    def date_expires(self):
        """Date & time when the certificate expires.
        
        :rtype: datetime
        """
        if self.expirationDate.value is None:
            return None
        return datetime.strptime(self.expirationDate.value, '%b %d %H:%M:%S %Y %Z')
    
    @property
    def expired(self):
        """Whether the certificate has expired (if the expiration date is in the past).
        
        :rtype: bool
        """
        if self.date_expires is None:
            return None
        return datetime.utcnow() > self.date_expires
    
    @property
    def issuerOrganizationName(self):
        """Certificate issuer organization name field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerOrganizationName')
    
    @property
    def subjectStreetAddress(self):
        """Certificate subject street address field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectStreetAddress')
    
    @property
    def sslVersion(self):
        """Certificate ssl version field.
        
        :rtype: CertificateField
        """
        return self._get_field('sslVersion')
    
    @property
    def issuerSerialNumber(self):
        """Certificate serial number field.
        
        :rtype: CertificateField
        """
        return self._get_field('issuerSerialNumber')
    
    @property
    def subjectCountry(self):
        """Certificate subject country field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectCountry')
    
    @property
    def subjectAlternativeNames(self):
        """Certificate subject alternative names field.
        
        :rtype: CertificateField
        """
        return self._get_field('subjectAlternativeNames')
        



class CertHistoryRecord(CertificateRecord):

    """SSL Certificate historical record. 

    Suited for API responses that may not provide SSL certificate details. Provides
    a mechanism to populate missing data with a call to the SSL certificate detail
    API upon first request of a missing field.
    """

    def __init__(self, record):
        self._firstseen = record.get('firstSeen')
        self._lastseen = record.get('lastSeen')
        if type(self._firstseen) == int:
            self._firstseen = datetime.fromtimestamp(self._firstseen / 1000).isoformat()
        if type(self._lastseen) == int:
            self._lastseen = datetime.fromtimestamp(self._lastseen / 1000).isoformat()
        self._ips = record.get('ipAddresses',[])

    def __str__(self):
        return '{0.hash} from {0.firstseen_date} to {0.lastseen_date}'.format(self)
    
    def __repr__(self):
        return "<CertHistoryRecord '{0.hash}'>".format(self)
    
    def _api_get_details(self):
        """Query the SSL API for certificate details."""
        try:
            response = get_api('SSL').get_ssl_certificate_details(query=self._sha1)
        except Exception:
            raise AnalyzerError
        try:
            self._cert_details = response['results'][0] # API oddly returns an array
        except IndexError:
            raise SSLAnalyzerError('No details available for this certificate')
        self._has_details = True
        return self._cert_details
    
    def _ensure_details(self):
        """Ensure the certificate has all details populated.

        Triggers an API call if details are missing.
        """
        if self._has_details:
            return
        self._api_get_details()



class SSLAnalyzerError(AnalyzerError):
    """An exception raised when accessing SSL properties in the Analyzer module."""
    pass

    