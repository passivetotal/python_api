from datetime import datetime
import pprint
from passivetotal.analyzer._common import RecordList, Record, FirstLastSeen
from passivetotal.analyzer import get_api, get_config



class Certificates(RecordList):
    
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
        return self.sorted_by('lastseen', True)[0]
    
    @property
    def oldest(self):
        return self.sorted_by('firstseen')[0]
    
    @property
    def expired(self):
        return self.filter(expired=True)
    
    @property
    def not_expired(self):
        return self.filter(expired=False)



class CertificateField:
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
        print('api search')
        if type(self._value) == list:
            raise ValueError('Cannot search a list')
        response = get_api('SSL').search_ssl_certificate_by_field(query=self._value, field=self._name)
        self._certificates = Certificates(response)
        return self._certificates
    
    @property
    def name(self):
        return self._name
    
    @property
    def value(self):
        if type(self._value) == list and self._name == 'subjectAlternativeNames':
            return [CertificateField('subjectAlternativeName', altname) for altname in self._value ]
        return self._value
    
    @property
    def certificates(self):
        if self._certificates==None:
            self._api_search()
        return self._certificates



class CertificateRecord(Record, FirstLastSeen):
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
    
    @property
    def as_dict(self):
        return { field: getattr(self, field).value for field in self.__class__._fields }
    
    @property
    def pretty(self):
        config = get_config('pprint')
        return pprint.pformat(self.as_dict, **config)

    @property
    def hash(self):
        return self._sha1
    
    @property
    def sha1(self):
        return self.hash

    @property
    def issuerCountry(self):
        return self._get_field('issuerCountry')
    
    @property
    def issuerDate(self):
        return self._get_field('issuerDate')
    
    @property
    def date_issued(self):
        return datetime.strptime(self.issuerDate.value, '%b %d %H:%M:%S %Y %Z')
    
    @property
    def days_valid(self):
        interval = self.date_expires - self.date_issued
        return interval.days
    
    @property
    def subjectCommonName(self):
        return self._get_field('subjectCommonName')
    
    @property
    def subjectSurname(self):
        return self._get_field('subjectSurname')
    
    @property
    def subjectOrganizationUnitName(self):
        return self._get_field('subjectOrganizationUnitName')
    
    @property
    def subjectGivenName(self):
        return self._get_field('subjectGivenName')

    @property
    def fingerprint(self):
        return self._get_field('fingerprint')
    
    @property
    def issuerStateOrProvinceName(self):
        return self._get_field('issuerStateOrProvinceName')
    
    @property
    def issuerCommonName(self):
        return self._get_field('issuerCommonName')
    
    @property
    def issuerGivenName(self):
        return self._get_field('issuerGivenName')
    
    @property
    def subjectLocalityName(self):
        return self._get_field('subjectLocalityName')
    
    @property
    def subjectOrganizationName(self):
        return self._get_field('subjectOrganizationName')
    
    @property
    def issueDate(self):
        return self._get_field('issueDate')
    
    @property
    def subjectEmailAddress(self):
        return self._get_field('subjectEmailAddress')
    
    @property
    def subjectProvince(self):
        return self._get_field('subjectProvince')
    
    @property
    def subjectStateOrProvinceName(self):
        return self._get_field('subjectStateOrProvinceName')
    
    @property
    def issuerEmailAddress(self):
        return self._get_field('issuerEmailAddress')
    
    @property
    def subjectSerialNumber(self):
        return self._get_field('subjectSerialNumber')
    
    @property
    def issuerProvince(self):
        return self._get_field('issuerProvince')
    
    @property
    def issuerOrganizationUnitName(self):
        return self._get_field('issuerOrganizationUnitName')
    
    @property
    def serialNumber(self):
        return self._get_field('serialNumber')
    
    @property
    def issuerSurname(self):
        return self._get_field('issuerSurname')
    
    @property
    def issuerStreetAddress(self):
        return self._get_field('issuerStreetAddress')
    
    @property
    def issuerLocalityName(self):
        return self._get_field('issuerLocalityName')
    
    @property
    def expirationDate(self):
        return self._get_field('expirationDate')
    
    @property
    def date_expires(self):
        return datetime.strptime(self.expirationDate.value, '%b %d %H:%M:%S %Y %Z')
    
    @property
    def expired(self):
        return datetime.utcnow() > self.date_expires
    
    @property
    def issuerOrganizationName(self):
        return self._get_field('issuerOrganizationName')
    
    @property
    def subjectStreetAddress(self):
        return self._get_field('subjectStreetAddress')
    
    @property
    def sslVersion(self):
        return self._get_field('sslVersion')
    
    @property
    def issuerSerialNumber(self):
        return self._get_field('issuerSerialNumber')
    
    @property
    def subjectCountry(self):
        return self._get_field('subjectCountry')
    
    @property
    def subjectAlternativeNames(self):
        return self._get_field('subjectAlternativeNames')
        



class CertHistoryRecord(CertificateRecord):

    def __init__(self, record):
        self._firstseen = record.get('firstSeen')
        self._lastseen = record.get('lastSeen')
        if type(self._firstseen) == int:
            self._firstseen = datetime.fromtimestamp(self._firstseen / 1000).isoformat()
        if type(self._lastseen) == int:
            self._lastseen = datetime.fromtimestamp(self._lastseen / 1000).isoformat()
        self._ips = record.get('ipAddresses',[])

    def __str__(self):
        ips = 'ip' if len(self._ips)==1 else 'ips'
        return '{0.hash} on {ipcount} {ips} from {0.firstseen_date} to {0.lastseen_date}'.format(self, ipcount=len(self._ips), ips=ips)
    
    def __repr__(self):
        return "<CertHistoryRecord '{0.hash}'>".format(self)
    
    def _api_get_details(self):
        response = get_api('SSL').get_ssl_certificate_details(query=self._sha1)
        self._cert_details = response['results'][0] # API oddly returns an array
        self._has_details = True
        return self._cert_details
    
    def _ensure_details(self):
        if self._has_details:
            return
        self._api_get_details()

    @property
    def ips(self):
        from passivetotal.analyzer import IPAddress
        for ip in self._ips:
            yield IPAddress(ip)


    