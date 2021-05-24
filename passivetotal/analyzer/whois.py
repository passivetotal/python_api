from datetime import datetime, timezone
from collections import namedtuple
import pprint
from passivetotal.analyzer import get_api, get_object
from passivetotal.analyzer._common import RecordList



WhoisContact = namedtuple('WhoisContact',['organization','name','email','telephone'])



class WhoisField:
    """Searchable field in a Whois record.

    Print or cast as string to access the value directly.

    Provides a `records` property that searches the API for other
    Whois records that match the value provided in the field.
    """

    _instances = {}

    def __new__(cls, name, value):
        if name=='telephone':
            name = 'phone'
        if name=='contactEmail':
            name = 'email'
        by_name = cls._instances.get(name)
        if not by_name:
            cls._instances[name] = {}
        self = cls._instances[name].get(value)
        if not self:
            self = cls._instances[name][value] = object.__new__(cls)
            self._name = name
            self._value = value
            self._records = None
        return self

    def __str__(self):
        if not self._value:
            return ''
        return self._value

    def __repr__(self):
        return "WhoisField('{0.name}','{0.value}')".format(self)

    def _api_search(self):
        """Use the 'Whois' request wrapper to perform a keyword search by field."""
        response = get_api('Whois').search_whois_by_field(field=self._name, query=self._value)
        self._records = WhoisRecords(response)
        return self._records

    @property
    def name(self):
        """Name of the field."""
        return self._name 
    
    @property
    def value(self):
        """Value of the field."""
        return self._value
    
    @property
    def records(self):
        """List of :class:`DomainWhois` records that match the key/value of this field."""
        if self._records==None:
            self._api_search()
        return self._records



class WhoisRecords(RecordList):

    """List of Whois records."""

    def _get_shallow_copy_fields(self):
        return []
    
    def _get_sortable_fields(self):
        return ['domain']
    
    def parse(self, api_response):
        """Parse an API response into a list of `DomainWhois` records."""
        self._records = list(map(DomainWhois, api_response.get('results',[])))
    
    @property
    def domains(self):
        """Return a set of unique domains in this record list."""
        return set([r.domain for r in self if r.domain])
    
    @property
    def emails(self):
        """Return a set of unique emails in this record list."""
        return set([r.email for r in self if r.email])
    
    @property
    def names(self):
        """Return a set of unique names in this record list."""
        return set([r.name for r in self if r.name])
    
    @property
    def orgs(self):
        """Return a set of unique org names in this record list."""
        return set([r.organization for r in self if r.organization])
    


class WhoisRecord:
    """Base type for IP and Domain Whois."""

    def _get_contacts(self, contact_type):
        """Build a contact record from part of the API response."""
        if not self._rawrecord:
            values = [None, None, None, None]
        if contact_type == 'root':
            values = [ WhoisField(field, self._rawrecord.get(field)) for field in ['organization','name','contactEmail','telephone'] ]
        else:
            values = [ WhoisField(field, self._rawrecord[contact_type].get(field)) for field in ['organization','name','email','telephone'] ]
        return WhoisContact._make(values)
    
    def _parsedate(self, field):
        """Try to parse a named field out of the raw Whois record."""
        datestr = self._rawrecord.get(field)
        if not datestr:
            return None
        try:
            return datetime.fromisoformat(self._rawrecord[field])
        except ValueError:
            fixed = datestr[:-2] + ':00'
        try:
            return datetime.fromisoformat(fixed)
        except ValueError:
            return None
        return None
    
    @property
    def as_dict(self):
        return self._rawrecord
    
    @property
    def pretty(self):
        """Pretty printed version of this object's dictionary representation."""
        from passivetotal.analyzer import get_config
        config = get_config('pprint')
        return pprint.pformat(self.as_dict, **config)

    @property
    def registrant(self):
        """Whois registrant contact record.

        :rtype: WhoisContact
        """
        return self._get_contacts('registrant')
    
    @property
    def tech(self):
        """Technical contact record.

        :rtype: WhoisContact
        """
        return self._get_contacts('tech')

    @property
    def contacts(self):
        """Primary domain contact records.

        :rtype: WhoisContact
        """
        return self._get_contacts('root')
    
    @property
    def billing(self):
        """Billing contact record.

        :rtype: WhoisContact
        """
        return self._get_contacts('billing')
    
    @property
    def admin(self):
        """Admin contact record.

        :rtype: WhoisContact
        """
        return self._get_contacts('admin')

    @property
    def name(self):
        """Primary registrant name."""
        return self.contacts.name
    
    @property
    def organization(self):
        """Primary contact organization name."""
        return self.contacts.organization
    
    @property
    def email(self):
        """Primary contact email address."""
        return self.contacts.email
    
    @property
    def telephone(self):
        """Primary contact telephone number."""
        return self.contacts.telephone
    
    @property
    def registrant_org(self):
        """Registrant organization from the registrant contact record."""
        return self.registrant.organization
    
    @property
    def registrant_name(self):
        """Registrant name from the registrant contact record."""
        return self.registrant.name
    
    @property
    def registrant_email(self):
        """Registrant email from the registrant contact record."""
        return self.registrant.email

    @property
    def registrant_phone(self):
        """Registrant telephone number from the registrant contact record."""
        return self.registrant.telephone

    @property
    def registrar(self):
        """Registrar of record for the domain or IP."""
        return self._rawrecord.get('registrar')
    
    @property
    def server(self):
        """Whois server that delivered the record."""
        return self._rawrecord.get('whoisServer')
    
    @property
    def date_registered(self):
        """Date the domain or IP was registered.

        :rtype: datetime
        """
        return self._parsedate('registered')
    
    @property
    def date_loaded(self):
        """Date when the domain or IP was loaded into the database.

        :rtype: datetime
        """
        return self._parsedate('lastLoadedAt')
    
    @property
    def date_updated(self):
        """Date when the domain or IP was updated at the registrar or registry.

        Be aware that registrars and registries may not reliably update this date
        when the contents of the record changes. Even when they do, it usually only
        means the domain was renewed or expired, or the nameservers were changed.

        :rtype: datetime
        """
        return self._parsedate('registryUpdatedAt')

    @property
    def record(self):
        """Raw Whois record as text."""
        return self._rawrecord.get('rawText')
    
    @property
    def raw(self):
        """Raw API response."""
        return self._rawrecord



class DomainWhois(WhoisRecord):

    """Whois record for an Internet domain name."""

    _instances = {}

    def __new__(cls, record):
        domain = record['domain']
        self = cls._instances.get(domain)
        if self is None:
            self = cls._instances[domain] = object.__new__(DomainWhois)
            self._domain = domain
            self._rawrecord = record
        return self
    
    def __str__(self):
        return 'registrant: "{0.organization} | {0.registrant_name} | {0.registrant_email}"'.format(self)

    def __repr__(self):
        return "DomainWhois('{}')".format(self.domain)
    
    @property
    def domain(self):
        """The domain name as returned by the API."""
        return get_object(self._domain,type='Hostname')
    
    @property
    def nameservers(self):
        """List of nameservers."""
        return self._rawrecord.get('nameServers', [])
    
    @property
    def date_expires(self):
        """Date the domain expires.

        :rtype: datetime
        """
        return self._parsedate('expiresAt')
    
    @property
    def age(self):
        """Number of days between now and when the domain was registered."""
        if not self.date_registered:
            return None
        now = datetime.now(timezone.utc)
        interval = now - self.date_registered
        return interval.days



class IPWhois(WhoisRecord):
    """Whois record for an IP Address."""

    _instances = {}

    def __new__(cls, record):
        domain = record['domain'] # yes, it's an IP, but this is where the data is
        self = cls._instances.get(domain)
        if self is None:
            self = cls._instances[domain] = object.__new__(IPWhois)
            self._domain = domain
            self._rawrecord = record
        return self
    
    def __str__(self):
        return 'registrant: "{0.organization} | {0.registrant_name} | {0.registrant_email}"'.format(self)

    def __repr__(self):
        return "IPWhois('{}')".format(self.ip)
    
    @property
    def ip(self):
        return get_object(self._domain, type='IPAddress')

