from datetime import datetime, timezone
from collections import namedtuple
from passivetotal.analyzer import get_config



WhoisContact = namedtuple('WhoisContact',['organization','name','email','telephone'])



class DomainWhois:

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
        return 'registrant: "{0.org} | {0.registrant_name} | {0.registrant_email}"'

    def __repr__(self):
        return "DomainWhois('{}')".format(self.domain)
    
    def _get_contacts(self, contact_type):
        """Build a contact record from part of the API response."""
        if not self._rawrecord:
            values = [None, None, None, None]
        if contact_type == 'root':
            values = [ self._rawrecord.get(field) for field in ['organization','name','contactEmail','telephone'] ]
        else:
            values = [ self._rawrecord[contact_type].get(field) for field in ['organization','name','email','telephone'] ]
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
            return datetime.fromisoformat(fixed)
        finally:
            return None
    
    @property
    def domain(self):
        """The domain name as returned by the API."""
        return self._domain
    
    @property
    def registrant(self):
        """Domain registrant contact record.

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
    def contacts(self):
        """Primary domain contact records.

        :rtype: WhoisContact
        """
        return self._get_contacts('root')
    
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
    def nameservers(self):
        """List of nameservers."""
        return self._rawrecord.get('nameServers', [])
    
    @property
    def registrar(self):
        """Registrar of record for the domain name."""
        return self._rawrecord.get('registrar')
    
    @property
    def server(self):
        """Whois server that delivered the record."""
        return self._rawrecord.get('whoisServer')
    
    @property
    def date_registered(self):
        """Date the domain was registered.

        :rtype: datetime
        """
        return self._parsedate('registered')
    
    @property
    def date_loaded(self):
        """Date when the domain was loaded into the database.

        :rtype: datetime
        """
        return self._parsedate('lastLoadedAt')
    
    @property
    def date_updated(self):
        """Date when the domain was updated at the registrar or registry.

        Be aware that registrars and registries may not reliably update this date
        when the contents of the record changes. Even when they do, it usually only
        means the domain was renewed or expired, or the nameservers were changed.

        :rtype: datetime
        """
        return self._parsedate('registryUpdatedAt')
    
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
    
    @property
    def record(self):
        """Raw API response."""
        return self._rawrecord.get('rawText')
    


