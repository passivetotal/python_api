from datetime import datetime, timezone
from collections import namedtuple
from passivetotal.analyzer import get_config



WhoisContact = namedtuple('WhoisContact',['organization','name','email','telephone'])



class DomainWhois:
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
        if not self._rawrecord:
            values = [None, None, None, None]
        if contact_type == 'root':
            values = [ self._rawrecord.get(field) for field in ['organization','name','contactEmail','telephone'] ]
        else:
            values = [ self._rawrecord[contact_type].get(field) for field in ['organization','name','email','telephone'] ]
        return WhoisContact._make(values)
    
    def _parsedate(self, field):
        datestr = self._rawrecord.get(field)
        if not datestr:
            return None
        try:
            return datetime.fromisoformat(self._rawrecord[field])
        except ValueError:
            pass
        fixed = datestr[:-2] + ':00'
        return datetime.fromisoformat(fixed)
    
    @property
    def domain(self):
        return self._domain
    
    @property
    def registrant(self):
        return self._get_contacts('registrant')
    
    @property
    def tech(self):
        return self._get_contacts('tech')
    
    @property
    def billing(self):
        return self._get_contacts('billing')
    
    @property
    def admin(self):
        return self._get_contacts('admin')
    
    @property
    def contacts(self):
        return self._get_contacts('root')
    
    @property
    def name(self):
        return self.contacts.name
    
    @property
    def organization(self):
        return self.contacts.organization
    
    @property
    def email(self):
        return self.contacts.email
    
    @property
    def telephone(self):
        return self.contacts.telephone
    
    @property
    def registrant_org(self):
        return self.registrant.organization
    
    @property
    def registrant_name(self):
        return self.registrant.name
    
    @property
    def registrant_email(self):
        return self.registrant.email

    @property
    def registrant_phone(self):
        return self.registrant.telephone
    
    @property
    def nameservers(self):
        return self._rawrecord.get('nameServers', [])
    
    @property
    def registrar(self):
        return self._rawrecord.get('registrar')
    
    @property
    def server(self):
        return self._rawrecord.get('whoisServer')
    
    @property
    def date_registered(self):
        return self._parsedate('registered')
    
    @property
    def date_loaded(self):
        return self._parsedate('lastLoadedAt')
    
    @property
    def date_updated(self):
        return self._parsedate('registryUpdatedAt')
    
    @property
    def date_expires(self):
        return self._parsedate('expiresAt')
    
    @property
    def age(self):
        if not self.date_registered:
            return None
        now = datetime.now(timezone.utc)
        interval = now - self.date_registered
        return interval.days
    
    @property
    def record(self):
        return self._rawrecord
    


