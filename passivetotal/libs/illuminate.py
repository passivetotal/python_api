"""RiskIQ Illuminate API Interface."""

from textwrap import TextWrapper
from passivetotal.api import Client
from passivetotal.response import Response
from passivetotal.common import utilities



class IlluminateRequest(Client):

    """Client to interface with the RiskIQ Illuminate calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(IlluminateRequest, self).__init__(*args, **kwargs)

    def get_reputation(self, **kwargs):
        """Get RiskIQ Illuminate score for a domain or IP address.

        Reference: https://api.riskiq.net/api/reputation/

        :param query: Domain or IP address to search
        :return: Dict of results
        """
        return self._get('reputation', '', **kwargs)
    
    def get_intel_profiles(self, **kwargs):
        """Get RiskIQ Intel Profiles.

        Reference: https://api.riskiq.net/api/intel-profiles/

        :return: Dict of results
        """
        return self._get('intel-profiles', '', **kwargs)
    
    def get_intel_profile_details(self, profile_id):
        """Get intel profile details on a specific actor group.

        Reference: https://api.riskiq.net/api/intel-profiles/

        :param profile_id: Text identifier of the actor group.
        :return: Dict of results
        """
        return self._get('intel-profiles', profile_id)
    
    def get_intel_profile_indicators(self, profile_id, **kwargs):
        """Get IOCs associated with an intel profile.

        Reference: https://api.riskiq.net/api/intel-profiles/

        :param profile_id: Text identifier of the actor group.
        :return: Dict of results
        """
        return self._get('intel-profiles', profile_id, 'indicators', **kwargs)
    
    def get_intel_profiles_for_indicator(self, indicator, **kwargs):
        """Check whether an indicator is associated with any intel profiles.

        Reference: https://api.riskiq.net/api/intel-profiles/

        :param indicator: String representation of the IOC.
        :return: Dict of results
        """
        return self._get('intel-profiles','indicator', query=indicator, **kwargs)



class IlluminateReputationResponse(Response):

    def _boost_properties(self):
        pass
    
    @property
    def csv(self):
        fieldnames = ['host','score','classification']
        if 'rules' in self._results[0]:
            fieldnames.extend(['rule_names','rule_descriptions'])
        data = []
        for record in self._results:
            row = [
                record.get('host'),
                record.get('score'),
                record.get('classification')
            ]
            if 'rules' in record:
                row.extend([
                    '|'.join(['{0} (sev. {1})'.format(r.get('name'), r.get('severity')) for r in record.get('rules',[])]),
                    '|'.join([r.get('description') for r in record.get('rules',[])]),
                ])
            data.append(row)
        as_csv = utilities.to_csv(fieldnames, data)
        return as_csv
    
    @property
    def text(self):
        wrapper = TextWrapper(width=60, initial_indent='      ', subsequent_indent='      ')
        lines = []
        width = max([len(r.get('host','')) for r in self._results])
        for record in self._results:
            template = '{host: <' + str(width) + '} {score:>3} ({c})'
            lines.append(template.format(
                host=record['host'],
                score=record.get('score',''),
                c=record.get('classification','')))
            for rule in record.get('rules',[]):
                lines.append('   {name} (severity {sev})'.format(
                    name=rule.get('name'),
                    sev=rule.get('severity')
                ))
                lines.extend(wrapper.wrap(rule.get('description')))
        lines.append('')
        return "\n".join(lines)