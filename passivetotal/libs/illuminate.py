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
    
    def get_asi_summary(self):
        """Get attack surface intelligence summary for the main organization 
        associated with an API account.

        Reference: https://api.riskiq.net/api/asi_thirdparty/

        :return: Dict of results
        """
        return self._get('attack-surface', '')
    
    def get_asi_priority(self, level, **kwargs):
        """Get attack surface intelligence priority detail.
        
        Reference: https://api.riskiq.net/api/asi_thirdparty/

        :param level: Priority level to retrieve details for [high, medium, low]
        :return: Dict of results
        """
        return self._get('attack-surface', 'priority', level, **kwargs)
    
    def get_asi_insights(self, insight_id, **kwargs):
        """Get attack surface intelligence assets by insight ID.

        Reference: https://api.riskiq.net/api/asi_thirdparty/

        :return: Dict of results
        """
        return self._get('attack-surface', 'insight', insight_id, **kwargs)
    
    def get_asi_3p_vendors(self, **kwargs):
        """Get list of attack surface intelligence third party vendors.

        Reference: https://api.riskiq.net/api/asi_thirdparty/

        :return: Dict of results
        """
        return self._get('attack-surface', 'third-party', **kwargs)
    
    def get_asi_3p_vendor_summary(self, vendor_id):
        """Get attack surface intelligence summary for a third-party vendor.

        Reference: https://api.riskiq.net/api/asi_thirdparty/

        :return: Dict of results
        """
        return self._get('attack-surface', 'third-party', str(vendor_id))
    
    def get_asi_3p_vendor_priority(self, vendor_id, level, **kwargs):
        """Get attack surface intelligence priorities for a third-party vendor.

        Reference: https://api.riskiq.net/api/asi_thirdparty/

        :return: Dict of results
        """
        path = 'third-party/{0}/priority/{1}'.format(vendor_id, level)
        return self._get('attack-surface', path, **kwargs)
    
    def get_asi_3p_vendor_insights(self, vendor_id, insight_id, **kwargs):
        """Get attack surface intelligence insights for a third-party vendor.

        Reference: https://api.riskiq.net/api/asi_thirdparty/

        :return: Dict of results
        """
        path = 'third-party/{0}/insight/{1}'.format(vendor_id, insight_id)
        return self._get('attack-surface', path, **kwargs)
    
    def get_asi_vuln_components(self, **kwargs):
        """Get attack surface vulnerable components.
        
        Reference: https://api.riskiq.net/api/asi_thirdparty/#!/default/get_pt_v2_attack_surface_vuln_intel_components
        
        :return: Dict of results
        """
        return self._get('attack-surface', 'vuln-intel/components', **kwargs)
    
    def get_asi_vuln_cves(self, **kwargs):
        """Get attack surface vulnerabilities.
        
        Reference: https://api.riskiq.net/api/asi_thirdparty/#!/default/get_pt_v2_attack_surface_vuln_intel_cves
        
        :return: Dict of results
        """
        return self._get('attack-surface', 'vuln-intel/cves', **kwargs)
    
    def get_asi_vuln_cve_observations(self, cve_id, **kwargs):
        """Get attack surface observations for a given CVE.
        
        Reference: https://api.riskiq.net/api/asi_thirdparty/#!/default/get_pt_v2_attack_surface_vuln_intel_cves_cveId_observations
        
        :return: Dict of results
        """
        path = 'vuln-intel/cves/{0}/observations'.format(cve_id)
        return self._get('attack-surface', path, **kwargs)

    def get_asi_3p_vuln_components(self, vendor_id, **kwargs):
        """Get attack surface vulnerable components for a third-party vendor.
        
        Reference: https://api.riskiq.net/api/asi_thirdparty/#!/default/get_pt_v2_attack_surface_vuln_intel_third_party_id_components
        
        :return: Dict of results
        """
        path = 'vuln-intel/third-party/{0}/components'.format(vendor_id)
        return self._get('attack-surface', path, **kwargs)
    
    def get_asi_3p_vuln_cves(self, vendor_id, **kwargs):
        """Get attack surface vulnerabilities for a third-party vendor.
        
        Reference: https://api.riskiq.net/api/asi_thirdparty/#!/default/get_pt_v2_attack_surface_vuln_intel_third_party_id_cves
        
        :return: Dict of results
        """
        path = 'vuln-intel/third-party/{0}/cves'.format(vendor_id)
        return self._get('attack-surface', path, **kwargs)
    
    def get_asi_3p_vuln_cve_observations(self, vendor_id, cve_id, **kwargs):
        """Get attack surface observations for a given CVE and third-party vendor ID.
        
        Reference: https://api.riskiq.net/api/asi_thirdparty/#!/default/get_pt_v2_attack_surface_vuln_intel_third_party_id_cves_cveId_observations
        
        :return: Dict of results
        """
        path = 'vuln-intel/third-party/{0}/cves/{1}/observations'.format(vendor_id, cve_id)
        return self._get('attack-surface', path, **kwargs)
    
    def get_vuln_article(self, cve_id, **kwargs):
        """Get details on a CVE vulnerability article.
        
        Reference: https://api.riskiq.net/api/vulnerability/#!/default/get_pt_v2_vuln_intel_article_cveId
        
        :return: Dict of results
        """
        path = 'article/{0}'.format(cve_id)
        return self._get('vuln-intel', path, **kwargs)





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