from datetime import date
from passivetotal.analyzer import get_api
from passivetotal.analyzer._common import (
    Record, RecordList, AnalyzerError, ForPandas
)



class MalwareList(RecordList, ForPandas):

    """List of malware hashes associated with a host or domain."""

    def _get_shallow_copy_fields(self):
        return ['_query','totalrecords']
    
    def _get_sortable_fields(self):
        return ['date_collected','source']
    
    def _get_dict_fields(self):
        return ['totalrecords']
        
    @property
    def totalrecords(self):
        return len(self._records)
    
    def parse(self, api_response):
        """Parse an API response into a list of records."""
        self._api_success = api_response.get('success',None)
        self._records = []
        for result in api_response.get('results',[]):
            self._records.append(MalwareRecord(result, query=self._query))



class MalwareRecord(Record, ForPandas):

    """Record of malware associated with a host."""

    def __init__(self, api_response, query=None):
        self._date_collected = api_response.get('collectionDate')
        self._sample = api_response.get('sample')
        self._source = api_response.get('source')
        self._source_url = api_response.get('sourceUrl')
        self._query = query

    def __str__(self):
        return '' if self.hash is None else self.hash
    
    def __repr__(self):
        return "<MalwareRecord {0.hash}>".format(self)
    
    def _get_dict_fields(self):
        return ['hash','source','source_url','str:date_collected']
    
    def to_dataframe(self):
        """Render this object as a Pandas DataFrame.

        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['query','date_collected','hash','source','source_url']
        as_d = {
            f: getattr(self, f) for f in cols
        }
        return pd.DataFrame([as_d], columns=cols)
    
    @property
    def hash(self):
        """Hash of the malware sample."""
        return self._sample
    
    @property
    def query(self):
        """Query submitted to the API (typically the hostname or IP address)."""
        return self._query

    @property
    def source(self):
        """Source where the malware sample was obtained."""
        return self._source
    
    @property
    def source_url(self):
        """URL to malware sample source."""
        return self._source_url
    
    @property
    def date_collected(self):
        """Date the malware was collected, as a Python date object."""
        try:
            parsed = date.fromisoformat(self._date_collected)
        except Exception:
            raise AnalyzerError
        return parsed



class HasMalware:

    """An object (ip or domain) with malware samples."""

    def _api_get_malware(self):
        """Query the enrichment API for malware samples."""
        query=self.get_host_identifier()
        try:
            response = get_api('Enrichment').get_malware(
                query=query
            )
        except Exception:
            raise AnalyzerError('Error querying enrichment API for malware samples')
        self._malware = MalwareList(response, query=query)
        return self._malware

    @property
    def malware(self):
        """List of malware hashes associated with this host.

        :rtype: :class:`passivetotal.analyzer.enrich.MalwareList`
        """
        if getattr(self, '_malware', None) is not None:
            return self._malware
        return self._api_get_malware()
     