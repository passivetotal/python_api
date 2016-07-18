import sys
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.dns import DnsUniqueResponse
from passivetotal.libs.whois import WhoisRequest
from passivetotal.libs.whois import WhoisResponse
from passivetotal.common.utilities import is_ip

query = sys.argv[1]
if not is_ip(query):
    raise Exception("This script only accepts valid IP addresses!")
    sys.exit(1)

# look up the unique resolutions
client = DnsRequest.from_config()
raw_results = client.get_unique_resolutions(query=query)
loaded = DnsUniqueResponse(raw_results)

whois_client = WhoisRequest.from_config()
for record in loaded.get_records()[:3]:
    raw_whois = whois_client.get_whois_details(query=record.resolve)
    whois = WhoisResponse(raw_whois)
    print(record.resolve, whois.contactEmail)
