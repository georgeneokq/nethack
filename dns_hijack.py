from scapy.all import *
from scapy.layers.dns import *
from netaddr import IPNetwork

TEST_MAPPING = {
  "10.33.1.3": "8.8.8.8"
}

def intercept_dns(intercept_map: dict):
  """
  Intercept DNS requests, given a dict where
  {
    <CIDR address>: <DNS answer IP>,
    ...
  }

  Parameters
  -----------
  intercept_map: dict
    Dictionary mapping of network address in CIDR notation, to an IP address to answer with.
    If the key is a single IP address instead of a range, it can be specified without /32 prefix.
  """
  answer_map = {}
  print('Mapping:')
  for [network, answer_ip] in intercept_map.items():
    # "Unpack" the IP addresses in the range and create a more specific mapping
    # for every host in the range
    print(f'{network} -> {answer_ip}')
    for host in IPNetwork(network).iter_hosts():
      answer_map[str(host)] = answer_ip
  
  def intercept(packet: Packet):
    if packet.haslayer('DNS') and packet['IP'].src in answer_map:
      origin_src = packet['IP'].src
      dns: DNS = packet['DNS']
      requested_domain = dns.qd.qname
      reply_packet = (
        IP(dst=origin_src) /
        UDP(sport=53, dport=packet['UDP'].sport) /
        DNS(qr=1, an=DNSRR(rrname=requested_domain, rdata=answer_map[origin_src]))
      )
      send(reply_packet)


  # Sniff for DNS packets and answer accordingly
  sniff(prn=intercept)

if __name__ == '__main__':
  intercept_dns(TEST_MAPPING)