import argparse
from eigrp_hijack import *
from dns_hijack import *

def main():
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers(dest='attack')
  subparsers.required = True
  
  eigrp_subparser = subparsers.add_parser('eigrp')
  eigrp_subparser.add_argument('networks',
    nargs='+',
    type=str,
    action='store',
    help="Space-separated network addresses in CIDR notation"
  )

  dns_subparser = subparsers.add_parser('dns')
  dns_subparser.add_argument('map',
    nargs='+',
    type=str,
    action='store',
    help="Space separated mappings, each key-value being colon-separated",
  )

  args = parser.parse_args()
  attack = args.attack

  if attack == 'eigrp':
    eigrp_inject_routes(networks=args.networks)
  
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