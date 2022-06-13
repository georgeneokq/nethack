import argparse
from ospf_hijack import *

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

    args = parser.parse_args()
    attack = args.attack

    if attack == 'ospf':
        spam_hello_and_advertisements(networks=args.networks)
    

if __name__ == '__main__':
    main()