# !usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from argparse import ArgumentParser
from dnsdb.api import APIClient
from dnsdb.clients import DnsDBClient
from getpass import getpass


def get_args():
    parser = ArgumentParser()
    parser.add_argument('-d', '--domain', help="search by domain")
    parser.add_argument('--host', help="search DNS by host")
    parser.add_argument('--ip', help="search DNS by ip")
    parser.add_argument('--type', help="search DNS by DNS type")
    parser.add_argument('--start', help="set result start position")
    parser.add_argument('-u', '--username', help="set username")
    parser.add_argument('-p', '--password', help="set password")
    parser.add_argument('-a', '--all', help='show all results', action='store_true', default=False)
    parser.add_argument('-o', '--output', help='set output file, default "-", "-" represents stdout', default='-')
    parser.add_argument('--api-url', help="set api URL", default='https://dnsdb.io/api/v1')
    return parser.parse_args()


def main():
    args = get_args()
    APIClient.API_BASE_URL = args.api_url
    username = args.username
    password = args.password
    domain = args.domain
    host = args.host
    dns_type = args.type
    ip = args.ip
    start = args.start
    get_all = args.all

    if username is None:
        username = raw_input("Username:")
    if password is None:
        password = getpass("Password:")

    client = DnsDBClient()
    client.login(username, password)
    if get_all:
        result = client.retrieve_dns(domain=domain, host=host, dns_type=dns_type, ip=ip, start=start)
    else:
        result = client.search_dns(domain=domain, host=host, dns_type=dns_type, ip=ip, start=start)
    output = args.output
    if output == '-':
        for record in result:
            print(record)
    else:
        with open(output, 'ab') as f:
            for record in result:
                f.write(str(record) + '\r\n')


if __name__ == '__main__':
    main()
