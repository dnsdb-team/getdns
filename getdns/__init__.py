# -*- coding: utf-8 -*-
from __future__ import print_function

import csv
import datetime
import os
import re
import sys
import traceback
from argparse import ArgumentParser
from getpass import getpass

from colorama import Fore, Style
from dnsdb_sdk.api import APIClient
from dnsdb_sdk.exceptions import APIException
import json

__version__ = '0.1.2b1'

try:
    # python2
    from ConfigParser import ConfigParser, NoSectionError, NoOptionError
except ImportError:
    # python3
    from configparser import ConfigParser, NoSectionError, NoOptionError

CONFIG_PATH = os.path.expanduser("~/.getdns")


def show_error(message):
    sys.stderr.write(Fore.RED + message + Style.RESET_ALL)


def validate_ip(ip):
    pattern = re.compile('^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.'
                         '(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.'
                         '(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.'
                         '(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$')
    return pattern.match(ip) is not None


def check_search_params(domain, host, ip):
    if ip:
        if not validate_ip(ip):
            show_error('"%s" is not a valid IP address\n' % ip)
            sys.exit(-1)
    if domain is None and host is None and ip is None:
        show_error('You need to provide at least one parameter in "--domain", "--ip", "--host"\n')
        sys.exit(-1)


def get_output_file(output_path):
    if output_path == '-':
        return sys.stdout
    else:
        if os.path.exists(output_path):
            os.remove(output_path)
        return open(output_path, 'a')


def read_line(prompt=''):
    try:
        # python2
        return raw_input(prompt)
    except NameError:
        # python3
        return input(prompt)


def get_config_value(conf, section, option, default=None):
    try:
        return conf.get(section, option)
    except NoSectionError:
        pass
    except NoOptionError:
        pass
    return default


def get_defaults():
    defaults = {}
    if os.path.exists(CONFIG_PATH):
        conf = ConfigParser()
        conf.read(CONFIG_PATH)
        defaults['api_id'] = get_config_value(conf, 'auth', 'api-id', '')
        defaults['api_key'] = get_config_value(conf, 'auth', 'api-key', '')
        defaults['proxy'] = get_config_value(conf, 'settings', 'proxy', '')
        defaults['api_url'] = get_config_value(conf, 'settings', 'api-url', 'https://api.dnsdb.io')
    else:
        defaults['api_id'] = ''
        defaults['api_key'] = ''
        defaults['proxy'] = ''
        defaults['api_url'] = 'https://dnsdb.io/api'
    return defaults


class OutputFormatter(object):
    def __init__(self, json_format=None, csv_format=None, custom_format=None):
        self.json = json_format
        self.csv = csv_format
        self.custom_format = custom_format

    def format(self, record):
        if self.custom_format:
            line = self.custom_format.replace('#{host}', record.host).replace('#{type}', record.type).replace(
                '#{value}', record.value)
            line += '\n'
        else:
            line = json.dumps(dict(record)) + '\n'
        return line


class ProgressBar(object):
    def __init__(self, title='Progress', max_value=100):
        try:
            from progressive.bar import Bar
            self.support_progressive = True
            self.bar = Bar(max_value=max_value, title=title)
            self.bar.cursor.clear_lines(1)
            self.bar.cursor.save()
        except ImportError:
            self.support_progressive = False
            from progress.bar import Bar
            self.bar = Bar('Receiving', max=max_value)

    def next(self, count=0):
        if self.support_progressive:
            self.bar.cursor.restore()
            self.bar.draw(value=count)
        else:
            self.bar.next()

    def finish(self):
        if not self.support_progressive:
            self.bar.finish()


def process_output(result, output, formatter, max_result=None):
    global csv_writer, bar
    show_progress = output != sys.stdout
    if show_progress:
        if max_result and max_result < len(result):
            max_value = max_result
        else:
            max_value = len(result)
        bar = ProgressBar(title='Receiving', max_value=max_value)
    count = 0
    if formatter.csv:
        csv_file = output
        csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONNUMERIC)
    for record in result:
        if max_result and count >= max_result:
            break
        if formatter.csv:
            csv_writer.writerow([record.host, record.type, record.value])
        else:
            output.write(formatter.format(record))
        count += 1
        if show_progress:
            bar.next(count)
    if show_progress:
        bar.finish()


def do_search_cmd(args):
    APIClient.API_BASE_URL = args.api_url
    api_id = args.api_id
    api_key = args.api_key
    domain = args.domain
    host = args.host
    dns_type = args.type
    ip = args.ip
    value_domain = args.value_domain
    value_host = args.value_host
    value_ip = args.value_ip
    email = args.email
    page = args.page
    page_size = args.page_size
    get_all = args.all
    check_search_params(domain, host, ip)
    if not api_id:
        api_id = read_line("API ID:")
    if not api_key:
        api_key = getpass("API Key:")
    proxies = None
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
    client = APIClient(api_id, api_key, proxies=proxies)
    output = get_output_file(args.output)
    start_time = datetime.datetime.now()
    try:
        if get_all:
            result = client.scan_dns(domain=domain, host=host, dns_type=dns_type, ip=ip, value_domain=value_domain,
                                     value_host=value_host, value_ip=value_ip, email=email, per_size=page_size)
        else:
            result = client.search_dns(domain=domain, host=host, dns_type=dns_type, ip=ip, value_domain=value_domain,
                                       value_host=value_host, value_ip=value_ip, email=email, page=page,
                                       per_size=page_size)
        process_output(result, output, OutputFormatter(args.json, args.csv, args.format), args.max)
    except APIException as e:
        if args.debug:
            traceback.print_exc()
        show_error(str(e) + '\n')
    finally:
        output.flush()
        if args.verbose:
            print('Running time: %s' % (datetime.datetime.now() - start_time))
        if output != sys.stdout:
            output.close()


def show_api_user_cmd(args):
    APIClient.API_BASE_URL = args.api_url
    api_id = args.api_id
    api_key = args.api_key
    if not api_id:
        api_id = read_line("API ID:")
    if not api_key:
        api_key = getpass("API Key:")
    proxies = None
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
    client = APIClient(api_id, api_key, proxies=proxies)
    try:
        start_time = datetime.datetime.now()
        api_user = client.get_api_user()
        print(json.dumps(dict(api_user)))
        if args.verbose:
            print('Running time: %s' % (datetime.datetime.now() - start_time))
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        show_error(str(e) + '\n')


def config_cmd(args):
    if args.reset:
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
        return
    if args.show:
        defaults = get_defaults()
        print(defaults)
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'w') as f:
            f.write('[auth]\n[settings]\n')
    conf = ConfigParser()
    conf.read(CONFIG_PATH)
    if args.api_id:
        conf.set('auth', 'api-id', args.api_id)
    if args.api_key:
        conf.set('auth', 'api-key', args.api_key)
    if args.api_url:
        conf.set('settings', 'api-url', args.api_url)
    if args.proxy:
        conf.set('settings', 'proxy', args.proxy)
    conf.write(open(CONFIG_PATH, "w"))


def get_args():
    defaults = get_defaults()
    api_id = defaults['api_id']
    api_key = defaults['api_key']
    api_url = defaults['api_url']
    proxy = defaults['proxy']
    parser = ArgumentParser(description="getdns is DNS query tool power by dnsdb.io")
    dnsdb_python_sdk_version = __import__('dnsdb_sdk').__version__
    parser.add_argument('-V', '--version', action='version',
                        version='''getdns: %s dnsdb-python-sdk: %s''' % (__version__, dnsdb_python_sdk_version))
    subparsers = parser.add_subparsers(dest='cmd')
    subparsers.required = True

    proxy_help = 'set proxy. HTTP proxy: "http://user:pass@host:port/", SOCKS5 proxy: "socks://user:pass@host:port"'
    format_help = 'set custom output format. #{host} represents DNS record\'s host, #{type} represents DNS ' \
                  'record\'s type, #{value} represents DNS record\'s value. For example: -f "#{host},#{type},#{value}"'
    # search parser
    search_parser = subparsers.add_parser('search', help='search DNS records')
    search_group = search_parser.add_argument_group('search options')
    search_group.add_argument('-d', '--domain', help='search by domain')
    search_group.add_argument('-H', '--host', help='search DNS by host')
    search_group.add_argument('--ip', help='search DNS by ip')
    search_group.add_argument('-t', '--type', help='search DNS by DNS type')
    search_group.add_argument('--value-domain', help='search DNS by value_domain')
    search_group.add_argument('--value-host', help='search DNS by value_host')
    search_group.add_argument('--value-ip', help='search DNS by value_ip')
    search_group.add_argument('--email', help='search DNS by email')
    search_group.add_argument('--page', help='set query page number', type=int, default=1)
    search_group.add_argument('--page-size', help='set query page size', type=int, default=50)
    search_group.add_argument('-a', '--all', help='retrieve all results, it will ignored [--page] option',
                              action='store_true', default=False)
    auth_group = search_parser.add_argument_group('authentication options')
    auth_group.add_argument('-i', '--api-id', help='set API ID, default "%s"' % api_id, default=api_id)
    auth_group.add_argument('-k', '--api-key', help='set API key, default "%s"' % api_key, default=api_key)
    search_parser.add_argument('-o', '--output', help='specify output file, default "-", "-" represents stdout',
                               default='-')
    output_format_options = search_parser.add_mutually_exclusive_group()
    output_format_options.add_argument('-j', '--json', help='set JSON output', action='store_true', default=True)
    output_format_options.add_argument('-c', '--csv', help='set CSV output', action='store_true', default=False)
    output_format_options.add_argument('-f', '--format', help=format_help)
    search_parser.add_argument('-m', '--max', help='set the maximum number of search results for the output', type=int)
    search_parser.add_argument('-P', '--proxy', help=proxy_help, default=proxy)
    search_parser.add_argument('--api-url', help='set API URL, default "%s"' % api_url, default=api_url)
    search_parser.add_argument('-v', '--verbose', help='show verbose information', action='store_true', default=False)
    search_parser.add_argument('-D', '--debug', help='run in debug mode', action='store_true', default=False)
    search_parser.set_defaults(func=do_search_cmd)

    # api user parser
    api_user_parser = subparsers.add_parser('api-user', help='get API user information')
    auth_group = api_user_parser.add_argument_group('authentication options')
    auth_group.add_argument('-i', '--api-id', help='set API ID, default "%s"' % api_id, default=api_id)
    auth_group.add_argument('-k', '--api-key', help='set API key, default "%s"' % api_key, default=api_key)
    api_user_parser.add_argument('-P', '--proxy', help=proxy_help, default=proxy)
    api_user_parser.add_argument('--api-url', help='set API URL, default "%s"' % api_url, default=api_url)
    api_user_parser.add_argument('-v', '--verbose', help='show verbose information', action='store_true', default=False)
    api_user_parser.add_argument('-D', '--debug', help='run in debug mode', action='store_true', default=False)
    api_user_parser.set_defaults(func=show_api_user_cmd)

    # config parser
    config_parser = subparsers.add_parser('config', help='set configurations')
    auth_group = config_parser.add_argument_group('authentication options')
    auth_group.add_argument('-i', '--api-id', help='set default API ID, default "%s"' % api_id, default=api_id)
    auth_group.add_argument('-k', '--api-key', help='set default API key, default "%s"' % api_key, default=api_key)
    config_parser.add_argument('--api-url', help='set default API URL, default "%s"' % api_url, default=api_url)
    config_parser.add_argument('-P', '--proxy', help=proxy_help, default=proxy)
    config_parser.add_argument('--reset', help='reset configuration', action='store_true', default=False)
    config_parser.add_argument('-s', '--show', help='show current configuration', action='store_true', default=False)
    config_parser.set_defaults(func=config_cmd)

    args = parser.parse_args()
    args.func(args)


def main():
    try:
        get_args()
    except KeyboardInterrupt:
        pass
