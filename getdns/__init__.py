# -*- coding: utf-8 -*-
from __future__ import print_function

import csv
import datetime
import os
import sys
import traceback

from colorama import Fore, Style
from dnsdb_sdk.api import APIClient
from progress.bar import IncrementalBar
from iptools import ipv4, ipv6
import json
import getpass
import argparse

__version__ = '0.1.2b2'

try:
    # python2
    from ConfigParser import ConfigParser, NoSectionError, NoOptionError
except ImportError:
    # python3
    from configparser import ConfigParser, NoSectionError, NoOptionError

CONFIG_PATH = os.environ.get('GETDNS_CONF', os.path.expanduser("~/.getdns"))
DEFAULT_TIMEOUT = 20
API_BASE_URL = 'https://api.dnsdb.io'


def show_error(message):
    sys.stderr.write(Fore.RED + message + '\n' + Style.RESET_ALL)


def show_info(message):
    print(message)


def validate_ip(ip):
    ip = ip.lower()
    return ipv4.validate_ip(ip) or ipv4.validate_cidr(ip) or ipv6.validate_ip(ip) or ipv6.validate_cidr(ip)


def check_search_params(domain=None, host=None, ip=None, value_domain=None, value_host=None, value_ip=None, email=None):
    if ip is not None:
        if not validate_ip(ip):
            show_error('"%s" is not a valid IP address' % ip)
            return False
    if value_ip is not None:
        if not validate_ip(value_ip):
            show_error('"%s" is not a valid IP address' % value_ip)
            return False
    if domain is None and host is None and ip is None and value_domain is None and value_host is None and value_ip is None and email is None:
        main_parameters = ["--domain", "--ip", "--host", "--value-domain", "--value-host", "--value-ip", "--email"]
        q = '", "'.join(main_parameters)
        show_error('You need to provide at least one search parameter in "%s"' % q)
        return False
    return True


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
        defaults['api_url'] = get_config_value(conf, 'settings', 'api-url', API_BASE_URL)
        defaults['timeout'] = float(get_config_value(conf, 'settings', 'timeout', DEFAULT_TIMEOUT))
    else:
        defaults['api_id'] = ''
        defaults['api_key'] = ''
        defaults['proxy'] = ''
        defaults['api_url'] = API_BASE_URL
        defaults['timeout'] = DEFAULT_TIMEOUT
    return defaults


def get_api_client(api_id, api_key, proxies=None, timeout=None):
    return APIClient(api_id=api_id, api_key=api_key, proxies=proxies, timeout=timeout)


class OutputFormatter(object):
    def __init__(self, json_format=None, csv_format=None, custom_format=None):
        self.json = json_format
        self.csv = csv_format
        self.custom_format = custom_format

    def format(self, record):
        if self.custom_format:
            line = self.custom_format.replace('#{host}', record.host).replace('#{type}', record.type).replace(
                '#{value}', record.value)
        else:
            line = json.dumps(dict(record))
        return line


def process_output(result, output, formatter, max_result=None):
    global csv_writer, bar
    show_progress = output != sys.stdout
    if show_progress:
        if max_result and max_result < len(result):
            max_value = max_result
        else:
            max_value = len(result)
        bar = IncrementalBar('Receiving', max=max_value)
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
            output.write(formatter.format(record) + '\n')
        count += 1
        if show_progress:
            bar.next()
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
    if ip is not None:
        ip = ip.lower()
    value_domain = args.value_domain
    value_host = args.value_host
    value_ip = args.value_ip
    if value_ip is not None:
        value_ip = value_ip.lower()
    email = args.email
    page = args.page
    page_size = args.page_size
    get_all = args.all
    if not check_search_params(domain, host, ip, value_domain, value_host, value_ip, email):
        return -1
    if not api_id:
        api_id = read_line("API ID:")
    if not api_key:
        api_key = getpass.getpass("API Key:")
    proxies = None
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
    client = get_api_client(api_id, api_key, proxies=proxies, timeout=args.timeout)
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
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        show_error(str(e))
    finally:
        output.flush()
        if args.verbose:
            show_info('Running time: %s' % (datetime.datetime.now() - start_time))
        if output != sys.stdout:
            output.close()


def show_api_user_cmd(args):
    APIClient.API_BASE_URL = args.api_url
    api_id = args.api_id
    api_key = args.api_key
    if not api_id:
        api_id = read_line("API ID:")
    if not api_key:
        api_key = getpass.getpass("API Key:")
    proxies = None
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
    client = get_api_client(api_id, api_key, proxies=proxies, timeout=args.timeout)
    try:
        start_time = datetime.datetime.now()
        api_user = client.get_api_user()
        show_info(json.dumps(dict(api_user), indent=1))
        if args.verbose:
            show_info('Running time: %s' % (datetime.datetime.now() - start_time))
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        show_error(str(e))


def config_cmd(args):
    if args.reset:
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
        return
    if args.show:
        defaults = get_defaults()
        show_info(json.dumps(defaults, indent=1))
        return
    conf = ConfigParser()
    conf.read(CONFIG_PATH)
    if not conf.has_section("auth"):
        conf.add_section("auth")
    if not conf.has_section("settings"):
        conf.add_section("settings")
    if args.api_id:
        conf.set('auth', 'api-id', args.api_id)
    if args.api_key:
        conf.set('auth', 'api-key', args.api_key)
    if args.api_url:
        conf.set('settings', 'api-url', args.api_url)
    if args.proxy:
        conf.set('settings', 'proxy', args.proxy)
    if args.timeout:
        conf.set('settings', 'timeout', str(args.timeout))
    conf.write(open(CONFIG_PATH, "w"))


def init_auth_options(parser, api_id, api_key):
    auth_group = parser.add_argument_group('authentication options')
    auth_group.add_argument('-i', '--api-id', help='set API ID', default=api_id)
    auth_group.add_argument('-k', '--api-key', help='set API key', default=api_key)


def raw_text_version_call(self, parser, namespace, values, option_string=None):
    version = self.version
    formatter = argparse.RawTextHelpFormatter(parser.prog)
    formatter.add_text(version)
    parser._print_message(formatter.format_help(), sys.stdout)
    parser.exit()


class DefaultsHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):

    def _get_help_string(self, action):
        default = action.default
        if default or default == 0:
            return super(DefaultsHelpFormatter, self)._get_help_string(action)
        else:
            return action.help

    def _split_lines(self, text, width):
        if text.startswith('R|'):
            return text[2:].splitlines()
        return argparse.HelpFormatter._split_lines(self, text, width)


def get_parser():
    argparse._VersionAction.__call__ = raw_text_version_call
    defaults = get_defaults()
    api_id = defaults['api_id']
    api_key = defaults['api_key']
    api_url = defaults['api_url']
    proxy = defaults['proxy']
    timeout = defaults['timeout']
    parser = argparse.ArgumentParser(description="search DNS records using the DNSDB Web API")
    dnsdb_python_sdk_version = __import__('dnsdb_sdk').__version__
    parser.add_argument('-V', '--version', action='version',
                        version="getdns: %s\ndnsdb-python-sdk: %s\nDNSDB Web API: %s" % (
                            __version__, dnsdb_python_sdk_version, APIClient.API_VERSION))
    subparsers = parser.add_subparsers(dest='cmd', title='commands')
    subparsers.required = True

    proxy_help = 'R|specify a proxy\nHTTP proxy: "http://user:pass@host:port/"\nSOCKS5 proxy: "socks5://user:pass@host:port"'
    config_proxy_help = 'R|specify a default proxy\nHTTP proxy: "http://user:pass@host:port/"\nSOCKS5 proxy: "socks5://user:pass@host:port"'
    format_help = 'R|set custom output format:\n#{host} will replace by DNS record\'s host\n#{type} will replace by DNS ' \
                  'record\'s type\n#{value} will replace by DNS record\'s value\nFor example: -f "#{host},#{type},#{value}"'
    # search parser
    search_parser = subparsers.add_parser('search', help='search DNS records', formatter_class=DefaultsHelpFormatter)
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
    init_auth_options(search_parser, api_id, api_key)
    search_parser.add_argument('-o', '--output', help='specify output file, "-" represents stdout', default='-')
    output_format_options = search_parser.add_mutually_exclusive_group()
    output_format_options.add_argument('-j', '--json', help='set JSON output', action='store_true', default=True)
    output_format_options.add_argument('-c', '--csv', help='set CSV output', action='store_true', default=False)
    output_format_options.add_argument('-f', '--format', help=format_help)
    search_parser.add_argument('-m', '--max', help='set the maximum number of search results for the output', type=int)
    search_parser.add_argument('-P', '--proxy', help=proxy_help, default=proxy)
    search_parser.add_argument('--api-url', help='set API URL', default=api_url)
    search_parser.add_argument('-v', '--verbose', help='show verbose information', action='store_true', default=False)
    search_parser.add_argument('-D', '--debug', help='run in debug mode', action='store_true', default=False)
    search_parser.add_argument('-T', '--timeout', help='set the socket timeout', default=timeout, type=float)
    search_parser.set_defaults(func=do_search_cmd)

    # api user parser
    api_user_parser = subparsers.add_parser('api-user', help='get API user information',
                                            formatter_class=DefaultsHelpFormatter)
    init_auth_options(api_user_parser, api_id, api_key)
    api_user_parser.add_argument('-P', '--proxy', help=proxy_help, default=proxy)
    api_user_parser.add_argument('--api-url', help='set API URL', default=api_url)
    api_user_parser.add_argument('-v', '--verbose', help='show verbose information', action='store_true', default=False)
    api_user_parser.add_argument('-D', '--debug', help='run in debug mode', action='store_true', default=False)
    api_user_parser.add_argument('-T', '--timeout', help='set the socket timeout', default=timeout, type=float)
    api_user_parser.set_defaults(func=show_api_user_cmd)

    # config parser
    config_parser = subparsers.add_parser('config', help='set configurations', formatter_class=DefaultsHelpFormatter)
    config_parser.add_argument('-i', '--api-id', help='set the default API ID', default=api_id)
    config_parser.add_argument('-k', '--api-key', help='set the default API key', default=api_key)
    config_parser.add_argument('--api-url', help='set the default API URL', default=api_url)
    config_parser.add_argument('-P', '--proxy', help=config_proxy_help, default=proxy)
    config_parser.add_argument('-T', '--timeout', help='set the default socket timeout', default=timeout, type=float)
    config_parser.add_argument('--reset', help='reset configuration', action='store_true', default=False)
    config_parser.add_argument('-s', '--show', help='show current configuration', action='store_true', default=False)
    config_parser.set_defaults(func=config_cmd)

    return parser


def main(args=None):
    try:
        if args is None:
            args = sys.argv[1:]
        parser = get_parser()
        args = parser.parse_args(args)
        args.func(args)
    except KeyboardInterrupt:
        show_error("Canceled")
