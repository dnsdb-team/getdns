import io
import json
import os
import platform
import sys
import uuid

from colorama import Fore, Style
from dnsdb_sdk.api import APIUser, DNSRecord
from dnsdb_sdk.exceptions import APIException
from mock import Mock, patch
from nose import with_setup
from nose.tools import assert_equal, assert_false, assert_true, raises

import getdns

try:
    # python 2
    from Queue import Queue
    from ConfigParser import ConfigParser, NoSectionError, NoOptionError
except ImportError:
    # python 3
    from queue import Queue
    from configparser import ConfigParser, NoSectionError, NoOptionError

PY_MAIN_VERSION, _, _ = platform.python_version_tuple()
PY2 = int(PY_MAIN_VERSION) == 2
PY3 = int(PY_MAIN_VERSION) == 3

CONFIG_PATH = os.path.expanduser('~/.getdns')
OUTPUT_FILE = 'output.txt'


def generate_uuid():
    return uuid.uuid4().hex.replace('-', '')


search_records = [
    DNSRecord(host='a1.example.com', type='a', value='1.1.1.1'),
    DNSRecord(host='a2.example.com', type='a', value='1.1.1.2'),
    DNSRecord(host='a3.example.com', type='a', value='1.1.1.3'),
    DNSRecord(host='a4.example.com', type='a', value='1.1.1.4'),
    DNSRecord(host='a5.example.com', type='a', value='1.1.1.5'),
    DNSRecord(host='a6.example.com', type='a', value='1.1.1.6'),
    DNSRecord(host='a7.example.com', type='a', value='1.1.1.7'),
    DNSRecord(host='a8.example.com', type='a', value='1.1.1.8'),
]
scan_records = search_records * 2
api_user = APIUser(api_id=generate_uuid(), user='admin', remaining_requests=10000,
                   creation_time='018-03-14T06:38:07.509Z',
                   expiration_time='2018-01-16T02:24:05.318Z')


class MockOutput(object):
    def __init__(self):
        self.content = ''

    def write(self, content):
        self.content += content

    def lines(self):
        return list(filter(lambda x: x and x != '', self.content.split('\n')))

    def clear(self):
        self.content = ''


class MessageCollector(object):
    def __init__(self):
        self.messages = Queue()
        self.args = None
        self.kwargs = None

    def collect(self, msg):
        self.messages.put(msg)

    def collect_trace(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def clear(self):
        self.messages = Queue()

    def get(self):
        return self.messages.get(block=False)


def get_mock_output():
    output = MockOutput()
    output.close = Mock(return_value=None)
    output.flush = Mock(return_value=None)
    return output


def get_file_lines(path):
    line_count = 0
    with open(path, 'r') as f:
        for _ in f:
            line_count += 1
    return line_count


def get_mock_api_client():
    client = Mock()
    client.search_dns.return_value = search_records
    client.scan_dns.return_value = scan_records
    client.get_api_user.return_value = api_user
    return client


def get_mock_args(api_url=None, api_id=None, api_key=None, domain=None, host=None, ip=None, dns_type=None,
                  value_domain=None, value_host=None, value_ip=None, email=None, page=1, page_size=50, search_all=False,
                  proxy=None, timeout=20):
    args = Mock()
    setattr(args, 'api_url', api_url)
    setattr(args, 'api_id', api_id)
    setattr(args, 'api_key', api_key)
    setattr(args, 'domain', domain)
    setattr(args, 'host', host)
    setattr(args, 'ip', ip)
    setattr(args, 'type', dns_type)
    setattr(args, 'value_domain', value_domain)
    setattr(args, 'value_host', value_host)
    setattr(args, 'value_ip', value_ip)
    setattr(args, 'email', email)
    setattr(args, 'page', page)
    setattr(args, 'page_size', page_size)
    setattr(args, 'all', search_all)
    setattr(args, 'proxy', proxy)
    setattr(args, 'timeout', timeout)
    return args


def setup_func():
    if os.path.exists(CONFIG_PATH):
        os.remove(CONFIG_PATH)


def teardown_func():
    if os.path.exists(CONFIG_PATH):
        os.remove(CONFIG_PATH)
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)


def run_main(cmd):
    args = ['getdns'] + list(filter(lambda x: x != '', cmd.split(' ')))
    with patch('sys.argv', new=args):
        getdns.main()


def test_validate_ip():
    assert_true(getdns.validate_ip('1.1.1.1'))
    assert_true(getdns.validate_ip('255.255.255.255'))
    assert_true(getdns.validate_ip('255.255.255.255/24'))
    assert_true(getdns.validate_ip('FF01:0:0:0:0:0:0:1101'))
    assert_true(getdns.validate_ip('FF01::1101'))
    assert_true(getdns.validate_ip('FF01::1101/128'))
    assert_false(getdns.validate_ip('123123'))


def test_check_search_params():
    mc = MessageCollector()
    with patch('getdns.show_error', new=mc.collect):
        assert_false(getdns.check_search_params())
        assert_equal(
            'You need to provide at least one search parameter in "--domain", "--ip", "--host", "--value-domain", "--value-host", "--value-ip", "--email"',
            mc.get())
        assert_false(getdns.check_search_params(ip='256.0.0.1'))
        assert_equal('"256.0.0.1" is not a valid IP address', mc.get())
        assert_false(getdns.check_search_params(value_ip='256.0.0.2'))
        assert_equal('"256.0.0.2" is not a valid IP address', mc.get())


def test_format():
    formatter = getdns.OutputFormatter(custom_format="#{host}|#{type}|#{value}")
    record = DNSRecord(host='www.example.com', type='a', value='1.1.1.1')
    assert_equal('www.example.com|a|1.1.1.1', formatter.format(record))


def test_read_line():
    api_id = generate_uuid()
    if PY2:
        with patch('__builtin__.raw_input', return_value=api_id):
            assert_equal(api_id, getdns.read_line("Your API ID:"))
    elif PY3:
        with patch('builtins.input', return_value=api_id):
            assert_equal(api_id, getdns.read_line("Your API ID:"))


def test_get_output_file():
    assert_equal(sys.stdout, getdns.get_output_file('-'))
    output = getdns.get_output_file('output.txt')
    if PY2:
        assert_true(isinstance(output, file))
    elif PY3:
        assert_true(isinstance(output, io.TextIOWrapper))
    os.remove('output.txt')


def test_get_config_value():
    conf = ConfigParser()
    api_url = 'https://api.dnsdb.io'
    conf.add_section('settings')
    conf.set('settings', 'api-url', api_url)
    assert_equal('default', getdns.get_config_value(conf, 'setting', 'api-url', 'default'))
    assert_equal('default', getdns.get_config_value(conf, 'settings', 'url', 'default'))
    assert_equal(api_url, getdns.get_config_value(conf, 'settings', 'api-url', 'default'))


def test_get_api_client():
    api_id = generate_uuid()
    api_key = generate_uuid()
    timeout = 10
    client = getdns.get_api_client(api_id, api_key, timeout=timeout)
    assert_equal(api_id, client.api_id)
    assert_equal(api_key, client.api_key)
    assert_equal(timeout, client.timeout)


def test_show_error():
    output = get_mock_output()
    with patch('sys.stderr', new=output):
        getdns.show_error('error')
        assert_equal(Fore.RED + 'error\n' + Style.RESET_ALL, output.content)


def test_do_search_cmd():
    args = get_mock_args(ip='123a')
    mc = MessageCollector()
    with patch('getdns.show_error', new=mc.collect):
        assert_equal(-1, getdns.do_search_cmd(args))


@with_setup(setup_func, teardown_func)
@patch('getdns.read_line', return_value='123')
@patch('getpass.getpass', return_value='123')
def test_search(read_line, getpass):
    client = get_mock_api_client()
    with patch('getdns.get_api_client', return_value=client):
        run_main('search --domain baidu.com -t a -v -o %s' % OUTPUT_FILE)
        assert_equal(len(search_records), get_file_lines(OUTPUT_FILE))
        client.search_dns.assert_called_once()
        client.scan_dns.assert_not_called()
        run_main('search --domain baidu.com -t a -v -a -o %s' % OUTPUT_FILE)
        assert_equal(len(scan_records), get_file_lines(OUTPUT_FILE))
        client.scan_dns.assert_called_once()


@with_setup(setup_func, teardown_func)
@patch('getdns.read_line', return_value=generate_uuid())
@patch('getpass.getpass', return_value=generate_uuid())
def test_search_as_csv(read_line, getpass):
    client = get_mock_api_client()
    with patch('getdns.get_api_client', return_value=client):
        output = get_mock_output()
        with patch('getdns.get_output_file', return_value=output):
            run_main('search --domain baidu.com --csv')
            assert_equal(len(search_records), len(output.lines()))
            content = ''
            for record in search_records:
                content += '"%s","%s","%s"\r\n' % (record.host, record.type, record.value)
            assert_equal(content, output.content)


@with_setup(setup_func, teardown_func)
@patch('getdns.read_line', return_value=generate_uuid())
@patch('getpass.getpass', return_value=generate_uuid())
def test_search_as_custom_format(read_line, getpass):
    client = get_mock_api_client()
    with patch('getdns.get_api_client', return_value=client):
        output = get_mock_output()
        with patch('getdns.get_output_file', return_value=output):
            run_main('search --domain baidu.com --format #{host}|#{type}|#{value}')
            content = ''
            for record in search_records:
                content += '%s|%s|%s\n' % (record.host, record.type, record.value)
            assert_equal(len(search_records), len(output.lines()))
            assert_equal(content, output.content)


@with_setup(setup_func, teardown_func)
@patch('getdns.read_line', return_value=generate_uuid())
@patch('getpass.getpass', return_value=generate_uuid())
def test_search_with_exception(read_line, getpass):
    client = get_mock_api_client()
    client.search_dns = Mock(side_effect=APIException(10001, 'unauthorized'))
    with patch('getdns.get_api_client', return_value=client):
        mc = MessageCollector()
        with patch('getdns.show_error', new=mc.collect):
            cmd = 'search --ip 123.123.123.123 --value-ip 123.123.123.123 --proxy http://user:pass@localhost:8111 -D'
            if PY2:
                with patch('traceback._print', new=mc.collect_trace):
                    run_main(cmd)
                    assert_equal('code:10001, message:unauthorized', mc.get())
            elif PY3:
                with patch('traceback.print_exception', new=mc.collect_trace):
                    run_main(cmd)
                    assert_equal('code:10001, message:unauthorized', mc.get())


@patch('getdns.read_line', return_value=generate_uuid())
@patch('getpass.getpass', return_value=generate_uuid())
def test_api_user(read_line, getpass):
    client = get_mock_api_client()
    with patch('getdns.get_api_client', return_value=client):
        mc = MessageCollector()
        with patch('getdns.show_info', new=mc.collect):
            run_main('api-user -v -D --proxy http://user:pass@localhost:8111')
            user = json.loads(mc.get())
            assert_equal(api_user.api_id, user['api_id'])
            assert_equal(api_user.user, user['user'])
            assert_equal(api_user.remaining_requests, user['remaining_requests'])
            assert_equal(api_user.creation_time, user['creation_time'])
            assert_equal(api_user.expiration_time, user['expiration_time'])


@patch('getdns.read_line', return_value=generate_uuid())
@patch('getpass.getpass', return_value=generate_uuid())
def test_api_user_with_exception(read_line, getpass):
    client = get_mock_api_client()
    client.get_api_user = Mock(side_effect=APIException(10001, 'unauthorized'))
    with patch('getdns.get_api_client', return_value=client):
        mc = MessageCollector()
        with patch('getdns.show_error', new=mc.collect):
            if PY2:
                with patch('traceback._print', new=mc.collect_trace):
                    run_main('api-user -D -v')
                    assert_equal('code:10001, message:unauthorized', mc.get())
                    assert_equal('APIException: code:10001, message:unauthorized\n', mc.args[1])
            elif PY3:
                with patch('traceback.print_exception', new=mc.collect_trace):
                    run_main('api-user -D -v')
                    assert_equal('code:10001, message:unauthorized', mc.get())


@patch('getdns.read_line', return_value=generate_uuid())
@patch('getpass.getpass', return_value=generate_uuid())
@patch('getdns.parse_args', new=Mock(side_effect=KeyboardInterrupt()))
def test_with_keyboard_interrupt(read_line, getpass):
    mc = MessageCollector()
    with patch('getdns.show_error', new=mc.collect):
        run_main('search -d example.com')
        assert_equal('Canceled', mc.get())


def test_config_set_and_show():
    api_url = 'http://api.dnsdb.io'
    api_id = uuid.uuid4().hex.replace('-', '')
    api_key = uuid.uuid4().hex.replace('-', '')
    proxy = 'http://user:password@host/'
    timeout = 10
    cmd = 'config --api-url %s --api-id %s --api-key %s --proxy %s --timeout %s ' % (
        api_url, api_id, api_key, proxy, timeout)
    run_main(cmd)
    mc = MessageCollector()
    with patch('getdns.show_info', new=mc.collect):
        run_main('config -s')
        settings = json.loads(mc.get())
        assert_equal(api_url, settings['api_url'])
        assert_equal(api_id, settings['api_id'])
        assert_equal(api_key, settings['api_key'])
        assert_equal(proxy, settings['proxy'])
        assert_equal(timeout, settings['timeout'])


def test_config_reset():
    cmd = 'config --reset'
    run_main(cmd)
    assert_false(os.path.exists(CONFIG_PATH))


def test_process_output():
    result = search_records
    output = get_mock_output()
    formatter = getdns.OutputFormatter(json_format=True)
    with patch('sys.stdout', new=output):
        output = sys.stdout
        getdns.process_output(result, output, formatter, 3)
        assert_equal(3, len(output.lines()))
    output = get_mock_output()
    with patch('getdns.get_output_file', new=output):
        getdns.process_output(result, output, formatter, 4)
        assert_equal(4, len(output.lines()))
