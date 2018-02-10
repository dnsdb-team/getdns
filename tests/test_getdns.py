import os
import sys
import uuid

from nose import with_setup
from nose.tools import assert_false, assert_true, assert_equal

from getdns import main, get_config_value

from . import api_mock_server

CONFIG_PATH = os.path.expanduser('~/.getdns')


def setup_func():
    if os.path.exists(CONFIG_PATH):
        os.remove(CONFIG_PATH)
    cmd = 'getdns config --api-url http://localhost:5000'
    sys.argv = cmd.split()
    main()
    api_mock_server.reset_all_response()
    api_mock_server.start()


def teardown_func():
    api_mock_server.stop()
    if os.path.exists(CONFIG_PATH):
        os.remove(CONFIG_PATH)


@with_setup(setup_func, teardown_func)
def test_search():
    cmd = 'getdns search --api-id 123 --api-key 123 --domain baidu.com -t a --debug --verbose'
    sys.argv = cmd.split(' ')
    main()
    cmd = 'getdns search --api-id 123 --api-key 123 --domain baidu.com -t a -o output.txt'
    sys.argv = cmd.split(' ')
    main()
    assert_true(os.path.exists('output.txt'))
    os.remove('output.txt')


@with_setup(setup_func, teardown_func)
def test_search_as_csv():
    cmd = 'getdns search --api-id 123 --api-key 123 --domain baidu.com -t a --debug --verbose --csv'
    sys.argv = cmd.split(' ')
    main()


@with_setup(setup_func, teardown_func)
def test_api_user():
    cmd = 'getdns api-user --api-id 123 --api-key 123 --debug --verbose'
    sys.argv = cmd.split(' ')
    main()


def test_config_show():
    cmd = 'getdns config -s'
    sys.argv = cmd.split(' ')
    main()


def test_config_reset():
    cmd = 'getdns config --reset'
    sys.argv = cmd.split(' ')
    main()
    assert_false(os.path.exists(CONFIG_PATH))


def test_config_set():
    api_url = 'http://api.dnsdb.io'
    api_id = uuid.uuid4().hex.replace('-', '')
    api_key = uuid.uuid4().hex.replace('-', '')
    proxy = 'http://user:password@host/'
    cmd = 'getdns config --api-url %s --api-id %s --api-key %s --proxy %s' % (api_url, api_id, api_key, proxy)
    sys.argv = cmd.split(' ')
    main()
    try:
        # python2
        from ConfigParser import ConfigParser, NoSectionError, NoOptionError
    except ImportError:
        # python3
        from configparser import ConfigParser, NoSectionError, NoOptionError
    conf = ConfigParser()
    conf.read(CONFIG_PATH)
    assert_equal(get_config_value(conf, 'auth', 'api-id'), api_id)
    assert_equal(get_config_value(conf, 'auth', 'api-key'), api_key)
    assert_equal(get_config_value(conf, 'settings', 'api-url'), api_url)
    assert_equal(get_config_value(conf, 'settings', 'proxy'), proxy)
    os.remove(CONFIG_PATH)
