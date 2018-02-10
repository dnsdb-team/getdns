import os
import signal
import time
import uuid
from multiprocessing import Process

from flask import Flask, jsonify


class APIUser(object):
    def __init__(self, user, api_id=uuid.uuid4().hex, api_key=uuid.uuid4().hex, remaining_requests=10000):
        self.user = user
        self.api_id = api_id
        self.api_key = api_key
        self.remaining_requests = remaining_requests
        self.creation_time = "2018-01-16T02:24:05.318Z"
        self.expiration_time = "2018-02-16T07:26:43.501Z"


app = Flask(__name__)

api_user = APIUser('admin')
scan_id = None
records = [
    {'host': 'maps-cctld.l.google.com', 'type': 'a', 'value': '119.110.118.221'},
    {'host': 'maps-cctld.l.google.com', 'type': 'a', 'value': '204.186.215.52'},
    {'host': 'maps-cctld.l.google.com', 'type': 'a', 'value': '46.134.193.89'},
    {'host': 'maps-cctld.l.google.com', 'type': 'a', 'value': '59.18.45.84'},
    {'host': 'maps.l.google.com', 'type': 'a', 'value': '59.18.45.119'},
    {'host': 'fit.google.com', 'type': 'aaaa', 'value': '2a00:1450:4017:804::200e'},
    {'host': 'lh5.l.google.com', 'type': 'a', 'value': '142.176.121.217'},
    {'host': 'agjw9w.feedproxy.ghs.google.com', 'type': 'cname', 'value': 'ghs.l.google.com'},
    {'host': 'groups.l.google.com', 'type': 'aaaa', 'value': '2607:f8b0:4001:c0d::71'},
    {'host': 'gmail-imap.l.google.com', 'type': 'aaaa', 'value': '2a00:1450:400c:c09::6c'},
    {'host': 'googlemail-smtp.l.google.com', 'type': 'aaaa', 'value': '2a00:1450:4013:c03::10'},
    {'host': 'inbox.google.com', 'type': 'aaaa', 'value': '2607:f8b0:4005:804::2005'},
    {'host': 'gmail-imap.l.google.com', 'type': 'aaaa', 'value': '2607:f8b0:4001:c15::6d'},
    {'host': 'gmail-pop.l.google.com', 'type': 'aaaa', 'value': '2a00:1450:4010:c0d::6d'},
    {'host': 'home.google.com', 'type': 'aaaa', 'value': '2607:f8b0:4002:c06::8b'},
    {'host': 'mt.l.google.com', 'type': 'a', 'value': '74.125.232.225'},
    {'host': 'mt.l.google.com', 'type': 'aaaa', 'value': '2a00:1450:4010:c02::65'},
    {'host': 'mail-io0-f169.google.com', 'type': 'a', 'value': '209.85.223.169'},
    {'host': 'appspot.l.google.com', 'type': 'a', 'value': '216.58.204.241'},
]

__DEFAULT_SEARCH_RESPONSE = {
    'records': records, 'remaining_requests': api_user.remaining_requests, 'total': len(records)
}

__DEFAULT_SCAN_CREATE_RESPONSE = {
    'records': records, 'remaining_requests': api_user.remaining_requests, 'total': len(records), 'scan_id': scan_id
}
__DEFAULT_SCAN_NEXT_RESPONSE = {
    'records': records, 'remaining_requests': api_user.remaining_requests, 'total': len(records), 'scan_id': scan_id
}

__DEFAULT_API_USER_RESPONSE = api_user.__dict__

search_response = __DEFAULT_SEARCH_RESPONSE
scan_create_response = __DEFAULT_SCAN_CREATE_RESPONSE
scan_next_response = __DEFAULT_SCAN_NEXT_RESPONSE
api_user_response = __DEFAULT_API_USER_RESPONSE


def reset_all_response():
    global search_response
    search_response = __DEFAULT_SEARCH_RESPONSE
    global scan_create_response
    scan_create_response = __DEFAULT_SCAN_CREATE_RESPONSE
    global scan_next_response
    scan_next_response = __DEFAULT_SCAN_NEXT_RESPONSE
    global api_user_response
    api_user_response = __DEFAULT_API_USER_RESPONSE


def set_search_response_and_restart(response):
    global search_response
    search_response = response
    restart()


def set_api_user_response_and_restart(response):
    global api_user_response
    api_user_response = response
    restart()


@app.route('/v1/dns/search')
def search():
    return jsonify(search_response)


@app.route('/v1/dns/scan/create')
def scan_create():
    return jsonify(scan_create_response)


@app.route('/v1/dns/scan/next')
def scan_next():
    return jsonify(scan_next_response)


@app.route('/v1/api_user')
def get_api_user():
    return jsonify(api_user_response)


def run_web():
    app.run()


class MockAPIServer(object):

    def __init__(self):
        self.process = None

    def start(self):
        self.process = Process(target=run_web)
        self.process.start()

    def stop(self):
        if self.process is not None:
            os.kill(self.process.pid, signal.SIGKILL)

    def restart(self):
        self.stop()
        self.start()


server = MockAPIServer()


def start():
    server.start()
    time.sleep(0.1)


def stop():
    server.stop()
    time.sleep(0.1)


def restart():
    server.restart()
    time.sleep(0.1)


if __name__ == '__main__':
    run_web()
