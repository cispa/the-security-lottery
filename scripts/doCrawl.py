from contextlib import contextmanager
from data import UserAgents
from hashlib import md5

import requests.packages.urllib3.util.connection as urllib3_cn
import requests
import argparse
import signal
import socket
import gzip
import json
import os

DEBUG = False
DATA_DIRECTORY = '/data'


def allowed_gai_family():
    family = socket.AF_INET
    return family


urllib3_cn.allowed_gai_family = allowed_gai_family


def raise_timeout(signum, frame):
    if DEBUG:
        print('Hard kill via signal!')
        print(signum)
        print(frame)
    raise TimeoutError


@contextmanager
def timeout(seconds):
    # Register a function to raise a TimeoutError on the signal.
    signal.signal(signal.SIGALRM, raise_timeout)
    # Schedule the signal to be sent after the specified seconds.
    signal.alarm(seconds)
    try:
        yield
    except TimeoutError:
        pass
    finally:
        # Unregister the signal so it won't be triggered, if the timeout is not reached.
        signal.signal(signal.SIGALRM, signal.SIG_IGN)


def compute_file_name_hash(content):
    content_hash = md5(content).hexdigest()
    # Save file to disk
    folder = f'{DATA_DIRECTORY}/{content_hash[0]}/{content_hash[1]}'
    os.makedirs(folder, exist_ok=True)
    if os.path.exists(f'{folder}/{content_hash}.html.gz'):
        return content_hash
    with gzip.open(f'{folder}/{content_hash}.html.gz', 'wb') as fh:
        fh.write(content)
    return content_hash


def crawl(url, proxies=None, headers=None, user_agent=UserAgents['chrome']['windows']):
    if headers is None:
        headers = dict()
    headers['User-Agent'] = user_agent
    with timeout(25):
        try:
            if proxies is not None:
                r = requests.get(url, headers=headers, proxies=proxies, timeout=20, stream=True)
            else:
                r = requests.get(url, headers=headers, timeout=20, stream=True)
            killed = False
        except Exception as exp:
            return False, str(exp) if str(exp) != 'tuple index out of range' else 'TimeoutError: signal.alarm(25)'

    if killed:
        return False, 'Hard kill due to signal timeout!'

    peer = None
    tls_version = None
    try:
        connection = r.raw._connection
        if hasattr(connection.sock, 'socket'):
            sock = connection.sock.socket
        else:
            sock = connection.sock
        if sock and hasattr(sock, 'getpeername'):
            peer = '%s:%s' % sock.getpeername()
        if sock and hasattr(sock, 'version'):
            tls_version = sock.version()
    except Exception as exp:
        if DEBUG:
            print('Socket Error:', str(exp))
        pass

    fingerprint = compute_file_name_hash(r.content)
    if fingerprint is None:
        return False, f'ERROR: Can not create fingerprint'

    if DEBUG:
        print(f'Application-Fingerprint is: {fingerprint}')

    result_data = [r.url, peer, tls_version, fingerprint]
    response_headers = {h.lower(): r.headers[h] for h in r.headers}
    response_headers['status_code'] = r.status_code
    result_data.append(json.dumps(response_headers))

    return True, result_data


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="The url that should be crawled!")
    parser.add_argument("--proxies", help="JSON containing proxies that are used for the request.")
    parser.add_argument("--headers", help="JSON containing headers that are used for the request.")
    parser.add_argument("--user_agent", help="User agent that is used for the request")
    parser.add_argument("--debug", help="prints out everything for debugging")
    args = parser.parse_args()

    user_agent_in = None
    if args.user_agent:
        if args.user_agent.startswith('"') and args.user_agent.endswith('"'):
            args.user_agent = args.user_agent[1:-1]
        user_agent_in = args.user_agent

    headers_in = None
    if args.headers:
        if args.headers.startswith('"') and args.headers.endswith('"'):
            args.headers = args.headers[1:-1]
        try:
            headers_in = json.loads(args.headers)
        except Exception as e:
            print(args.headers)
            print("ERROR: JSON parsing error:\n")
            print(e)
            exit(42)

    proxies_in = None
    if args.proxies:
        if args.proxies.startswith('"') and args.proxies.endswith('"'):
            args.proxies = args.proxies[1:-1]
        try:
            proxies_in = json.loads(args.proxies)
        except Exception as e:
            print(args.proxies)
            print("ERROR: JSON parsing error:\n")
            print(e)
            exit(42)
        if 'https' not in proxies_in or 'http' not in proxies_in:
            print('ERROR: Proxy needs to be {"https": "<ip>:<port>", "http": "<ip>:<port>"}')
            exit(43)

    if args.url.startswith('"') and args.url.endswith('"'):
        args.url = args.url[1:-1]

    if args.debug:
        DEBUG = True

    success, result = crawl(args.url, proxies=proxies_in, headers=headers_in, user_agent=user_agent_in)

    print(json.dumps({'success': success, 'result': result}))

    exit(0)
