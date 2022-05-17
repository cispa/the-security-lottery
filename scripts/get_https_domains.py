import os
import signal
import sys
from multiprocessing import Pool
from urllib.parse import urlparse

import requests
import tldextract

from data import UserAgents

PROCESSES = os.environ.get('NUM_PROCESSES', None)
if PROCESSES is None:
    print('Environment variable NUM_PROCESSES is not defined! Using only ONE Process.')
    PROCESSES = 1
else:
    try:
        PROCESSES = int(PROCESSES)
    except ValueError:
        print('NUM_PROCESSES is not an integer! Abort.')
        exit(-1)

COUNT = os.environ.get('NUM_DOMAINS', None)
if COUNT is None:
    print('Environment variable NUM_DOMAINS is not defined! Defaulting to 10k.')
    COUNT = 10000
else:
    try:
        COUNT = int(COUNT)
    except ValueError:
        print('NUM_DOMAINS is not an integer! Abort.')
        exit(-1)

USER_AGENT = UserAgents['chrome']['windows']
DOMAINS_FILE = 'domains.csv'


def handler(signum, frame):
    raise TimeoutError('Request Timeout (60s)')


def get_domains(filename):
    with open(filename) as file:
        return [line.strip().split(',') for line in file]


def get_end_url_origin(domain):
    try:
        signal.alarm(20)
        response = requests.get(f"{domain}", timeout=15)
    except Exception:
        return None
    finally:
        signal.alarm(0)

    if response.status_code != 200:
        return None

    # parse origin of reponse URL
    parsed_url = urlparse(response.url)

    if parsed_url.scheme != 'https':
        return None

    # ignore cross-site redirects
    original_site = wrap_tldextract(domain).registered_domain
    if wrap_tldextract(response.url).registered_domain != original_site:
        return None

    origin = f"{parsed_url.scheme}://"

    if parsed_url.hostname is not None:
        origin += parsed_url.hostname
        if parsed_url.port is not None and parsed_url.port != 443:
            origin += f":{parsed_url.port}"
    else:
        origin += parsed_url.scheme

    return origin


TLDEXTRACT_CACHE = dict()


def wrap_tldextract(url):
    global TLDEXTRACT_CACHE
    if url in TLDEXTRACT_CACHE:
        return TLDEXTRACT_CACHE[url]
    result = tldextract.extract(url)
    TLDEXTRACT_CACHE[url] = result
    return result


def get_final_origin(id, domain):
    end_origin = get_end_url_origin(f"https://{domain}")
    if end_origin is None:
        end_origin = get_end_url_origin(f"https://www.{domain}")
        if end_origin is None:
            return -1, ''
    print(end_origin)
    return int(id), end_origin


def write_results(filename, domains, n):
    seen = set()
    seen_registrable_domains = set()
    results = []
    start = 0
    while len(results) < n:
        chunk_size = min(COUNT, n - len(results))
        with Pool(PROCESSES) as p:
            for id, domain in sorted(p.starmap(get_final_origin, domains[start:start + chunk_size])):
                registrable_domain = wrap_tldextract(domain).registered_domain
                if id != -1 and domain not in seen and registrable_domain not in seen_registrable_domains:
                    seen.add(domain)
                    seen_registrable_domains.add(registrable_domain)
                    results.append((id, domain))
        start += chunk_size

    with open(filename, 'w') as file:
        for id, end_origin in sorted(results):
            file.write(f"{id},{end_origin}\n")


if __name__ == '__main__':
    signal.signal(signal.SIGALRM, handler)
    write_results(DOMAINS_FILE, get_domains(sys.argv[1]), COUNT)
