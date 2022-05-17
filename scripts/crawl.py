from data import UserAgents, ClientConfigurations, get_db_cursor, get_scoped_db_cursor
from compute_script_stats import file_worker
from get_https_domains import DOMAINS_FILE
from requests import RequestException
from collections import defaultdict
from multiprocessing import Process
from parsers import parse_header
from json import JSONDecodeError

import requests.packages.urllib3.util.connection as urllib3_cn
import tldextract
import subprocess
import requests
import socket
import random
import time
import json
import sys
import os
import re


def allowed_gai_family():
    family = socket.AF_INET
    return family


urllib3_cn.allowed_gai_family = allowed_gai_family

# -----------------------------------------------------------------------------
# CONSTANTS
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

DEBUG = False
NUM_SAMPLES = 5
PROXY_LIST = list()

# Timeout values
KILL = 30
HARD_KILL = 40

# URL range
URL_LOWER = 0
CHUNKSIZE = 5000
URL_UPPER = os.environ.get('NUM_DOMAINS', None)
if URL_UPPER is None:
    print('Environment variable NUM_DOMAINS is not defined! Defaulting to 10k.')
    URL_UPPER = 10000
else:
    try:
        URL_UPPER = int(URL_UPPER)
    except ValueError:
        print('NUM_DOMAINS is not an integer! Abort.')
        exit(-1)

VPN_DIR = os.path.join(os.getcwd(), 'VPN/')

MATTERMOST_ERROR_HOOK = os.environ.get('MATTERMOST_ERROR_HOOK', None)

TOR_PROXY = {
    'https': 'socks4://127.0.0.1:9050',
    'http': 'socks4://127.0.0.1:9050'
}


# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
def debug_print(*args):
    if DEBUG:
        print(*args)


def get_ip_address(proxies=None):
    for _ in range(5):
        try:
            return requests.get('http://ip-api.com/json/', proxies=proxies, timeout=30).json()['query']
        except (RequestException, JSONDecodeError):
            try:
                return requests.get('https://api.myip.com', proxies=proxies, timeout=30).json()['ip']
            except (RequestException, JSONDecodeError):
                pass
    return None


def get_vpn_list():
    try:
        output = subprocess.check_output(['/bin/bash', 'hma-vpn.sh', '-l'], cwd=VPN_DIR, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        output = str(e.output).encode()
    servers = output.decode().split('servers matched')[1]
    matches = re.findall(r'([^(^ ]*).*\(([^)]*)\)\s*([^\n]*)', servers)
    server_list = [(m[0].strip(), m[1].strip(), m[2].strip()) for m in matches]
    return server_list


def crawl(url, proxies=None, headers=None, user_agent=UserAgents['chrome']['windows']):
    call = ['timeout', f'--kill-after={HARD_KILL}', f'{KILL}', 'python3', 'doCrawl.py']
    if proxies is not None:
        call.append(f'--proxies="{json.dumps(proxies)}"')
    if headers is not None:
        call.append(f'--headers="{json.dumps(headers)}"')
    if user_agent is not None:
        call.append(f'--user_agent="{user_agent}"')
    call.append(url)
    try:
        output = json.loads(subprocess.check_output(call).decode())
    except Exception as exp:
        output = {'success': False, 'result': str(exp)}
    return [output['success'], output['result']]


def classify_worker(argv):
    row_id, end_url, headers, table = argv
    results = dict()
    cookies = dict()
    origin = '/'.join(end_url.split('#')[0].split('?')[0].split('/')[:3])
    for h in ['x-frame-options', 'strict-transport-security', 'content-security-policy', 'set-cookie']:
        value = headers.get(h, None)
        parsed = parse_header(h, value, origin)
        if h == 'set-cookie':
            cookies = parsed
        else:
            results.update(parsed)
    return row_id, results, cookies, table


# -----------------------------------------------------------------------------
# BROWSER
def worker_browsers(worker_id, start, end, test_count):
    print(f'Browser Worker {worker_id} started ...')
    cur = get_db_cursor(False)
    cur2 = get_db_cursor()
    query = f"SELECT url FROM browser_tests WHERE NOT crawled " \
            f"AND id > {start * test_count} AND id <= {end * test_count} " \
            f"AND (id % {test_count})=0 LIMIT 1 FOR UPDATE SKIP LOCKED;"
    cur.execute("BEGIN;")
    cur.execute(query)
    res = cur.fetchone()
    extract = tldextract.TLDExtract()
    while res is not None:
        url, = res
        cur.execute("SELECT id, browser, os FROM browser_tests WHERE url=%s FOR UPDATE;", (url,))
        tests = cur.fetchall()
        domain = '.'.join(extract(url))
        if domain.startswith('.'):
            domain = domain[1:]
        print(f'Browser Worker {worker_id} now works on {domain} ({url})')
        errors = defaultdict(dict)
        for crawl_try in range(NUM_SAMPLES):
            for test_id, browser, system in random.sample(tests, len(tests)):
                success, data = crawl(url, user_agent=UserAgents[browser][system])
                start_previous = time.time()
                if success:
                    debug_print(f'Results for {browser} on {system} for {domain}.')
                    end_url, peer, tls_version, file_name_hash, headers = data
                    end_origin = end_url.split("/")[0] + "//" + end_url.split("/")[2]
                    end_site = extract(end_url).registered_domain
                    save_file_info(cur2, file_name_hash)
                    _, results, cookies, _ = classify_worker((1, end_url, json.loads(headers), 'browser'))
                    cur2.execute("""
                    INSERT INTO browser (test, domain, start_url, end_url, peer, tls_version, file_name_hash, crawl_try, 
                    headers, end_origin, results, cookies, end_site) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                    """, (
                        test_id, domain, url, end_url, peer, tls_version, file_name_hash, crawl_try, headers,
                        end_origin, json.dumps(results), json.dumps(cookies), end_site))
                else:
                    errors[test_id][crawl_try] = data
                    debug_print(f'Error with {browser} on {system} for {domain}.')
                sleeptime = max(0, (start_previous + 2) - time.time())
                time.sleep(sleeptime)

        for test_id, _, _ in tests:
            if test_id in errors:
                cur.execute("UPDATE browser_tests SET error=%s, crawled=TRUE WHERE id=%s;",
                            (json.dumps(errors[test_id]), test_id))
            else:
                cur.execute("UPDATE browser_tests SET crawled=TRUE WHERE id=%s", (test_id,))
        cur.execute("COMMIT;")
        cur.execute("END;")
        cur.execute("BEGIN;")
        cur.execute(query)
        res = cur.fetchone()
    # commit last query
    cur.execute("COMMIT;")
    cur.execute("END;")
    print(f'Browser Worker {worker_id} terminates!')


def browser_crawler(start, end):
    print('START Browser crawl.....')
    cur = get_db_cursor()
    cur.execute("SELECT COUNT(*) FROM (SELECT DISTINCT browser, os FROM browser_tests) as foo;")
    test_count, = cur.fetchone()
    processes = list()
    for wid in range(PROCESSES):
        p = Process(target=worker_browsers, args=(wid, start, end, test_count))
        processes.append(p)
        p.start()
    for p in processes:
        p.join()
    print('DONE.')


# -----------------------------------------------------------------------------
# CLIENT
def worker_client_configurations(worker_id, start, end, test_count):
    print(f'Client Configuration Worker {worker_id}...')
    cur = get_db_cursor(False)
    cur2 = get_db_cursor()
    query = f"SELECT url FROM client_tests WHERE NOT crawled " \
            f"AND id > {start * test_count} AND id <= {end * test_count} " \
            f"AND (id % {test_count})=0 LIMIT 1 FOR UPDATE SKIP LOCKED;"
    cur.execute("BEGIN;")
    cur.execute(query)
    res = cur.fetchone()
    extract = tldextract.TLDExtract()
    while res is not None:
        url, = res
        cur.execute("SELECT id, config FROM client_tests WHERE url=%s FOR UPDATE;", (url,))
        tests = cur.fetchall()
        domain = '.'.join(extract(url))
        if domain.startswith('.'):
            domain = domain[1:]
        print(f'Client Configuration Worker {worker_id} now works on {domain} ({url})')
        errors = defaultdict(dict)
        for crawl_try in range(NUM_SAMPLES):
            for test_id, config in random.sample(tests, len(tests)):
                success, data = crawl(url, headers=config)
                start_previous = time.time()
                if success:
                    debug_print(f'Results requesting {domain} with config {config}.')
                    end_url, peer, tls_version, file_name_hash, headers = data
                    end_origin = end_url.split("/")[0] + "//" + end_url.split("/")[2]
                    end_site = extract(end_url).registered_domain
                    save_file_info(cur2, file_name_hash)
                    _, results, cookies, _ = classify_worker((1, end_url, json.loads(headers), 'client'))
                    cur2.execute("""
                    INSERT INTO client (test, domain, start_url, end_url, peer, tls_version, file_name_hash, crawl_try, 
                    headers, end_origin, results, cookies, end_site) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                    """, (
                        test_id, domain, url, end_url, peer, tls_version, file_name_hash, crawl_try, headers,
                        end_origin, json.dumps(results), json.dumps(cookies), end_site))
                else:
                    errors[test_id][crawl_try] = data
                    debug_print(f'Error in requesting {domain} with config {config}.')
                sleeptime = max(0, (start_previous + 2) - time.time())
                time.sleep(sleeptime)

        for test_id, _ in tests:
            if test_id in errors:
                cur.execute("UPDATE client_tests SET error=%s, crawled=TRUE WHERE id=%s;",
                            (json.dumps(errors[test_id]), test_id))
            else:
                cur.execute("UPDATE client_tests SET crawled=TRUE WHERE id=%s", (test_id,))
        cur.execute("COMMIT;")
        cur.execute("END;")
        cur.execute("BEGIN;")
        cur.execute(query)
        res = cur.fetchone()
    # commit last query
    cur.execute("COMMIT;")
    cur.execute("END;")
    print(f'Client Configuration Worker {worker_id} terminates!')


def client_configuration_crawler(start, end):
    print('START Client Configuration crawl.....')
    cur = get_db_cursor()
    cur.execute("SELECT COUNT(*) FROM (SELECT DISTINCT config FROM client_tests) as foo;")
    test_count, = cur.fetchone()
    processes = list()
    for wid in range(PROCESSES):
        p = Process(target=worker_client_configurations, args=(wid, start, end, test_count))
        processes.append(p)
        p.start()
    for p in processes:
        p.join()
    print('DONE.')


# -----------------------------------------------------------------------------
# ONION
def worker_onion(worker_id, end_node_data, start, end, test_count):
    print(f'Onion Worker {worker_id} started for {end_node_data}...')
    country_code, country, end_node = end_node_data
    cur = get_db_cursor(False)
    cur2 = get_db_cursor()
    if country_code is None:
        query = f"SELECT id, url FROM onion_tests WHERE NOT crawled " \
                f"AND id > {start * test_count} AND id <= {end * test_count} " \
                f"AND country_code IS %s AND country IS %s LIMIT 1 FOR UPDATE SKIP LOCKED;"
    else:
        query = f"SELECT id, url FROM onion_tests WHERE NOT crawled " \
                f"AND id > {start * test_count} AND id <= {end * test_count} " \
                f"AND country_code=%s AND country=%s LIMIT 1 FOR UPDATE SKIP LOCKED;"
    cur.execute("BEGIN;")
    cur.execute(query, (country_code, country))
    res = cur.fetchone()
    extract = tldextract.TLDExtract()
    while res is not None:
        test_id, url = res
        domain = '.'.join(extract(url))
        if domain.startswith('.'):
            domain = domain[1:]
        print(f'Onion Worker {worker_id} now works on {domain} ({url})')
        errors = {}
        for crawl_try in range(NUM_SAMPLES):
            success, data = crawl(url, proxies=(TOR_PROXY if country is not None else None))
            start_previous = time.time()
            if success:
                debug_print(f'Results requesting {domain} from {end_node_data}.')
                end_url, peer, tls_version, file_name_hash, headers = data
                end_origin = end_url.split("/")[0] + "//" + end_url.split("/")[2]
                end_site = extract(end_url).registered_domain
                save_file_info(cur2, file_name_hash)
                _, results, cookies, _ = classify_worker((1, end_url, json.loads(headers), 'onion'))
                cur2.execute("""
                INSERT INTO onion (test, end_node, domain, start_url, end_url, peer, tls_version, file_name_hash,
                 crawl_try, headers, end_origin, results, cookies, end_site) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (test_id, end_node, domain, url, end_url, peer, tls_version, file_name_hash, crawl_try, headers,
                      end_origin, json.dumps(results), json.dumps(cookies), end_site))
            else:
                errors[crawl_try] = data
                debug_print(f'Error in requesting {domain} from {end_node_data}.')
            sleeptime = max(0, (start_previous + 2) - time.time())
            time.sleep(sleeptime)
        if errors:
            cur.execute("UPDATE onion_tests SET error=%s, crawled=TRUE WHERE id=%s;",
                        (json.dumps(errors), test_id))
        else:
            cur.execute("UPDATE onion_tests SET crawled=TRUE WHERE id=%s", (test_id,))
        cur.execute("COMMIT;")
        cur.execute("END;")
        cur.execute("BEGIN;")
        cur.execute(query, (country_code, country))
        res = cur.fetchone()
    # commit last query
    cur.execute("COMMIT;")
    cur.execute("END;")
    print(f'Onion Worker {worker_id} terminates!')


def connect_to_tor(c):
    disconnect_tor()
    # Specify ExitNode in config File
    with open('torrc', 'r+') as tor_rc:
        tor_rc_old = tor_rc.read()
        tor_rc_mid = re.sub(r'Log debug file.*', f'Log debug file /tmp/tor-debug-{c.lower()}.log', tor_rc_old)
        tor_rc_new = re.sub(r'ExitNodes.*', 'ExitNodes {' + c.lower() + '} StrictNodes 1', tor_rc_old)  # tor_rc_mid)
        tor_rc.seek(0)
        tor_rc.write(tor_rc_new)
        tor_rc.truncate()
    time.sleep(1)
    # Connect to onion network
    os.system("tor -f torrc --runasdaemon 1")
    time.sleep(2)
    # Make sure that the connection has been established
    url = f"https://check.torproject.org/"
    try:
        r = requests.get(url, proxies=TOR_PROXY, stream=True, timeout=10)
    except Exception as e:
        print('No End Node for ' + c)
        print(e)
        return False
    while 'Congratulations.' not in r.text:
        try:
            r = requests.get(url, proxies=TOR_PROXY, stream=True, timeout=60)
        except Exception as e:
            print('Problem for ' + c)
            print(e)
            return False

        print('Tor Status:')
        try:
            print(r.text.split('<title>')[1].split('<')[0].strip())
        except:
            print(r.text)
        time.sleep(1)
    return True


def disconnect_tor():
    # Kill all tor instances
    os.system('kill $(pgrep tor)')
    time.sleep(2)
    # Make sure that the connection has been established
    r = b''
    while 'tor -f torrc' in r.decode():
        r = subprocess.check_output("ps -aef | grep -i 'tor '", shell=True)
        print('Tor still running:\n', r.decode().strip())
        time.sleep(1)


def onion_crawler(start, end):
    cur = get_db_cursor()
    print('START Onion crawl.....')
    own_ip = get_ip_address()
    print(f'Own Location: {json.dumps(own_ip)}')
    cur.execute("SELECT DISTINCT country_code, country FROM onion_tests ORDER BY country;")
    countries = cur.fetchall()
    for country_code, country in countries:
        if country_code is None:
            query = f"SELECT count(1) FROM onion_tests WHERE NOT crawled " \
                    f"AND id > {start * len(countries)} AND id <= {end * len(countries)} " \
                    f"AND country_code IS %s AND country IS %s;"
        else:
            query = f"SELECT count(1) FROM onion_tests WHERE NOT crawled " \
                    f"AND id > {start * len(countries)} AND id <= {end * len(countries)} " \
                    f"AND country_code=%s AND country=%s;"
        cur.execute(query, (country_code, country))

        # No need to connect to Tor if there are no jobs in current chunk
        if cur.fetchone()[0] == 0:
            continue

        try:
            if country_code is None:
                end_node = own_ip
            elif not connect_to_tor(country_code):
                with get_scoped_db_cursor() as cur2:
                    cur2.execute(
                        f"UPDATE onion_tests SET error=%s, crawled=TRUE "
                        f"WHERE country_code=%s AND country=%s "
                        f"AND id > {start * len(countries)} AND id <= {end * len(countries)};",
                        (json.dumps({i: 'Could not connect to TOR.' for i in range(NUM_SAMPLES)}),
                         country_code, country))
                continue
            else:
                end_node = get_ip_address(TOR_PROXY)
                if own_ip == end_node:
                    print(f'Error in connecting to {country}.')
                    with get_scoped_db_cursor() as cur2:
                        cur2.execute(
                            f"UPDATE onion_tests SET error=%s, crawled=TRUE "
                            f"WHERE country_code=%s AND country=%s"
                            f"AND id > {start * len(countries)} AND id <= {end * len(countries)};",
                            (json.dumps({i: 'Could not connect to TOR.' for i in range(NUM_SAMPLES)}),
                             country_code, country))
                    continue

            print(f'Successfully connected to {end_node} [Target was: {country}]')
            processes = list()
            for wid in range(PROCESSES):
                p = Process(target=worker_onion,
                            args=(wid, (country_code, country, end_node), start, end, len(countries)))
                processes.append(p)
                p.start()
            for p in processes:
                p.join()
        finally:
            disconnect_tor()
        print('\n')
    print('DONE.')


# -----------------------------------------------------------------------------
# VPN
def worker_vpns(worker_id, vpn_data, ip, start, end, test_count):
    print(f'VPN Worker {worker_id} started for {vpn_data} ...')
    vpn_dom, country_code, country = vpn_data
    cur = get_db_cursor(False)
    cur2 = get_db_cursor()
    if vpn_dom is None:
        query = f"SELECT id, url FROM vpn_tests WHERE NOT crawled " \
                f"AND id > {start * test_count} AND id <= {end * test_count} " \
                f"AND vpn_dom IS %s AND country_code IS %s AND country IS %s LIMIT 1 FOR UPDATE SKIP LOCKED;"
    else:
        query = f"SELECT id, url FROM vpn_tests WHERE NOT crawled " \
                f"AND id > {start * test_count} AND id <= {end * test_count} " \
                f"AND vpn_dom=%s AND country_code=%s AND country=%s LIMIT 1 FOR UPDATE SKIP LOCKED;"
    cur.execute("BEGIN;")
    cur.execute(query, vpn_data)
    res = cur.fetchone()
    tld_cache_dir = f"/tmp/tldextract_cache_{worker_id}"
    if not os.path.exists(tld_cache_dir):
        os.makedirs(tld_cache_dir)
    extract = tldextract.TLDExtract(cache_dir=tld_cache_dir)
    while res is not None:
        test_id, url = res
        domain = '.'.join(extract(url))
        if domain.startswith('.'):
            domain = domain[1:]
        print(f'VPN Worker {worker_id} now works on {domain} ({url})')
        errors = {}
        for crawl_try in range(NUM_SAMPLES):
            success, data = crawl(url)
            start_previous = time.time()
            if success:
                debug_print(f'Results requesting {domain} from {vpn_data}.')
                end_url, peer, tls_version, file_name_hash, headers = data
                end_origin = end_url.split("/")[0] + "//" + end_url.split("/")[2]
                end_site = extract(end_url).registered_domain
                save_file_info(cur2, file_name_hash)
                _, results, cookies, _ = classify_worker((1, end_url, json.loads(headers), 'vpn'))
                cur2.execute("""
                INSERT INTO vpn (test, ip, domain, start_url, end_url, peer, tls_version, file_name_hash, crawl_try,
                 headers, end_origin, results, cookies, end_site) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (
                    test_id, ip, domain, url, end_url, peer, tls_version, file_name_hash, crawl_try, headers,
                    end_origin, json.dumps(results), json.dumps(cookies), end_site))
            else:
                errors[crawl_try] = data
                debug_print(f'Error in requesting {domain} from {vpn_data}.')
            sleeptime = max(0, (start_previous + 2) - time.time())
            time.sleep(sleeptime)
        if errors:
            cur.execute("UPDATE vpn_tests SET error=%s, crawled=TRUE WHERE id=%s;",
                        (json.dumps(errors), test_id))
        else:
            cur.execute("UPDATE vpn_tests SET crawled=TRUE WHERE id=%s", (test_id,))
        cur.execute("COMMIT;")
        cur.execute("END;")
        cur.execute("BEGIN;")
        cur.execute(query, vpn_data)
        res = cur.fetchone()
    # commit last query
    cur.execute("COMMIT;")
    cur.execute("END;")
    print(f'VPN Worker {worker_id} terminates!')


def connect_to_vpn(c):
    # Assumes credentials in VPN/hmauser.pass
    # Assumes a set uid bit => chmod u+s VPN/hma-vpn.sh
    # https://support.hidemyass.com/hc/en-us/articles/202721456-Recommended-Linux-CLI-OpenVPN-Client
    # Usage -d demonize, -c credential_file
    # Make sure that the connection has been established
    output = b''
    i = 0
    while 'Connected' not in output.decode():
        if i >= 32:
            if MATTERMOST_ERROR_HOOK is not None:
                requests.post(MATTERMOST_ERROR_HOOK,
                              json={'text': f'Failed to connect to {c}', 'username': 'VPN Crawl Failure'})
            else:
                print(f'Failed to connect to {c}')
            return False
        if 'Failed' in output.decode() or output.decode() == '' or 'Disconnected' in output.decode():
            os.system(f'cd VPN && /bin/bash hma-vpn.sh -x')
            time.sleep(1)
            os.system(f'cd VPN/ && /bin/bash hma-vpn.sh -d -c hmauser.pass "{c}"')
            time.sleep(3)

        try:
            output = subprocess.check_output(['/bin/bash', 'hma-vpn.sh', '-s'], cwd=VPN_DIR, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = str(e.output).encode()
        print('VPN Status:')
        print(output.decode())
        time.sleep(1)
        i += 1
    return True


def disconnect_vpn():
    # Kill the HMA instance
    os.system('cd VPN/ && /bin/bash hma-vpn.sh -x')
    time.sleep(2)
    # Make sure that the connection has been established
    output = b''
    while 'Disconnected' not in output.decode():
        try:
            output = subprocess.check_output(['/bin/bash', 'hma-vpn.sh', '-s'], cwd=VPN_DIR, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = str(e.output).encode()
        print('VPN status:')
        print(output.decode())
        time.sleep(1)


def vpn_crawler(start, end):
    cur = get_db_cursor()
    print('START VPN crawl.....')
    cur.execute("SELECT DISTINCT vpn_dom, country_code, country FROM vpn_tests ORDER BY country_code, vpn_dom;")
    vpn_data = cur.fetchall()
    for vpn_dom, country_code, country in vpn_data:
        if vpn_dom is None:
            query = f"SELECT count(1) FROM vpn_tests WHERE NOT crawled " \
                    f"AND id > {start * len(vpn_data)} AND id <= {end * len(vpn_data)} " \
                    f"AND vpn_dom IS %s AND country_code IS %s AND country IS %s;"
        else:
            query = f"SELECT count(1) FROM vpn_tests WHERE NOT crawled " \
                    f"AND id > {start * len(vpn_data)} AND id <= {end * len(vpn_data)} " \
                    f"AND vpn_dom=%s AND country_code=%s AND country=%s;"
        cur.execute(query, (vpn_dom, country_code, country))

        # No need to connect to VPN if there are no jobs in current chunk
        if cur.fetchone()[0] == 0:
            continue

        try:
            if vpn_dom is None or connect_to_vpn(vpn_dom):
                ip = get_ip_address()
                processes = list()
                for wid in range(PROCESSES):
                    p = Process(target=worker_vpns,
                                args=(wid, (vpn_dom, country_code, country), ip, start, end, len(vpn_data)))
                    processes.append(p)
                    p.start()
                for p in processes:
                    p.join()
            else:
                print(f'Error in connecting to {(vpn_dom, country_code, country)}.')
                with get_scoped_db_cursor() as cur2:
                    cur2.execute(
                        f"UPDATE vpn_tests SET error=%s, crawled=TRUE "
                        f"WHERE vpn_dom=%s AND country_code=%s AND country=%s "
                        f"AND id > {start * len(vpn_data)} AND id <= {end * len(vpn_data)};",
                        (json.dumps({i: 'Could not connect to VPN.' for i in range(NUM_SAMPLES)}),
                         vpn_dom, country_code, country))
        finally:
            disconnect_vpn()
    print('DONE.')


def save_file_info(cur, file_name_hash):
    cur.execute("SELECT 1 FROM script_stats WHERE file_name_hash=%s", (file_name_hash,))
    if cur.rowcount > 0:
        return

    result = file_worker(file_name_hash)
    if result:
        rel, stats, html_stats, title, file_bytes = result
        cur.execute("""
                    INSERT INTO script_stats VALUES (%s, %s, %s, %s, %s) ON CONFLICT (file_name_hash) DO UPDATE 
                    SET stats=excluded.stats, html_tree=excluded.html_tree, title=excluded.title, file_bytes=excluded.file_bytes
                """, (rel, stats, html_stats, title, file_bytes))


# -----------------------------------------------------------------------------
# SETUP
def setup():
    print('Running Setup....')
    cur = get_db_cursor()

    cur.execute("""
        CREATE TABLE dataset (
        start_url VARCHAR(64),
        start_site VARCHAR(256)
        );
    """)

    cur.execute("""
    CREATE UNIQUE INDEX ON dataset (start_url);
    """)

    cur.execute("""
    CREATE TABLE script_stats (
            file_name_hash VARCHAR(32) UNIQUE,
            stats JSONB,
            html_tree JSONB,
            title TEXT,
            file_bytes INTEGER
        );
    """)

    # Browser
    cur.execute("""
        CREATE TABLE browser (
            id SERIAL PRIMARY KEY,
            test INTEGER,
            domain VARCHAR(64),
            start_url VARCHAR(64),
            end_url VARCHAR(1024),
            peer VARCHAR(64),
            tls_version VARCHAR(64),
            file_name_hash VARCHAR(32),
            crawl_try INTEGER,
            headers JSONB,
            timestamp TIMESTAMP DEFAULT NOW(),
            results JSONB default null,
            cookies JSONB default null,
            cluster int default null,
            end_origin varchar(256) default null,
            end_site varchar(256) default null
        );
    """)
    for column in ["test", "domain", "peer", "tls_version", "file_name_hash", "crawl_try",
                   "end_origin", "cluster", "end_site"]:
        cur.execute(f"CREATE INDEX ON browser ({column});")

    print('Created table Browser')

    cur.execute(f"""
        CREATE TABLE browser_tests (
            id SERIAL PRIMARY KEY,
            browser VARCHAR(32),
            os VARCHAR(32),
            url VARCHAR(64),
            crawled BOOLEAN DEFAULT FALSE,
            error JSONB DEFAULT NULL
        );
    """)
    for column in ["browser", "os", "url", "crawled"]:
        cur.execute(f"CREATE INDEX ON browser_tests ({column})")
    cur.execute("CREATE UNIQUE INDEX ON browser_tests (browser, os, url);")

    print('Created table browser_tests')

    # Client
    cur.execute("""
        CREATE TABLE client (
            id SERIAL PRIMARY KEY,
            test INTEGER,
            domain VARCHAR(64),
            start_url VARCHAR(64),
            end_url VARCHAR(1024),
            peer VARCHAR(64),
            tls_version VARCHAR(64),
            file_name_hash VARCHAR(32),
            crawl_try INTEGER,
            headers JSONB,
            timestamp TIMESTAMP DEFAULT NOW(),
            results JSONB default null,
            cookies JSONB default null,
            cluster int default null,
            end_origin varchar(256) default null,
            end_site varchar(256) default null
        );
    """)
    for column in ["test", "domain", "peer", "tls_version", "file_name_hash", "crawl_try",
                   "end_origin", "cluster", "end_site"]:
        cur.execute(f"CREATE INDEX ON client ({column})")

    print('Created table Client')

    cur.execute(f"""
                CREATE TABLE client_tests (
                    id SERIAL PRIMARY KEY,
                    config JSONB,
                    url VARCHAR(64),
                    crawled BOOLEAN DEFAULT FALSE,
                    error JSONB DEFAULT NULL
                );
            """)
    for column in ["config", "url", "crawled"]:
        cur.execute(f"CREATE INDEX ON client_tests ({column})")
    cur.execute("CREATE UNIQUE INDEX ON client_tests (config, url)")

    print('Created table client_tests')

    # Onion
    cur.execute("""
        CREATE TABLE onion (
            id SERIAL PRIMARY KEY,
            test INTEGER,
            end_node VARCHAR(64),
            domain VARCHAR(64),
            start_url VARCHAR(64),
            end_url VARCHAR(1024),
            peer VARCHAR(64),
            tls_version VARCHAR(64),
            file_name_hash VARCHAR(32),
            crawl_try INTEGER,
            headers JSONB,
            timestamp TIMESTAMP DEFAULT NOW(),
            results JSONB default null,
            cookies JSONB default null,
            cluster int default null,
            end_origin varchar(256) default null,
            end_site varchar(256) default null
        );
    """)
    for column in ["test", "domain", "end_node", "peer", "tls_version", "file_name_hash", "crawl_try",
                   "end_origin", "cluster", "end_site"]:
        cur.execute(f"CREATE INDEX ON onion ({column})")

    print('Created table Onion')

    cur.execute(f"""
            CREATE TABLE onion_tests (
                id SERIAL PRIMARY KEY,
                country_code VARCHAR(2),
                country VARCHAR(64),
                url VARCHAR(64),
                crawled BOOLEAN DEFAULT FALSE,
                error JSONB DEFAULT NULL
            );
        """)
    for column in ["country_code", "country", "url", "crawled"]:
        cur.execute(f"CREATE INDEX ON onion_tests ({column})")
    cur.execute("CREATE UNIQUE INDEX ON onion_tests (country_code, country, url)")

    print('Created table onion_tests')

    # VPN
    cur.execute("""
        CREATE TABLE vpn (
            id SERIAL PRIMARY KEY,
            test INTEGER,
            ip VARCHAR(64),
            domain VARCHAR(64),
            start_url VARCHAR(64),
            end_url VARCHAR(1024),
            peer VARCHAR(64),
            tls_version VARCHAR(64),
            file_name_hash VARCHAR(32),
            crawl_try INTEGER,
            headers JSONB,
            timestamp TIMESTAMP DEFAULT NOW(),
            results JSONB default null,
            cookies JSONB default null,
            cluster int default null,
            end_origin varchar(256) default null,
            end_site varchar(256) default null
        );
    """)
    for column in ["test", "domain", "ip", "peer", "tls_version", "file_name_hash", "crawl_try",
                   "end_origin", "cluster", "end_site"]:
        cur.execute(f"CREATE INDEX ON vpn ({column})")

    print('Created table VPN')

    cur.execute(f"""
            CREATE TABLE vpn_tests (
                id SERIAL PRIMARY KEY,
                vpn_dom VARCHAR(64),
                country_code VARCHAR(2),
                country VARCHAR(64),
                url VARCHAR(64),
                crawled BOOLEAN DEFAULT FALSE,
                error JSONB DEFAULT NULL
            );
        """)
    for column in ["country_code", "country", "vpn_dom", "url", "crawled"]:
        cur.execute(f"CREATE INDEX ON vpn_tests ({column})")

    cur.execute("CREATE UNIQUE INDEX ON vpn_tests (vpn_dom, country_code, country, url)")

    print('Created table vpn_tests')

    print('DONE.')


def add_tests():
    print('Creating & Filling Test Tables...')
    urls = []
    with open(DOMAINS_FILE, 'r') as f:
        for entry in f.readlines()[URL_LOWER:URL_UPPER]:
            urls.append(entry.split(',', 1)[1].strip())

    cur = get_db_cursor()
    for url in urls:
        site = tldextract.extract(url).registered_domain
        cur.execute("""
        INSERT INTO dataset (start_url, start_site) VALUES (%s, %s) ON CONFLICT DO NOTHING
        """, (url, site))

    # Browser
    if os.environ.get('DO_BROWSER', None) != '1':
        print('Skipping browser crawl preparation because DO_BROWSER != 1.')
    else:
        for url in urls:
            for browser in UserAgents:
                for system in UserAgents[browser]:
                    if UserAgents[browser][system] is not None:
                        query = f'INSERT INTO browser_tests (browser, os, url) VALUES (%s, %s, %s)'
                        cur.execute(query, (browser, system, url))
        print('Filled table browser_tests')

    # Client
    if os.environ.get('DO_LANGUAGE', None) != '1':
        print('Skipping client crawl preparation because DO_LANGUAGE != 1.')
    else:
        for url in urls:
            for config in ClientConfigurations:
                query = f'INSERT INTO client_tests (config, url) VALUES (%s, %s)'
                cur.execute(query, (json.dumps(config), url))
        print('Filled table client_tests')

    # Onion
    if os.environ.get('DO_ONION', None) != '1':
        print('Skipping onion crawl preparation because DO_ONION != 1.')
    else:
        # use TOR exit node list to select countries we want to use
        c = requests.get("https://onionoo.torproject.org/details?search=flag:exit").json()
        countries = set([(x['country'], x['country_name']) for x in c["relays"]])

        for url in urls:
            for country_code, country in countries:
                query = f'INSERT INTO onion_tests (country_code, country, url) VALUES (%s, %s, %s)'
                cur.execute(query, (country_code, country, url))
        print('Filled table onion_tests')

    # VPN
    if os.environ.get('DO_VPN', None) != '1':
        print('Skipping VPN crawl preparation because DO_VPN != 1.')
    else:
        vpn_server_list = get_vpn_list()
        for url in urls:
            seen_countries = set()
            for vpn_dom, country_code, country in vpn_server_list:
                if country_code in seen_countries:
                    continue
                seen_countries.add(country_code)
                query = f'INSERT INTO vpn_tests (vpn_dom, country_code, country, url) VALUES (%s, %s, %s, %s)'
                cur.execute(query, (vpn_dom, country_code, country, url))
        print('Filled table vpn_tests')

    print('DONE.')


# -----------------------------------------------------------------------------
def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'setup':
        setup()
    elif len(sys.argv) > 1 and sys.argv[1] == 'add_tests':
        add_tests()
    elif len(sys.argv) > 1 and sys.argv[1] == 'browser':
        for i in range(URL_LOWER, URL_UPPER, CHUNKSIZE):
            browser_crawler(i, min(URL_UPPER, i + CHUNKSIZE))
    elif len(sys.argv) > 1 and sys.argv[1] == 'client':
        for i in range(URL_LOWER, URL_UPPER, CHUNKSIZE):
            client_configuration_crawler(i, min(URL_UPPER, i + CHUNKSIZE))
    elif len(sys.argv) > 1 and sys.argv[1] == 'onion':
        for i in range(URL_LOWER, URL_UPPER, CHUNKSIZE):
            onion_crawler(i, min(URL_UPPER, i + CHUNKSIZE))
    elif len(sys.argv) > 1 and sys.argv[1] == 'vpn':
        for i in range(URL_LOWER, URL_UPPER, CHUNKSIZE):
            vpn_crawler(i, min(URL_UPPER, i + CHUNKSIZE))
    else:
        print('No mode specified: Use [setup|add_tests|browser|client|onion|vpn]')


if __name__ == '__main__':
    main()
