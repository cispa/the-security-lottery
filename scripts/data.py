from psycopg2.extras import RealDictCursor
from contextlib import contextmanager

import psycopg2
import random
import time
import os

DB_USER = os.environ.get('DB_USER', None)
if DB_USER is None:
    print('Environment variable DB_USER is missing!')
    exit(-1)

DB_NAME = os.environ.get('DB_NAME', None)
if DB_NAME is None:
    print('Environment variable DB_NAME is missing!')
    exit(-1)

DB_HOST = os.environ.get('DB_HOST', None)
if DB_HOST is None:
    print('Environment variable DB_NAME is missing!')
    exit(-1)

DB_PORT = os.environ.get('DB_PORT', None)
if DB_PORT is None:
    print('Environment variable DB_PORT is missing!')
    exit(-1)

DB_PWD = os.environ.get('DB_PWD', None)
if DB_PWD is None:
    print('Environment variable DB_PWD is missing!')
    exit(-1)

SecurityHeaders = {
    'content-security-policy-report-only',  # Indicator for CSP
    'access-control-allow-origin',  # Indicator for CORS
    'strict-transport-security',  # Indicator for MITM
    'content-security-policy',  # Indicator for CSP
    'public-key-pins',  # Indicator for MITM
    'referrer-policy',  # Indicator for Privacy Stuff
    'feature-policy',  # Indicator for Privacy Stuff
    'cache-control',  # Indicator for Privacy Stuff
    'set-cookie',  # Indicator for session hijacking
    'x-content-security-policy',  # Indicator for CSP
    'x-content-type-options',  # Indicator for Content Type Sniffing
    'x-xss-protection',  # Indicator for XSS
    'x-frame-options',  # Indicator for Clickjacking
    'transfer-encoding',  # Indicator for HTTP desync
    'expires'  # Indicator for Privacy Stuff
}

# Data taken from https://www.whatismybrowser.com/guides/the-latest-user-agent/ on 27th December 2021
UserAgents = {
    'chrome': {
        'windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
        'macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
        'linux': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
        'ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/96.0.4664.116 Mobile/15E148 Safari/604.1',
        'android': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
    },
    'firefox': {
        'windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0',
        'macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12.1; rv:95.0) Gecko/20100101 Firefox/95.0',
        'linux': 'Mozilla/5.0 (X11; Linux i686; rv:95.0) Gecko/20100101 Firefox/95.0',
        'ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/40.0 Mobile/15E148 Safari/605.1.15',
        'android': 'Mozilla/5.0 (Android 12; Mobile; rv:68.0) Gecko/68.0 Firefox/95.0',
    },
    'safari': {
        'macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15',
        'ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1',
        'windows': None,
        'android': None,
        'linux': None,
    },
    'edge': {
        'windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62',
        'macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62',
        'android': 'Mozilla/5.0 (Linux; Android 10; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36 EdgA/96.0.1054.53',
        'ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 EdgiOS/96.1054.49 Mobile/15E148 Safari/605.1.15',
        'linux': None,
    },
    'opera': {
        'windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 OPR/82.0.4227.43',
        'macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 OPR/82.0.4227.43',
        'linux': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 OPR/82.0.4227.43',
        'android': 'Mozilla/5.0 (Linux; Android 10; SM-G970F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36 OPR/63.3.3216.58675',
        'ios': None,
    }
}

ClientConfigurations = [
    {'Accept-Language': 'en'},
    {'Accept-Language': 'es'},
    {'Accept-Language': 'cn'},
    {'Accept-Language': 'ru'},
    {'Accept-Language': 'de'}
]


def get_db_cursor(autocommit=True, dict_cursor=False, fails=0, database=DB_NAME):
    if fails > 10:
        raise Exception("I died :(")
    try:
        conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=database, user=DB_USER, password=DB_PWD)
        conn.autocommit = autocommit
        if dict_cursor:
            cur = conn.cursor(cursor_factory=RealDictCursor)
        else:
            cur = conn.cursor()
        return cur
    except Exception as _:
        time.sleep(random.randint(10, 20) / 10)
        get_db_cursor(autocommit, dict_cursor, fails + 1, database=database)


@contextmanager
def get_scoped_db_cursor(autocommit=True, dict_cursor=False):
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PWD)
    conn.autocommit = autocommit
    if dict_cursor:
        cur = conn.cursor(cursor_factory=RealDictCursor)
    else:
        cur = conn.cursor()
    try:
        yield cur
    finally:
        cur.close()
        conn.close()
