from enums import *

import re


def parse_header(header: str, value: str, origin: str) -> dict:
    if header == 'content-security-policy':
        return parse_csp(origin, value)
    elif header == 'strict-transport-security':
        return parse_hsts(value)
    elif header == 'x-frame-options':
        return parse_xfo(value)
    elif header == 'set-cookie':
        return parse_cookie(value)
    else:
        print(f'Header {header} not supported!!')
        return None


# ----------------------------------------------------------------------------
# Cookies
def classify_cookie(cookie_stats: dict) -> dict:
    classes = {
        'secure': CookieSecure.UNSAFE.value,
        'httponly': CookieSecure.UNSAFE.value,
        'samesite': CookieSecure.UNSAFE.value
    }
    if 'secure' in cookie_stats['keywords']:
        classes['secure'] = CookieSecure.SAFE.value
    if 'httponly' in cookie_stats['keywords']:
        classes['httponly'] = CookieHttpOnly.SAFE.value
    if cookie_stats['samesite'] == 'strict':
        classes['samesite'] = CookieSameSite.STRICT.value
    if cookie_stats['samesite'] == 'lax':
        classes['samesite'] = CookieSameSite.LAX.value
    return classes


def parse_cookie(cookie_string: str) -> dict:
    if cookie_string is None:
        return {}
    parsed_cookies = dict()
    for cv in re.split(r', (?!\d)', cookie_string):
        spliced = cv.split(';')
        keywords = set()
        same_site = None
        domain = None
        path = '/'
        cookie_name = spliced[0].strip().split('=')[0].strip()
        spliced = spliced[1:]
        for entry in spliced:
            entry = entry.strip()
            if entry.lower() == 'secure' or entry.lower() == 'httponly':
                keywords.add(entry.lower())
            elif '=' in entry:
                splitter_sub = entry.lower().split('=', 1)
                if splitter_sub[0].lower() == 'domain':
                    domain = splitter_sub[1]
                elif splitter_sub[0].lower() == 'path':
                    path = splitter_sub[1]
                elif splitter_sub[0].lower() == 'samesite':
                    if splitter_sub[1] == 'none' or splitter_sub[1] == 'lax' or splitter_sub[1] == 'strict':
                        same_site = splitter_sub[1]
        cookie_name = None if cookie_name is None else cookie_name.split(',')[0]
        same_site = None if same_site is None else same_site.split(',')[0]
        domain = None if domain is None else domain.split(',')[0].lstrip('.')
        path = '' if path is None else path.split(',')[0].rstrip('/')
        cookie_identifier = f'{cookie_name}|{domain}|{path}'
        parsed_cookies[cookie_identifier] = {
            "keywords": list(keywords),
            "samesite": same_site,
            "name": cookie_name,
            "domain": domain,
            "path": path
        }
    # Convert Cookie-Jar to Cookie Classes
    classified_cookies = dict()
    for cookie_id in parsed_cookies:
        classified_cookies[cookie_id] = classify_cookie(parsed_cookies[cookie_id])
    return classified_cookies


# ----------------------------------------------------------------------------
# CSP
def is_unsafe_inline_active(sources: set) -> bool:
    allow_all_inline = False
    for source in sources:
        r = r"^('NONCE'|'nonce-[A-Za-z0-9+/\-_]+={0,2}'|'sha(256|384|512)-[A-Za-z0-9+/\-_]+={0,2}'|'strict-dynamic')$"
        if re.search(r, source, re.IGNORECASE):
            return False
        if re.match(r"^'unsafe-inline'$", source, re.IGNORECASE):
            allow_all_inline = True
    return allow_all_inline


# Paper Definition 3
def is_safe_csp(csp: dict) -> bool:
    unsafe_expressions = {'*', 'http:', 'http://', 'http://*', 'https:', 'https://', 'https://*', 'data:'}
    effective_source = csp['script-src'] if "script-src" in csp else csp.get('default-src', None)
    if effective_source is None or is_unsafe_inline_active(effective_source):
        return False
    if "'strict-dynamic'" not in effective_source and effective_source & unsafe_expressions:
        return False
    return True


def classify_framing(origin: str, sources: set) -> int:
    if sources == {"'none'"} or len(sources) == 0:
        return FA.NONE.value
    https_origin = origin.replace('http://', 'https://')
    domain_origin = origin.replace('http://', '').replace('https://', '')
    if len(sources) > 0 and len(sources - {"'self'", origin, https_origin, domain_origin}) == 0:
        return FA.SELF.value
    unsafe_expressions = {'*', 'http:', 'http://', 'http://*', 'https:', 'https://', 'https://*'}
    if sources.intersection(unsafe_expressions):
        return FA.UNSAFE.value
    return FA.CONSTRAINED.value


def classify_csp(origin: str, parsed_csp: dict) -> dict:
    classes = {'FA': FA.UNSAFE.value, 'XSS': XSS.UNSAFE.value, 'TLS': TLS.UNSAFE.value}
    if is_safe_csp(parsed_csp):
        classes['XSS'] = XSS.SAFE.value
    if 'upgrade-insecure-requests' in parsed_csp or 'block-all-mixed-content' in parsed_csp:
        classes['TLS'] = TLS.ENABLED.value
    if 'frame-ancestors' in parsed_csp:
        classes['FA'] = classify_framing(origin, parsed_csp['frame-ancestors'])
    return classes


def parse_csp(origin: str, raw_csp: str) -> dict:
    if raw_csp is None:
        return {'FA': FA.UNSAFE.value, 'XSS': XSS.UNSAFE.value, 'TLS': TLS.UNSAFE.value}
    # Normalize Random Values
    policy_str = raw_csp
    nonce_regex = r"'nonce-[^']*'"
    policy_str = re.sub(nonce_regex, "'NONCE'", policy_str)
    report_regex = r"report-uri [^; ]*"
    policy_str = re.sub(report_regex, 'report-uri REPORT_URI;', policy_str)
    report_to = r"report-to [^; ]*"
    policy_str = re.sub(report_to, 'report-to REPORT_URI;', policy_str)
    # Let policy be a new policy with an empty directive set
    complete_policy = dict()
    # For each token returned by splitting list on commas
    for policy_string in policy_str.encode().lower().split(b','):
        # Let policy be a new policy with an empty directive set
        policy = dict()
        # For each token returned by strictly splitting serialized on the U+003B SEMICOLON character (;):
        tokens = policy_string.split(b';')
        for token in tokens:
            # Strip all leading and trailing ASCII whitespace from token.
            data = token.strip().split()
            # If token is an empty string, continue.
            if len(data) == 0:
                continue
            # Let directive name be the result of collecting a sequence of code points from
            # token which are not ASCII whitespace.
            while data[0] == ' ':
                data = data[1:]
                if len(data) == 0:
                    break
            # If token is an empty string, continue.
            if len(data) == 0:
                continue
            # Set directive name to be the result of running ASCII lowercase on directive name.
            directive_name = data[0]
            # If policy's directive set contains a directive whose name is directive name, continue.
            if directive_name in policy:
                continue
            # Let directive value be the result of splitting token on ASCII whitespace.
            directive_set = set()
            for d in data[1:]:
                if d.strip() != '':
                    directive_set.add(d.decode())
            # Append directive to policy’s directive set.
            policy[directive_name.decode()] = directive_set
        csp_classes = classify_csp(origin, policy)
        for use_case in csp_classes:
            if use_case in complete_policy:
                complete_policy[use_case] = max(complete_policy[use_case], csp_classes[use_case])
            else:
                complete_policy[use_case] = csp_classes[use_case]
    # Return policy dict
    return complete_policy


# ----------------------------------------------------------------------------
# XFO
def classify_xfo(value):
    assert value.strip() == value
    if value == 'deny':
        return XFO.NONE.value
    elif value == 'sameorigin':
        return XFO.SELF.value
    else:
        return XFO.UNSAFE.value


def parse_xfo(raw_xfo):
    if raw_xfo is None:
        return {'XFO': XFO.UNSAFE.value}
    return {'XFO': max(classify_xfo(value.strip()) for value in raw_xfo.lower().split(','))}


# ----------------------------------------------------------------------------
# HSTS
def classify_hsts_age(max_age):
    if max_age is None:
        return HSTSAge.UNSAFE.value
    elif max_age == 0:
        return HSTSAge.DISABLE.value
    elif 0 < max_age < 24 * 60 * 60 * 365:
        return HSTSAge.LOW.value
    else:
        return HSTSAge.BIG.value


def parse_hsts(raw_hsts):
    if raw_hsts is None:
        return {'HSTS': (HSTSAge.UNSAFE.value, HSTSSub.UNSAFE.value, 0)}
    value = raw_hsts.split(',')[0]  # only consider first header-value
    max_age = None
    include_sub_domains = False
    preload = False
    try:
        for element in value.split(";"):
            if element.strip().lower() == 'includesubdomains':  # RFC 7230 says case doesn't matter
                if include_sub_domains:
                    raise ValueError
                include_sub_domains = True
            if element.strip().lower() == 'preload':  # RFC 7230 says case doesn't matter
                if preload:
                    raise ValueError
                preload = True
            if element.strip().lower().startswith('max-age'):
                if max_age is not None:
                    raise ValueError
                try:
                    max_age = int(element.strip().split('=')[1])
                except IndexError:
                    raise ValueError
        if max_age is None:
            include_sub_domains = False
    except ValueError:
        # invalid header value
        max_age = None
        include_sub_domains = False
        preload = False
    return {'HSTS': (classify_hsts_age(max_age),
                     int(include_sub_domains),
                     int(preload and include_sub_domains and classify_hsts_age(max_age) == HSTSAge.BIG.value))}
