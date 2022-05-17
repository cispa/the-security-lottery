from data import get_db_cursor, DB_NAME
from collections import defaultdict

import tldextract
import functools
import itertools
import locale
import json
import sys
import os

DATA_DIRECTORY = '/data'

locale.setlocale(locale.LC_ALL, '')

extract = tldextract.TLDExtract()


class DDEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, defaultdict):
            return dict(obj)
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


def recursive_filter(old_data, dataset):
    new_data = defaultdict(set)
    for key, values in old_data.items():
        if isinstance(values, set) or isinstance(values, list):
            new_data[key] = set(
                [extract(x).registered_domain for x in values if extract(x).registered_domain in dataset])
        else:
            new_data[key] = recursive_filter(values, dataset)
    return new_data


def main():
    cur = get_db_cursor()

    cur.execute("""
    SELECT start_site FROM dataset
    """)

    sites = set([x[0] for x in cur.fetchall()])

    tables = ['browser', 'client', 'vpn', 'onion']
    csp_keys = ['XSS', 'FA', 'TLS']
    mechanisms = ['XSS', 'FA', 'TLS', 'XFO', 'HSTS']
    cookie_mech = ['cookie', 'cookie secure', 'cookie samesite', 'cookie httponly']

    cookie_debug = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    mechanism_debug = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(set))))

    if not os.path.exists(f"result_{DB_NAME}.json"):
        data = {"inter": dict(), "intra": dict(),
                "usage": dict(),
                "intra_any": defaultdict(set), "inter_any": defaultdict(set)}

        filters = {"XSS": "results->>'XSS' = '1'",
                   "FA": "(results->>'FA')::int IN (1,2,3)",
                   "TLS": "results->>'TLS' = '1'",
                   "XFO": "results->>'XFO' != '0'",
                   "HSTS": "(results->'HSTS'->>0)::int IN (-1, 1, 2);",
                   "cookie secure": "cookies::text LIKE '%secure\": 1%'",
                   "cookie httponly": "cookies::text LIKE '%httponly\": 1%'",
                   "cookie samesite": "cookies::text LIKE '%samesite\": 1%' or cookies::text LIKE '%samesite\": 2%'",
                   }

        for table in tables:
            data["inter"][table] = defaultdict(set)
            data["intra"][table] = defaultdict(set)
            data["usage"][table] = defaultdict(set)

            for mechanism, filter_string in filters.items():
                cur.execute(f"""
                SELECT DISTINCT end_origin FROM {table} WHERE {filter_string}
                """)

                for end_origin, in cur.fetchall():
                    extracted_site = extract(end_origin).registered_domain
                    if extracted_site not in sites:
                        continue
                    data["usage"][table][mechanism].add(extracted_site)

            data["usage"][table]['CSP'] = data["usage"][table]['XSS'] | data["usage"][table]['TLS'] | \
                                          data["usage"][table]['FA']

            data["usage"][table]['cookie'] = data["usage"][table]['cookie secure'] | \
                                             data["usage"][table]['cookie httponly'] | \
                                             data["usage"][table]['cookie samesite']

            cur.execute(f"""
                        SELECT end_origin, test, cluster, "key", array_agg(DISTINCT "value") as vls FROM ( 
                        SELECT test, cluster, end_origin, (jsonb_each(cookies)).* FROM {table})
                        as foo
                        GROUP BY end_origin, test, cluster, "key"
                        HAVING array_length(array_agg(DISTINCT "value"), 1) > 1;
                        """)

            for end_origin, test, cluster, cookie_id, features in cur.fetchall():
                for a, b in itertools.combinations(features, 2):
                    diffs = {x: y for x, y in a.items() if x in b and b[x] != y}
                    for flag in diffs.keys():
                        data["intra"][table][f"cookie {flag}"].add(end_origin)
                        data["intra"][table][f"cookie"].add(end_origin)
                        data["intra_any"][f"cookie {flag}"].add(end_origin)
                        data["intra_any"][f"cookie"].add(end_origin)
                        cookie_info = (cookie_id, flag, cluster)
                        cookie_debug["intra"][table][end_origin].add(cookie_info)

            cur.execute(f"""
            WITH cc AS (SELECT test, cluster, "key", count(1), array_agg(DISTINCT "value") as vls FROM ( 
            SELECT test, cluster, (jsonb_each(cookies)).* FROM {table})
            as foo
            GROUP BY test, cluster, "key"
            HAVING array_length(array_agg(DISTINCT "value"), 1) = 1
            AND count(1) >= 3
            )
            
            SELECT DISTINCT end_origin, cluster, "key", array_agg(DISTINCT "vls") FROM (
            SELECT DISTINCT end_site, end_origin, cluster, "key", vls, test
            FROM cc LEFT JOIN {table} USING (test, cluster)) as moo
            WHERE end_site IN (SELECT start_site FROM dataset)
            GROUP BY end_origin, cluster, "key" HAVING array_length(array_agg(DISTINCT vls), 1) > 1;
            """)

            for end_origin, cluster, cookie_id, attribute_pairs in cur.fetchall():
                for a, b in itertools.combinations(attribute_pairs, 2):
                    a, b = a[0], b[0]
                    for flag in a.keys() & b.keys():
                        if a[flag] != b[flag]:
                            data["inter"][table][f"cookie {flag}"].add(end_origin)
                            data["inter"][table][f"cookie"].add(end_origin)
                            data["inter_any"][f"cookie {flag}"].add(end_origin)
                            data["inter_any"][f"cookie"].add(end_origin)
                            cookie_info = (cookie_id, flag, cluster)
                            cookie_debug["inter"][table][end_origin].add(cookie_info)

            cur.execute(f"""
            SELECT end_origin,
            cluster,
            test,
            array_agg(DISTINCT results)
            FROM {table} 
            WHERE cluster IS NOT NULL
            GROUP BY 1, 2, 3
            HAVING count(1) >= 3
            AND array_length(array_agg(DISTINCT results), 1) > 1;
            """)

            for end_origin, cluster, test, results in cur.fetchall():
                data["intra"][table]["any"].add(end_origin)
                data["intra_any"]["any"].add(end_origin)
                for r1, r2 in itertools.combinations(results, 2):
                    for key in r1.keys():
                        if r2.get(key) != r1.get(key):
                            data["intra"][table][key].add(end_origin)
                            data["intra_any"][key].add(end_origin)
                            mechanism_debug["intra"][table][key][end_origin].add(cluster)
                            if key in csp_keys:
                                data["intra_any"]['CSP'].add(end_origin)
                                data["intra"][table]['CSP'].add(end_origin)
                                mechanism_debug["intra"][table]['CSP'][end_origin].add(cluster)

            cur.execute(f"""
                        SELECT end_origin,
                        test,
                        array_agg(DISTINCT results->'HSTS')
                        FROM {table} 
                        -- WHERE cluster IS NOT NULL
                        GROUP BY 1, 2
                        HAVING count(1) >= 3
                        AND array_length(array_agg(DISTINCT results->'HSTS'), 1) > 1;
                        """)
            for end_origin, test, results in cur.fetchall():
                data["intra_any"]['HSTS no cluster'].add(end_origin)
                data["intra"][table]["HSTS no cluster"].add(end_origin)

            for mechanism in mechanisms:
                cur.execute(f"""
                SELECT
                end_origin,
                cluster
                FROM (
                SELECT test, cluster FROM {table} GROUP BY test, cluster HAVING count(1) >= 3 
                AND array_length(ARRAY_AGG(DISTINCT results->>'{mechanism}'), 1) = 1
                ) AS foo
                LEFT JOIN {table} USING (test, cluster)
                GROUP BY 1, 2
                HAVING 
                array_length(array_agg(DISTINCT results->>'{mechanism}'), 1) > 1;
                """)

                for end_origin, cluster in cur.fetchall():
                    data["inter_any"][mechanism].add(end_origin)
                    data["inter_any"]["any"].add(end_origin)
                    data["inter"][table]["any"].add(end_origin)
                    data["inter"][table][mechanism].add(end_origin)
                    mechanism_debug["inter"][table][mechanism][end_origin].add(cluster)
                    if mechanism in csp_keys:
                        data["inter_any"]['CSP'].add(end_origin)
                        data["inter"][table]['CSP'].add(end_origin)
                        mechanism_debug["inter"][table]['CSP'][end_origin].add(cluster)

            cur.execute(f"""
                    SELECT
                    DISTINCT end_origin
                    FROM (
                    SELECT test FROM {table} GROUP BY test HAVING count(1) >= 3 
                    AND array_length(ARRAY_AGG(DISTINCT results->>'HSTS'), 1) = 1
                    ) AS foo
                    LEFT JOIN {table} USING (test)
                    GROUP BY 1
                    HAVING 
                    array_length(array_agg(DISTINCT results->>'HSTS'), 1) > 1;
                    """)

            for end_origin, in cur.fetchall():
                data["inter_any"]['HSTS no cluster'].add(end_origin)
                # data["inter_any"]["any"].add(end_origin)
                # data["inter"][table]["any"].add(end_origin)
                data["inter"][table]["HSTS no cluster"].add(end_origin)

        with open(f"{DATA_DIRECTORY}/result_{DB_NAME}.json", "w") as fh:
            json.dump(data, fh, cls=DDEncoder, indent=True)

        with open(f"{DATA_DIRECTORY}/cookie_{DB_NAME}.json", "w") as fh:
            json.dump(cookie_debug, fh, cls=DDEncoder, indent=True)

        with open(f"{DATA_DIRECTORY}/mechanism_{DB_NAME}.json", "w") as fh:
            json.dump(mechanism_debug, fh, cls=DDEncoder, indent=True)
    else:
        data = json.load(open(f"{DATA_DIRECTORY}/result_{DB_NAME}.json"))

    data = recursive_filter(data, sites)

    for table in tables:
        data["usage"][table]['cookie'] = data["usage"][table]['cookie secure'] | \
                                         data["usage"][table]['cookie httponly'] | \
                                         data["usage"][table]['cookie samesite']

    def filter_with_other(data, other_data):
        new_data = defaultdict(set)
        for key, values in data.items():
            if isinstance(values, set) or isinstance(values, list):
                new_data[key] = set(values)
                new_data[key] &= set([extract(x).registered_domain for x in other_data.get(key, [])])
            else:
                new_data[key] = filter_with_other(values, other_data[key])
        return new_data

    prettify_mechanism = {
        "CSP": "Content Security Policy",
        "XSS": "\\emph{- for XSS mitigation}",
        "TLS": "\\emph{- for TLS enforcement}",
        "FA": "\\emph{- for framing control}",
        "XFO": "\midrule\nX-Frame-Options",
        "cookie": "\midrule\nCookie Security",
        "cookie secure": "\\emph{- Secure flag}",
        "cookie samesite": "\\emph{- SameSite flag}",
        "cookie httponly": "\\emph{- HTTPOnly flag}",
        "HSTS": "\midrule\nStrict-Transport-Security",
        "HSTS no cluster": "\\emph{w/o content check*}"
    }

    def funky_len(element):
        if len(element) == 0:
            return "-"
        else:
            return f"{len(element):,}"

    all_usage = set()

    for mechanism in ['CSP'] + mechanisms + ['HSTS no cluster'] + cookie_mech:
        print(f"{prettify_mechanism[mechanism]} &", end="\t")
        usage = set()
        for table in tables:
            usage.update(data["usage"][table][mechanism])
            all_usage.update(data["usage"][table][mechanism])
        print(f" {funky_len(usage)} &", end="\t")
        for table in tables:
            print(f" {funky_len(data['intra'][table][mechanism])} &", end="\t")
        print(f" {funky_len(data['intra_any'][mechanism])} &", end="\t")
        mech_any = set()
        for table in tables:
            print(f" {funky_len(data['inter'][table][mechanism])} &", end="\t")
            mech_any.update(data['inter'][table][mechanism])
        print(f" {funky_len(mech_any)} &", end="\t")
        mech_any = set()
        for table in tables:
            print(f" {funky_len(data['inter'][table][mechanism] - data['intra'][table][mechanism])} &", end="\t")
            mech_any.update(data['inter'][table][mechanism] - data['intra'][table][mechanism])
        print(f" {funky_len(mech_any)} \\\\", end="\n")

    for table in tables:
        data['inter'][table]['HSTS no cluster'] = set()
        data['intra'][table]['HSTS no cluster'] = set()
        data['inter_any']['HSTS no cluster'] = set()
        data['intra_any']['HSTS no cluster'] = set()

    print(f"\\midrule\nAny & {funky_len(all_usage)} & ", end="")

    all_sites = defaultdict(lambda: defaultdict(set))
    for table in tables:
        tmp = functools.reduce(lambda x, y: x | y, data['intra'][table].values(), set())
        all_sites["intra"][table] = tmp
        tmp = functools.reduce(lambda x, y: x | y, data['inter'][table].values(), set())
        all_sites["inter"][table] = tmp

        all_sites["inter"]["any"].update(all_sites["inter"][table])
        all_sites["intra"]["any"].update(all_sites["intra"][table])

    for table in tables:
        print(f" {funky_len(all_sites['intra'][table])} &", end="\t")
    print(f" {funky_len(all_sites['intra']['any'])} &", end="\t")
    for table in tables:
        print(f" {funky_len(all_sites['inter'][table])} &", end="\t")
    print(f" {funky_len(all_sites['inter']['any'])} &", end="\t")
    for table in tables:
        print(f" {funky_len(all_sites['inter'][table] - all_sites['intra'][table])} &", end="\t")
    print(f" {funky_len(all_sites['inter']['any'] - all_sites['intra']['any'])} \\\\\n", end="")

    print(funky_len(all_sites['intra']['any'] | all_sites['inter']['any']))

    return

    for table in tables:
        all_sites = functools.reduce(lambda x, y: x | y, data['intra'][table].values(), set())
        print(f" {len(all_sites)} & ", end="")
    all_sites_intra = functools.reduce(lambda x, y: x | y, data['intra_any'].values(), set())
    print(f" {len(all_sites_intra)} & ", end="")
    for table in tables:
        all_sites = functools.reduce(lambda x, y: x | y, data['inter'][table].values(), set())
        print(f" {len(all_sites)} & ", end="")
    all_sites_inter = functools.reduce(lambda x, y: x | y, data['inter_any'].values(), set())
    print(f" {len(all_sites_inter - all_sites_intra)} \\\\")
    for table in tables:
        all_sites = functools.reduce(lambda x, y: x | y, data['inter'][table].values(), set())
        print(f" {len(all_sites)} & ", end="")
    all_sites_inter = functools.reduce(lambda x, y: x | y, data['inter_any'].values(), set())
    print(f" {len(all_sites_inter - all_sites_intra)} \\\\")

    all_sites_inter = functools.reduce(lambda x, y: x | y, data['inter_any'].values(), set())
    all_sites_intra = functools.reduce(lambda x, y: x | y, data['intra_any'].values(), set())

    print(len(all_sites_inter | all_sites_intra))

    with open(f"{DATA_DIRECTORY}/result_{DB_NAME}_sites.json", "w") as fh:
        json.dump(data, fh, cls=DDEncoder, indent=True)


if __name__ == '__main__':
    main()
