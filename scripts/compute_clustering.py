from similarity import similarity, build_full_cache
from collections import defaultdict
from data import get_db_cursor

SIMILARITY_THRESHOLD = 0.8


def cluster():
    cur = get_db_cursor()
    cur_sim = get_db_cursor()
    for table in ['client', 'browser', 'vpn', 'onion']:
        build_full_cache(table)
        print(f'Start clustering for {table}...')
        cur.execute(f"""
            SELECT domain, h FROM (
                SELECT domain, array_agg(DISTINCT file_name_hash) AS h FROM {table} WHERE file_name_hash IN (
                    SELECT file_name_hash FROM script_stats
                ) GROUP BY 1
            ) AS foo WHERE array_length(h, 1) > 1;
        """)
        raw_data = cur.fetchall()
        print(f'Got {len(raw_data)} domains!')
        similar = set()
        multiple = set()
        for domain, hashes in raw_data:
            clusters = defaultdict(set)
            for h in hashes:
                if len(clusters.keys()) == 0:
                    clusters[1] = {h}
                    continue
                determined_cluster = None
                for c, entries in clusters.items():
                    for e in entries:
                        if similarity(cur_sim, h, e) < SIMILARITY_THRESHOLD:
                            break
                    else:
                        # No Break => Found matching cluster
                        determined_cluster = c
                        break
                if determined_cluster is None:
                    clusters[max(clusters.keys()) + 1] = {h}
                else:
                    clusters[determined_cluster].add(h)
            if len(clusters.keys()) == 1:
                similar.add(domain)
            else:
                multiple.add(domain)
            for cluster_id, entries in clusters.items():
                hash_list = str(entries).replace('{', '(').replace('}', ')')
                cur.execute(f"UPDATE {table} SET cluster = %s WHERE file_name_hash IN {hash_list};", (cluster_id,))
        cur.execute(f"""
            SELECT domain, h[1] FROM (
                SELECT domain, array_agg(DISTINCT file_name_hash) AS h FROM {table} WHERE file_name_hash IN (
                    SELECT file_name_hash FROM script_stats
                ) GROUP BY 1
            ) AS foo WHERE array_length(h, 1) = 1;
        """)
        unique_responses = cur.fetchall()
        for _, file_hash in unique_responses:
            cur.execute(f"UPDATE {table} SET cluster = 1 WHERE file_name_hash = %s;", (file_hash,))

        print(f'Only Unique Responses: {len(unique_responses)}')
        print(f'Only Similar Responses: {len(similar)}')
        print(f'Multiple Different Responses: {len(multiple)}')


if __name__ == '__main__':
    cluster()
