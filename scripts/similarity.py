from psycopg2.extensions import cursor
from difflib import SequenceMatcher
from data import get_db_cursor

import json

SIMILARITY_CACHE = dict()
SCRIPT_STAT_CACHE = dict()


def jaccard_similarity(set_a: set, set_b: set) -> float:
    if len(set_a) == 0 and len(set_b) == 0:
        return 1.0
    intersection = len(list(set_a.intersection(set_b)))
    union = (len(set_a) + len(set_b)) - intersection
    return float(intersection) / union


def compute_similarity_score(a: dict, b: dict) -> float:
    global SIMILARITY_CACHE
    # Parameter Data format: {'bytes_size': bytes_size, 'script_stats': script_stats, title: 'title'}
    # Jaccard Similarity of the set of included script domains
    cache_key = json.dumps(a) + json.dumps(b)
    if cache_key in SIMILARITY_CACHE:
        return SIMILARITY_CACHE[cache_key]
    script_domains_similarity = jaccard_similarity(set(a['script_stats'].keys()), set(b['script_stats'].keys()))
    # Average similarity of the number of scripts from each domain that is in both sites
    script_number_similarity = list()
    for script_domain in set(a['script_stats'].keys()).intersection(set(b['script_stats'].keys())):
        num_dom_a = a['script_stats'][script_domain]
        num_dom_b = b['script_stats'][script_domain]
        script_number_similarity.append(min(num_dom_a, num_dom_b) / max(num_dom_a, num_dom_b))
    if len(script_number_similarity) == 0:
        script_number_similarity = 1.0
    else:
        script_number_similarity = sum(script_number_similarity) / len(script_number_similarity)
    # Similarity of the file/response size
    if max(a['bytes_size'], b['bytes_size']) == 0:
        size_similarity = 1.0
    else:
        size_similarity = min(a['bytes_size'], b['bytes_size']) / max(a['bytes_size'], b['bytes_size'])
    # Longest contiguous matching subsequence (LCS) ratio of the two titles
    title_similarity = SequenceMatcher(None, a['title'], b['title']).ratio()
    # Average over the individual computed similarity scores
    if min([script_number_similarity, script_domains_similarity, size_similarity, title_similarity]) < 0.75:
        return 0.0
    total = sum([script_number_similarity, script_domains_similarity, size_similarity, title_similarity])
    SIMILARITY_CACHE[cache_key] = total / 4.0
    return SIMILARITY_CACHE[cache_key]


def fetch_script_stats(cur: cursor, file_name_hash: str) -> dict:
    global SCRIPT_STAT_CACHE
    if file_name_hash in SCRIPT_STAT_CACHE:
        return SCRIPT_STAT_CACHE[file_name_hash]
    cur.execute('SELECT file_bytes, stats, title FROM script_stats WHERE file_name_hash=%s', (file_name_hash,))
    [size, stats, title] = cur.fetchone()
    SCRIPT_STAT_CACHE[file_name_hash] = dict(zip(['bytes_size', 'script_stats', 'title'], [size, stats, title]))
    return SCRIPT_STAT_CACHE[file_name_hash]


def similarity(cur: cursor, file_name_hash_a: str, file_name_hash_b: str) -> float:
    stats_a = fetch_script_stats(cur, file_name_hash_a)
    stats_b = fetch_script_stats(cur, file_name_hash_b)
    return compute_similarity_score(stats_a, stats_b)


def build_full_cache(table: str):
    global SCRIPT_STAT_CACHE
    cur = get_db_cursor()
    print('Building script_stats cache!')
    cur.execute(f'SELECT file_name_hash, file_bytes, stats, title FROM script_stats '
                f'WHERE file_name_hash in (SELECT DISTINCT file_name_hash FROM {table});')
    for file_name_hash, size, stats, title in cur.fetchall():
        SCRIPT_STAT_CACHE[file_name_hash] = dict(zip(['bytes_size', 'script_stats', 'title'], [size, stats, title]))
    print(f'Loaded {len(SCRIPT_STAT_CACHE.keys())} hashes!')
