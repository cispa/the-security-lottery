from collections import defaultdict
from urllib.parse import urljoin
from bs4 import BeautifulSoup

import tldextract
import os.path
import json
import gzip

DATA_DIRECTORY = '/data'


def get_sub_tree_stats(element, depth=0):
    if element is None:
        return None
    if depth > 4:
        return None
    # [('body', [('h1', None), ('div', [...]))]
    if len(list(element.children)) == 0:
        return None
    children = list()
    for child in element.children:
        if child.name is not None:
            children.append((child.name, get_sub_tree_stats(child, depth + 1)))
    if len(children) == 0:
        return None
    return children


def recursive_stats(filename):
    file_path = f"{DATA_DIRECTORY}/{filename[0]}/{filename[1]}/{filename}.html.gz"
    if not os.path.exists(file_path):
        raise Exception(f"File {filename} not found")
    soup = BeautifulSoup(gzip.open(file_path, 'r').read(), features="lxml")
    stats = get_sub_tree_stats(soup.find("html"))
    title = str(soup.find("title"))
    return stats, title


def get_stats(filename, url):
    file_path = f"{DATA_DIRECTORY}/{filename[0]}/{filename[1]}/{filename}.html.gz"
    if not os.path.exists(file_path):
        raise Exception(f"File {filename} not found")
    raw_data = gzip.open(file_path, 'r').read()
    soup = BeautifulSoup(raw_data, features="lxml")
    script_stats = defaultdict(int)
    for script in soup.find_all("script"):
        if script.get("src"):
            script_stats[tldextract.extract(urljoin(url, script.get("src"))).registered_domain] += 1
        else:
            script_stats["inline"] += 1
    return len(raw_data), script_stats


def file_worker(relevant_part_of_file):
    try:
        file_bytes, stats = get_stats(relevant_part_of_file, 'https://fakedomain.com')
        html_stats, title = recursive_stats(relevant_part_of_file)
        return relevant_part_of_file, json.dumps(dict(stats)), json.dumps(html_stats), title, file_bytes
    except Exception as e:
        print(relevant_part_of_file)
        print(e)
    return None
