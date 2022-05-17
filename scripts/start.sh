#!/bin/bash
set -e

if [[ -z "${DO_VPN}" ]]; then
  echo "DO_VPN is not set. Abort!"
  exit -1;
else
  if [ $DO_VPN = 1 ]; then
    if [[ -z "${HMA_USERNAME}" ]]; then
      echo "HMA_USERNAME is not set, although DO_VPN is set to 1. Abort!"
      exit -1;
    else
      echo "${HMA_USERNAME}" > /secLot/VPN/hmauser.pass;
    fi

    if [[ -z "${HMA_PASSWORD}" ]]; then
      echo "HMA_PASSWORD is not set, although DO_VPN is set to 1. Abort!"
      exit -1;
    else
      echo "${HMA_PASSWORD}">> /secLot/VPN/hmauser.pass;
    fi
  fi
fi

if [[ -z "${SKIP_SETUP}" ]] || [ $SKIP_SETUP != '1' ]; then
  echo "Collecting crawlable HTTPS domains ..."
  python3 get_https_domains.py XVWN_20220101.csv
  echo "Done HTTPS collection."
  echo "Start Database setup..."
  python3 crawl.py setup && python3 crawl.py add_tests
  echo "Done Setup."
else
  echo "Skipping Setup because SKIP_SETUP == 1."
fi

echo "Start crawling process..."
if [[ -z "${DO_BROWSER}" ]]; then
  echo "DO_BROWSER is not set. Abort!"
  exit -1;
else
  if [ $DO_BROWSER = '1' ]; then
    echo "Crawling Different Browsers"
    python3 crawl.py browser
    echo "Finished Browsers"
  else
    echo "Skipping Browser crawl: DO_BROWSER != 1"
  fi
fi
if [[ -z "${DO_LANGUAGE}" ]]; then
  echo "DO_LANGUAGE is not set. Abort!"
  exit -1;
else
  if [ $DO_LANGUAGE = '1' ]; then
    echo "Crawling Different Language-Settings"
    python3 crawl.py client
    echo "Finished Language"
  else
    echo "Skipping Language crawl: DO_LANGUAGE != 1"
  fi
fi
if [[ -z "${DO_ONION}" ]]; then
  echo "DO_ONION is not set. Abort!"
  exit -1;
else
  if [ $DO_ONION = '1' ]; then
    echo "Crawling Different Onion Endnodes"
    python3 crawl.py onion
    echo "Finished Onion"
  else
    echo "Skipping Onion crawl: DO_ONION != 1"
  fi
fi
if [[ -z "${DO_VPN}" ]]; then
  echo "DO_VPN is not set. Abort!"
  exit -1;
else
  if [ $DO_VPN = '1' ]; then
    echo "Crawling Different VPN Servers"
    python3 crawl.py vpn
    echo "Finished VPN."
  else
    echo "Skipping VPN crawl: DO_VPN != 1"
  fi
fi
echo "Done Crawling."

echo "Computing content cluster..."
python3 compute_clustering.py
echo "Done clustering."

echo "Prepare Results..."
python3 sql_table.py
echo "Profit."

