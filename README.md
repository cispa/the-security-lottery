# The Security Lottery
This repository contains the crawling and analytics scripts used for the paper "The Security Lottery: Measuring Client-Side Web Security Inconsistencies" published at the 31st USENIX Security Symposium 2022.

## Setup
Before starting the crawlers, you have to set up a PostgreSQL database.
Afterwards the following Environment variables are required such that the script will work on this database.
Either you set the following entries as environment variables on your system or update the corresponding entries in the [docker-compose.yaml](docker-compose.yaml) file
```python
DB_HOST=<IP/Hostname of you PostgreSQL DB>
DB_USER=<User of the PostgreSQL DB>
DB_PWD=<Password for DB_USER>
DB_NAME=<Name of the Database>
DB_PORT=<Port of the Database>
```
Make sure that you have created the Database on the PostgreSQL server and that the User has full access to this Database.

Since the VPN crawler depends on the VPN provider [hidemyass.com](https://www.hidemyass.com/), you need valid credentials for the VPN crawl.
Therefore xou have to set the following environment variables on your system or update the corresponding entries in the [docker-compose.yaml](docker-compose.yaml) file
```python
HMA_USERNAME=<Your Username for the HMA-VPN service>
HMA_PASSWORD=<Password for the HMA-VPN service>
```

**Optional:** In order to fasten the crawling process you can set the following environment variables on your system or update the corresponding entries in the [docker-compose.yaml](docker-compose.yaml) file, such that the crawling is done in multiple processes.
```python
NUM_PROCESSES=<Number of Processes>
NUM_DOMAINS=<Number of domains to be crawled>
SKIP_SETUP=<set to 1 to skip the DB setup>
```
Also you can specify which of the crawls you want to perform by change the corresponding `DO_<BROWSER|LANGUAGE|ONION|VPN>` values to 1=enabled or 0=disbaled.

## The docker way:
Build and start the docker by using the `docker-compose up` in the root directory of this repo.
The docker will now automatically prepare, crawl, and analyse the dataset.

## The non-docker way:
First make sure to run [install.sh](install.sh) before continuing, such that all necessary dependencies are installed on your system.

Either use [start.sh](scripts/start.sh) to run all the steps below automatically or manually proceed with the following steps.

### Step 0: Create the HMA credential file:
Create (or change) [VPN/hmauser.pass](scripts/VPN/hmauser.pass) such that it contains the following content:
```
<Your Username for the HMA-VPN service>
<Password for the HMA-VPN service>
```

### Step 1: Collecting crawlable https domains
As a first step, you have to collect the set of domains that should be crawled by the different crawlers.
```shell
python3 get_https_domains.py <TRANCO_FILE>
```

### Step 2: Initialize the database
Run the following script, which the database tables have to be created.
```shell
python3 crawl.py setup && python3 crawl.py add_tests
```
to create the database tables and add the exact test cases to be crawled.

### Step 3: Start the crawlers
Start the crawlers one by one by calling [crawl.py](scripts/crawl.py) with the respective command line parameter:
```shell
python3 crawl.py [browser|client|onion|vpn]
```
**Note:** Depending on the amount of URLs this might take a while (especially for onion/vpn).

### Step 4: Compute Clustering
Start the [compute_clustering.py](scripts/compute_clustering.py) script:
```shell
python3 compute_clustering.py
```
**Note:** This step might take a while.

### Step 5: Analyse the gathered data:
Start the [sql_table.py](scripts/sql_table.py) script:
```shell
python3 sql_table.py
```
Enjoy the output!
