# pyDHT

**pyDHT** is a lightweight Python application for discovering and indexing torrents through the public BitTorrent Mainline DHT.

It participates as a standard DHT client, discovers torrent-related DHT keys, locates peers, retrieves torrent metadata using the BitTorrent peer protocol, validates the metadata, and stores confirmed torrent information locally.

**Owner:** Denis Laskov  
**Year:** 2026  
**Current version:** v0.1  
**Language:** Python 3.12+  
**Primary network:** BitTorrent Mainline DHT  
**Storage:** SQLite + JSONL

---

## 1. What it does

pyDHT participates in the public BitTorrent Mainline DHT and supports:

```text
BEP-5   -> DHT / KRPC / routing
BEP-9   -> BitTorrent metadata exchange
BEP-10  -> BitTorrent extension protocol
BEP-43  -> DHT read-only mode
BEP-51  -> DHT infohash sampling
BEP-44  -> protocol observation
```

The main discovery flow is:

```text
Mainline DHT
     ↓
discover DHT key / infohash
     ↓
get_peers
     ↓
locate BitTorrent peers
     ↓
TCP peer connection
     ↓
BitTorrent handshake
     ↓
BEP-10 extension handshake
     ↓
BEP-9 metadata exchange
     ↓
validate exact metadata bytes
     ↓
extract torrent name and files
     ↓
SQLite catalogue
```

pyDHT supports:

- Mainline DHT bootstrap
- BEP-5 KRPC
- standard DHT routing
- `ping`
- `find_node`
- `get_peers`
- incoming `announce_peer`
- passive torrent discovery
- iterative `get_peers` searches
- optional BEP-51 `sample_infohashes`
- BitTorrent TCP peer connections
- BitTorrent handshake
- BEP-10 extension negotiation
- BEP-9 metadata retrieval
- exact-byte metadata validation
- torrent name and file indexing
- durable torrent discovery/retry state
- keyword monitoring
- optional Telegram notifications
- JSONL DHT/network evidence
- routing-table restart persistence

The configured KRPC client/version identifier is:

```text
qB7K
```

It is sent as the top-level KRPC `v` field in outbound messages.

Incoming BEP-51 `sample_infohashes` responses advertise an interval of:

```text
300 seconds
```

### Torrent identity

Raw 20-byte keys observed in DHT are represented as:

```text
dht20:<40 lowercase hexadecimal characters>
```

Example:

```text
dht20:0123456789abcdef0123456789abcdef01234567
```

A DHT key is not treated as a confirmed torrent identity until metadata has been retrieved and validated.

Confirmed BitTorrent v1 torrents use:

```text
btih:<40 lowercase hexadecimal characters>
```

Example:

```text
btih:0123456789abcdef0123456789abcdef01234567
```

### What pyDHT does not do

pyDHT does **not**:

```text
download torrent payload files
serve torrent payload files
seed torrents
advertise locally hosted torrents
announce pyDHT-owned torrents
scrape trackers
crawl PEX
act as an inbound torrent honeypot
provide a web UI
provide a REST API
perform automatic NAT traversal
```

Only torrent metadata is retrieved from peers. Torrent payload content is never downloaded.

---

## 2. Prerequisites

Required:

- **Python 3.12 or newer**
- IPv4 Internet connectivity
- outbound UDP connectivity to the BitTorrent Mainline DHT
- outbound TCP connectivity to BitTorrent peers
- local write access for the `db/` directory

pyDHT uses SQLite for its torrent catalogue and does not require a separate database server.

When running:

```python
DHT_READ_ONLY = False
```

the configured DHT UDP port should normally be reachable from the Internet so pyDHT can participate as a normal DHT node.

When running:

```python
DHT_READ_ONLY = True
```

pyDHT operates using BEP-43 read-only behavior.

Telegram access is required only when Telegram notifications are enabled.

---

## 3. How to install

### 1. Download or clone pyDHT

Download the current project and enter its directory:

```bash
cd pyDHT/
```

### 2. Verify Python

```bash
python3 --version
```

The version must be Python 3.12 or newer.

### 3. Configure pyDHT

All application configuration is located in:

```text
config.py
```

Review the configuration before the first run.

### 4. Start pyDHT

```bash
python3 main.py
```

`main.py` is the application entry point.

On startup pyDHT initializes its local storage, restores available DHT routing state, opens the configured UDP listener, bootstraps into the Mainline DHT when necessary, and starts torrent discovery.

The runtime database and DHT data files under:

```text
db/
```

are created when required.

---

## 4. How to change default configuration

All user-adjustable configuration is stored in:

```text
config.py
```

There is no separate YAML, JSON, INI, `.env`, or keyword configuration file.

Example:

```python
DHT_CLIENT_VERSION = "qB7K"

DHT_READ_ONLY = False

DHT_BEP51_ENABLED = True
DHT_BEP51_RESPONSE_INTERVAL = 300

ALLOW_NON_GLOBAL_ENDPOINTS = False
```

The DHT client version must remain exactly four ASCII bytes.

Other configuration groups control:

```text
DHT UDP port
bootstrap nodes
DHT request rate
maximum pending KRPC requests
routing behavior
BEP-51 discovery
torrent worker count
peer connection limits
metadata limits
timeouts
retry behavior
SQLite limits
JSONL limits
keyword monitoring
Telegram notifications
logging/debugging
```

Secrets such as a Telegram Bot token may originate from environment variables but are read only through `config.py`.

Example:

```python
TELEGRAM_BOT_TOKEN = os.environ.get(
    "PYDHT_TELEGRAM_BOT_TOKEN",
    "",
)
```

Restart pyDHT after changing the configuration.

---

## 5. How to use the output files

The main runtime data directory is:

```text
db/
```

### SQLite torrent catalogue

```text
db/pydht.sqlite3
```

SQLite contains torrent-centric information only.

Main tables:

```text
torrent_candidates
torrents
files
notifications
```

### `torrent_candidates`

Stores durable discovery and retry state for DHT keys before a confirmed torrent identity necessarily exists.

Typical information includes:

```text
dht_key
state
first_seen
last_seen
attempts
last_attempt
next_attempt_at
last_error
torrent_uid
```

It does not contain DHT nodes, peer endpoints, routing information, or KRPC telemetry.

### `torrents`

Contains confirmed and validated torrents.

Typical information includes:

```text
torrent_uid
name
total_size
file_count
piece_length
metadata_size
raw_info
first_seen
last_seen
status
```

### `files`

Contains the files belonging to each confirmed torrent:

```text
torrent_uid
file_index
path
size
```

### `notifications`

Contains durable keyword-match and Telegram notification state.

---

### DHT/network JSONL

```text
db/dht_network.jsonl
```

This is the append-oriented DHT and network technical evidence stream.

It can contain structured observations for:

```text
KRPC exchanges
DHT nodes
discovered peers
torrent discovery
routing events
announce_peer
BEP-51
BitTorrent peer sessions
BEP-10
BEP-9
BEP-44 observations
protocol errors
timings
remote client/version information
```

Each line is one complete JSON object.

Example:

```bash
head -n 10 db/dht_network.jsonl
```

or:

```bash
jq . db/dht_network.jsonl
```

The JSONL stream is technical network evidence and is separate from the torrent catalogue stored in SQLite.

pyDHT is not a packet-capture system and JSONL should not be treated as lossless PCAP-equivalent evidence.

---

### DHT routing snapshot

```text
db/dht_routing.jsonl
```

This file stores restart state for the DHT routing table.

Unlike `dht_network.jsonl`, it is not an append-only event log.

It is periodically written as an atomic routing snapshot and may contain:

```text
local DHT node identity
snapshot metadata
known routing contacts
routing state
```

Restored remote contacts are revalidated after restart before being treated as healthy routing nodes.

---

## 6. Project structure

```text
pyDHT/
├── main.py
├── config.py
│
├── includes/
│   ├── __init__.py
│   ├── bencode.py
│   ├── dht.py
│   ├── peer.py
│   ├── indexer.py
│   ├── storage.py
│   ├── monitoring.py
│   ├── communications.py
│   └── debug.py
│
├── db/
│   ├── pydht.sqlite3
│   ├── dht_network.jsonl
│   └── dht_routing.jsonl
│
├── tests/
│   ├── test_bencode.py
│   ├── test_dht.py
│   ├── test_peer.py
│   ├── test_routing.py
│   ├── test_metadata.py
│   ├── test_storage.py
│   └── test_monitoring.py
│
├── README.md
└── LICENSE
```

The runtime architecture is intentionally simple:

```text
1 Python process
1 asyncio event loop
1 SQLite worker thread
1 JSONL writer thread
fixed torrent workers
```

`main.py` is the only application entry point.

`config.py` is the only application configuration source.

---

## 7. Next steps

Potential future development includes:

1. Active IPv6 DHT support.
2. BitTorrent v2 / BEP-52 torrent indexing.
3. uTP peer metadata transport.
4. Full optional BEP-42 validation and node-ID generation.
5. Additional torrent catalogue analysis and research tools.

---

## 8. Credits

**pyDHT** was created and is maintained by **Denis Laskov**.

Copyright © 2026 Denis Laskov.