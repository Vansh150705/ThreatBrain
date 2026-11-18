# tb-collector

A standalone daemon that watches a log file, detects attacks, and posts
normalized security events to a ThreatBrain backend's `/api/v1/ingest/event`.

It runs on **any host that writes logs** (a Linux server, Kali, an appliance) —
no code changes to the protected system. The first source adapter detects **SSH
brute-force** from `/var/log/auth.log`.

## How it works

```
/var/log/auth.log ──tail──▶ AuthLogSSHBruteForce ──Detection──▶ normalizer
                                                                     │
                                                          POST /ingest/event
                                                                     ▼
                                                          ThreatBrain pipeline
```

Per source IP, the adapter keeps a sliding window of failed logins; when it sees
`threshold` failures within `window_seconds`, it emits **one** event and then
stays quiet for `cooldown_seconds` so a single attack is a single event, not a
flood.

## Install

```bash
cd collector
python -m venv venv
./venv/bin/python -m pip install -r requirements.txt      # Windows: venv/Scripts/python.exe
```

## Configure

```bash
cp collector.example.yaml collector.yaml
chmod 600 collector.yaml
# edit collector.yaml: base_url, api_key, collector_id, log_path
```

**Authentication.** Create an API key in the ThreatBrain console
(*Settings -> API keys*, scope `ingest`) and put it in `api_key`. A key can only send
events: it cannot read data, approve actions or call any other endpoint, and an admin
can revoke it instantly. Email/password login still works but stores a full user
password on the host; prefer keys.

## Run

```bash
./venv/bin/python -m tb_collector --config collector.yaml      # add -v for debug logs
```

You'll see `watching /var/log/auth.log`. When an attack trips the threshold it logs
`DETECTED brute_force (high) from <ip> -> posting` and a new threat appears in the console.

Reliability built in:

* **Log rotation / truncation** is detected; the file is reopened so no lines are lost.
* **Retries with backoff** on network errors, HTTP 429 and 5xx.
* **Disk spool**: if the backend is down, detections are queued in `spool_path`
  (`0600`, bounded) and replayed oldest-first when it returns. Events the server
  *rejects* (bad payload, wrong key scope) are logged and not retried.
* **Async ingest** (default): the backend answers `202` and runs the agent pipeline in the
  background so a slow LLM never stalls tailing.

## Run as a service (systemd)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tb-collector
sudo mkdir -p /opt/tb-collector
sudo cp -r tb_collector tb_common requirements.txt /opt/tb-collector/
sudo cp collector.yaml /opt/tb-collector/         # your real config
sudo chown root:tb-collector /opt/tb-collector/collector.yaml && sudo chmod 640 /opt/tb-collector/collector.yaml
sudo python3 -m venv /opt/tb-collector/venv
sudo /opt/tb-collector/venv/bin/pip install -r /opt/tb-collector/requirements.txt
sudo cp systemd/tb-collector.service /etc/systemd/system/
sudo systemctl enable --now tb-collector
sudo systemctl status tb-collector
```

## Test

```bash
./venv/bin/python -m pip install -r requirements-dev.txt
./venv/bin/python -m pytest -q
```

## Config reference

| Key | Default | Meaning |
|-----|---------|---------|
| `base_url` | — | ThreatBrain API base, ending in `/api/v1`. |
| `api_key` | — | Scoped `ingest` API key (recommended). |
| `email` / `password` | — | Alternative: an analyst account. One of the two methods is required. |
| `collector_id` | — | Free label for this collector instance. |
| `asset_name` | `null` | Optional asset name attached to events. |
| `log_path` / `log_paths` | — | Log file(s) to tail (e.g. `/var/log/auth.log`). |
| `threshold` | `10` | Failed logins per window to trigger a detection. |
| `window_seconds` | `60` | Sliding-window length. |
| `cooldown_seconds` | `300` | Quiet period per IP after a detection. |
| `async_ingest` | `true` | Return immediately; backend runs the pipeline in the background. |
| `spool_path` | `tb-collector-spool.jsonl` | Where undeliverable detections are queued. |
| `spool_max_items` | `2000` | Spool bound; oldest items are dropped first. |

## tb-executor (human-approved response)

`tb_executor` is the only component that changes anything on a host. It polls for
actions an administrator has **approved** in the console and carries them out behind
guards (see `executor.example.yaml`). It starts in `dry_run: true`.

```bash
cp executor.example.yaml executor.yaml && chmod 600 executor.yaml   # use an `executor`-scope API key
./venv/bin/python -m tb_executor --config executor.yaml
```

Guards: never loopback/link-local/multicast/private (unless `allow_private`), never
allow-listed IPs or protected accounts, range blocks no broader than /16, option-like
usernames refused, every action must be listed in `enabled_actions`, and each outcome is
reported back and written to the append-only audit trail. IPv6 sources use `ip6tables`.
