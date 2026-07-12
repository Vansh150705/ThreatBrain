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
chmod 600 collector.yaml          # it holds your ThreatBrain password
# edit collector.yaml: base_url, email, password, collector_id, log_path
```

The account in `collector.yaml` must have the `analyst` role or higher in
ThreatBrain (an `owner` works). `base_url` points at your backend, e.g.
`https://vansh150705-threatbrain-backend.hf.space/api/v1`.

## Run

```bash
./venv/bin/python -m tb_collector --config collector.yaml
```

You'll see `watching /var/log/auth.log`. When an attack trips the threshold it
prints `DETECTED brute-force from <ip> -> posting` and a new threat appears in
your ThreatBrain dashboard.

## Run as a service (systemd)

```bash
sudo mkdir -p /opt/tb-collector
sudo cp -r tb_collector requirements.txt /opt/tb-collector/
sudo cp collector.yaml /opt/tb-collector/         # your real config
sudo python3 -m venv /opt/tb-collector/venv
sudo /opt/tb-collector/venv/bin/pip install -r /opt/tb-collector/requirements.txt
sudo cp systemd/tb-collector.service /etc/systemd/system/
sudo systemctl enable --now tb-collector
sudo systemctl status tb-collector
```

## Test

```bash
./venv/bin/python -m pytest -q
```

## Config reference

| Key | Default | Meaning |
|-----|---------|---------|
| `base_url` | — | ThreatBrain API base, ending in `/api/v1`. |
| `email` / `password` | — | A ThreatBrain account (analyst+). |
| `collector_id` | — | Free label for this collector instance. |
| `asset_name` | `null` | Optional asset name attached to events. |
| `log_path` | — | Log file to tail (e.g. `/var/log/auth.log`). |
| `threshold` | `10` | Failed logins per window to trigger a detection. |
| `window_seconds` | `60` | Sliding-window length. |
| `cooldown_seconds` | `300` | Quiet period per IP after a detection. |
