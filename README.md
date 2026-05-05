# ============================================================
# FILE: README.md
# ============================================================
# wazuh-exporter
 
A custom Prometheus exporter that bridges [Wazuh](https://wazuh.com) alert
data (stored in OpenSearch) into Prometheus, with GeoIP enrichment and a
multi-window architecture designed to power a "Fleet Command Center" Grafana
dashboard.
 
## Features
 
- **Multi-window aggregation** — 5 time windows (15m, 1h, 6h, 24h, 7d),
  all exposed via a single `window` label per metric
- **GeoIP enrichment** — source IPs enriched with lat/lon and country via
  `ipinfo.io`, with Wazuh's own GeoLocation field as fallback
- **Thread-safe in-memory cache** — avoids re-querying known IPs
- **Custom Collector pattern** — metrics are rebuilt fresh on every scrape;
  no stale values from previous polls
- **Grafana variable sync** — `wazuh_window_select` metric allows the
  Grafana time picker to auto-select the correct data window
 
## Metrics
 
| Metric | Labels | Description |
|--------|--------|-------------|
| `wazuh_alerts_total` | `window` | Total alerts in window |
| `wazuh_critical_alerts_count` | `window` | Alerts with rule level ≥ 7 |
| `wazuh_ip_geo` | `ip, country, lat, lon, window` | Alert count + geo per source IP |
| `wazuh_country_count` | `country, code, window` | Alerts by country |
| `wazuh_agent_alerts` | `agent, window` | Alerts per agent |
| `wazuh_threat_level` | `level, window` | Alerts by rule level |
| `wazuh_window_select` | `window` | Grafana variable sync helper |
| `wazuh_window_thresholds` | `window, seconds` | Window upper bounds reference |
 
## Requirements
 
- Python 3.8+
- A running Wazuh Indexer (OpenSearch) instance
- Prometheus scraping the exporter's port
 
```bash
pip install -r requirements.txt
```
 
## Configuration
 
Copy `.env.example` to `.env` and populate all values:
 
```bash
cp .env.example .env
chmod 600 .env
```
 
| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_MANAGER_IP` | `127.0.0.1` | IP of the Wazuh Indexer (OpenSearch) node |
| `INDEXER_USER` | `admin` | OpenSearch username |
| `INDEXER_PASS` | *(required)* | OpenSearch password — **do not hardcode** |
| `INDEXER_PORT` | `9200` | OpenSearch port |
| `EXPORTER_PORT` | `9101` | Port the exporter exposes metrics on |
| `POLL_INTERVAL` | `60` | Seconds between OpenSearch polls |
 
## Running
 
### Direct
 
```bash
source .env  # or: export $(cat .env | xargs)
python3 wazuh_exporter.py
```
 
### As a systemd service
 
```bash
sudo cp wazuh_exporter.py /opt/wazuh-exporter/
sudo cp .env /opt/wazuh-exporter/.env
sudo chmod 600 /opt/wazuh-exporter/.env
sudo cp wazuh-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-exporter
sudo systemctl status wazuh-exporter
```
 
## Prometheus Scrape Config
 
```yaml
- job_name: 'wazuh'
  static_configs:
    - targets: ['<wazuh-manager-ip>:9101']
      labels:
        instance: 'wazuh-manager'
```
 
## Grafana Variable Setup
 
To auto-select the correct window based on Grafana's time picker, create a
dashboard variable with:
 
- **Type:** Query
- **Data source:** Prometheus
- **Query:**
  ```
  label_values(topk(1, -(wazuh_window_select >= $__range_s)), window)
  ```
- **Regex:** `[0-9]+(.*)`
 
This strips the ordinal prefix (`1-15m` → `15m`) so `$window` resolves to
clean values like `15m`, `1h`, `6h`, `24h`, `7d`.
 
Use `{window="$window"}` as a label filter in every panel query.
 
## Notes
 
- **GeoIP rate limits:** `ipinfo.io` has a free-tier request limit. For
  environments with many unique source IPs, consider replacing the API call
  with a locally-installed
  [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
  database and the `geoip2` Python library.
- **SSL verification:** OpenSearch typically uses a self-signed cert in
  homelab deployments. The exporter disables SSL verification (`verify=False`)
  with `urllib3` warnings suppressed. Enable verification with a real cert
  in production environments.
 
## Part of the Koshin-HL Homelab Portfolio
 
More context in the
[Telemetry Bridge case study](https://github.com/Koshin-HL).
 
 
---
