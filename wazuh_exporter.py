"""
wazuh_exporter.py — Wazuh Prometheus Exporter
==============================================
Bridges Wazuh Indexer (OpenSearch) alert data into Prometheus with:
  - Multi-window aggregation (5 time windows, single label per metric)
  - GeoIP enrichment via ipinfo.io with Wazuh GeoLocation fallback
  - Thread-safe in-memory GeoIP cache
  - Grafana variable sync helper for auto-window selection
  - Custom Collector pattern (no stale metrics between scrapes)

Configuration is read from environment variables (see .env.example).
Do NOT hardcode credentials in this file.

Exposes metrics on :9101 (configurable via EXPORTER_PORT env var).
Polls OpenSearch every 60 seconds (configurable via POLL_INTERVAL).
"""

import os
import time
import ipaddress
import threading

import pycountry
import requests as http_requests
import urllib3
from prometheus_client import start_http_server, REGISTRY, Gauge
from prometheus_client.core import GaugeMetricFamily

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration — loaded from environment variables at startup
# ---------------------------------------------------------------------------

WAZUH_MANAGER_IP = os.environ.get("WAZUH_MANAGER_IP", "127.0.0.1")
INDEXER_USER     = os.environ.get("INDEXER_USER", "admin")
INDEXER_PASS     = os.environ.get("INDEXER_PASS", "")
INDEXER_PORT     = os.environ.get("INDEXER_PORT", "9200")
EXPORTER_PORT    = int(os.environ.get("EXPORTER_PORT", "9101"))
POLL_INTERVAL    = int(os.environ.get("POLL_INTERVAL", "60"))

BASE_URL = f"https://{WAZUH_MANAGER_IP}:{INDEXER_PORT}"

if not INDEXER_PASS:
    raise RuntimeError(
        "INDEXER_PASS environment variable is not set. "
        "Create a .env file from .env.example and populate it."
    )

# ---------------------------------------------------------------------------
# Time windows
# ---------------------------------------------------------------------------

WINDOWS = {
    "15m": "now-15m",
    "1h":  "now-1h",
    "6h":  "now-6h",
    "24h": "now-24h",
    "7d":  "now-7d",
}

# ---------------------------------------------------------------------------
# Static window helper metrics — registered once at startup
# ---------------------------------------------------------------------------

_WINDOW_THRESHOLDS = Gauge(
    "wazuh_window_thresholds",
    "Reference: available alert windows with their upper bound in seconds",
    ["window", "seconds"],
)

# Ordinal prefix keeps alphabetical sort == chronological sort in Grafana.
# Grafana variable query:
#   label_values(topk(1, -(wazuh_window_select >= $__range_s)), window)
# Regex [0-9]+(.*) strips the prefix so $window resolves to "15m", "1h", etc.
_WINDOW_SELECT = Gauge(
    "wazuh_window_select",
    "Grafana variable sync helper: upper bound seconds per window",
    ["window"],
)

# ---------------------------------------------------------------------------
# GeoIP cache and helpers
# ---------------------------------------------------------------------------

_geo_cache: dict = {}
_geo_lock  = threading.Lock()


def _code_to_name(alpha2: str) -> str:
    """Resolve ISO alpha-2 country code to full country name via pycountry."""
    try:
        obj = pycountry.countries.get(alpha_2=alpha2.upper())
        return obj.name if obj else alpha2
    except Exception:
        return alpha2


def _is_internal(ip: str) -> bool:
    """Return True for RFC1918, loopback, and any address that can't be parsed."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return True


def get_geo(ip: str):
    """
    Return (lat, lon, country_name, country_code) for an external IP.

    Resolution order:
      1. In-memory cache (thread-safe)
      2. ipinfo.io API (primary)
      3. Wazuh Indexer GeoLocation field (fallback)

    Internal/RFC1918 IPs are returned immediately as (None, None, "Internal", "INT")
    without a cache write or any external call.
    """
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]

    if _is_internal(ip):
        return (None, None, "Internal", "INT")

    # Primary: ipinfo.io
    try:
        res = http_requests.get(f"http://ipinfo.io/{ip}/json", timeout=5)
        if res.status_code == 200:
            data = res.json()
            parts = data.get("loc", "").split(",")
            lat   = float(parts[0]) if len(parts) == 2 else None
            lon   = float(parts[1]) if len(parts) == 2 else None
            code  = data.get("country", "")
            name  = _code_to_name(code) if code else "Unknown"
            result = (lat, lon, name, code)
            with _geo_lock:
                _geo_cache[ip] = result
            return result
    except Exception as e:
        print(f"[geo] ipinfo.io error for {ip}: {e}", flush=True)

    # Fallback: GeoLocation field stored in Wazuh Indexer documents
    try:
        url = f"{BASE_URL}/wazuh-alerts-*/_search?q=data.srcip:{ip}&size=1"
        res = http_requests.get(
            url, auth=(INDEXER_USER, INDEXER_PASS), verify=False, timeout=5
        )
        hits = res.json().get("hits", {}).get("hits", [])
        if hits:
            geo = hits[0].get("_source", {}).get("GeoLocation", {})
            raw_name = geo.get("country_name", "")
            loc  = geo.get("location", {})
            lat  = loc.get("lat")
            lon  = loc.get("lon")
            if raw_name:
                try:
                    obj  = pycountry.countries.search_fuzzy(raw_name)[0]
                    code = obj.alpha_2
                    name = obj.name
                except Exception:
                    code = raw_name[:2].upper()
                    name = raw_name
                result = (lat, lon, name, code)
                with _geo_lock:
                    _geo_cache[ip] = result
                return result
    except Exception as e:
        print(f"[geo] Indexer fallback error for {ip}: {e}", flush=True)

    result = (None, None, "Unknown", "??")
    with _geo_lock:
        _geo_cache[ip] = result
    return result


# ---------------------------------------------------------------------------
# OpenSearch queries
# ---------------------------------------------------------------------------

def _time_filter(window_key: str) -> dict:
    return {"range": {"@timestamp": {"gte": WINDOWS[window_key], "lte": "now"}}}


def _query_window(window_key: str) -> dict:
    """
    Query OpenSearch for a single time window.
    Returns total alert count, critical alert count, and aggregations for
    top source IPs, top agents, and threat levels.
    """
    tf   = _time_filter(window_key)
    auth = (INDEXER_USER, INDEXER_PASS)

    total = http_requests.post(
        f"{BASE_URL}/wazuh-alerts-*/_count",
        json={"query": {"bool": {"filter": [tf]}}},
        auth=auth, verify=False, timeout=10,
    ).json().get("count", 0)

    critical = http_requests.post(
        f"{BASE_URL}/wazuh-alerts-*/_count",
        json={"query": {"bool": {
            "filter": [tf, {"range": {"rule.level": {"gte": 7}}}]
        }}},
        auth=auth, verify=False, timeout=10,
    ).json().get("count", 0)

    aggs_res = http_requests.post(
        f"{BASE_URL}/wazuh-alerts-*/_search",
        json={
            "size": 0,
            "query": {"bool": {"filter": [tf]}},
            "aggs": {
                "top_ips":       {"terms": {"field": "data.srcip",  "size": 50}},
                "top_agents":    {"terms": {"field": "agent.name",   "size": 20}},
                "threat_levels": {"terms": {"field": "rule.level",   "size": 15}},
            },
        },
        auth=auth, verify=False, timeout=10,
    ).json().get("aggregations", {})

    return {"total": total, "critical": critical, "aggs": aggs_res}


# ---------------------------------------------------------------------------
# Custom Prometheus Collector
# ---------------------------------------------------------------------------

class WazuhCollector:
    """
    Custom Collector that rebuilds metric families from the latest snapshot
    on every Prometheus scrape.

    Why a custom Collector instead of static Gauge objects?
    Static Gauges persist between scrapes. An IP that appeared last poll but
    not this poll would linger as a stale metric until process restart.
    This Collector emits only what's in the current snapshot — no ghosts.
    """

    def __init__(self):
        self._lock     = threading.Lock()
        self._snapshot: dict = {}

    def update(self, window: str, data: dict):
        with self._lock:
            self._snapshot[window] = data

    def collect(self):
        with self._lock:
            snapshot = dict(self._snapshot)

        g_total    = GaugeMetricFamily(
            "wazuh_alerts_total", "Total alerts in window", labels=["window"])
        g_critical = GaugeMetricFamily(
            "wazuh_critical_alerts_count",
            "Critical alerts (rule level >= 7) in window", labels=["window"])
        g_ip_geo   = GaugeMetricFamily(
            "wazuh_ip_geo",
            "Alert count with geo data per source IP",
            labels=["ip", "country", "lat", "lon", "window"])
        g_country  = GaugeMetricFamily(
            "wazuh_country_count", "Alerts by country",
            labels=["country", "code", "window"])
        g_agent    = GaugeMetricFamily(
            "wazuh_agent_alerts", "Alerts per agent",
            labels=["agent", "window"])
        g_level    = GaugeMetricFamily(
            "wazuh_threat_level", "Alerts by threat level",
            labels=["level", "window"])

        for window, wdata in snapshot.items():
            g_total.add_metric([window], wdata["total"])
            g_critical.add_metric([window], wdata["critical"])

            for ip, (count, lat, lon, country, code) in wdata["ips"].items():
                if lat is not None and lon is not None:
                    g_ip_geo.add_metric(
                        [ip, country, str(lat), str(lon), window], count)

            for (country, code), count in wdata["countries"].items():
                g_country.add_metric([country, code, window], count)

            for agent, count in wdata["agents"].items():
                g_agent.add_metric([agent, window], count)

            for level, count in wdata["levels"].items():
                g_level.add_metric([str(level), window], count)

        yield g_total
        yield g_critical
        yield g_ip_geo
        yield g_country
        yield g_agent
        yield g_level


# ---------------------------------------------------------------------------
# Poll loop
# ---------------------------------------------------------------------------

_collector = WazuhCollector()
REGISTRY.register(_collector)


def fetch_all_windows():
    """Query OpenSearch for all configured windows and update the collector."""
    for window_key in WINDOWS:
        try:
            raw  = _query_window(window_key)
            aggs = raw["aggs"]

            ips:       dict = {}
            countries: dict = {}

            for b in aggs.get("top_ips", {}).get("buckets", []):
                ip    = b["key"]
                count = b["doc_count"]
                lat, lon, country, code = get_geo(ip)
                ips[ip] = (count, lat, lon, country, code)
                key = (country, code)
                countries[key] = countries.get(key, 0) + count

            agents = {
                b["key"]: b["doc_count"]
                for b in aggs.get("top_agents", {}).get("buckets", [])
            }
            levels = {
                b["key"]: b["doc_count"]
                for b in aggs.get("threat_levels", {}).get("buckets", [])
            }

            _collector.update(window_key, {
                "total":     raw["total"],
                "critical":  raw["critical"],
                "ips":       ips,
                "countries": countries,
                "agents":    agents,
                "levels":    levels,
            })
            print(
                f"[{window_key}] total={raw['total']} critical={raw['critical']}",
                flush=True,
            )
        except Exception as e:
            print(f"[poll] Error fetching window {window_key}: {e}", flush=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Populate static window metrics once before the HTTP server starts
    thresholds = [
        ("15m", "900"),
        ("1h",  "3600"),
        ("6h",  "21600"),
        ("24h", "86400"),
        ("7d",  "604800"),
    ]
    for window, seconds in thresholds:
        _WINDOW_THRESHOLDS.labels(window=window, seconds=seconds).set(1)

    # Ordinal prefix keeps alphabetical sort == chronological sort in Grafana.
    # Upper bound for 7d is intentionally large so it always wins for long ranges.
    select_entries = [
        ("1-15m",  900),
        ("2-1h",   3600),
        ("3-6h",   21600),
        ("4-24h",  86400),
        ("5-7d",   99999999),
    ]
    for window, upper_bound in select_entries:
        _WINDOW_SELECT.labels(window=window).set(upper_bound)

    print(
        f"Starting Wazuh Exporter (multi-window + GeoIP enrichment)...",
        flush=True,
    )
    print(f"Indexer: {BASE_URL}", flush=True)
    print(f"Windows: {list(WINDOWS.keys())}", flush=True)

    start_http_server(EXPORTER_PORT)
    print(f"Metrics server running on port {EXPORTER_PORT}", flush=True)

    while True:
        fetch_all_windows()
        time.sleep(POLL_INTERVAL)
