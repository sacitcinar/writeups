# Strange & Unusual Activity

### Scenario

A threat-intelligence feed flagged suspicious communications within the `10.10.14.0/24` corporate network, but the internal monitoring systems did not generate any alerts. The task was to investigate a 24-hour capture of network traffic, identify the command-and-control (C2) communications, locate the affected workstation and determine the extent of data transferred.

| Field | Details |
|---|---|
| Platform | TryHackMe |
| Difficulty | Medium |
| Category | Network Forensics / Threat Hunting |
| Tools | Kibana, Elasticsearch, Zeek |
| Author | dmncdcco |

## Overview

The investigation used Zeek logs available through Kibana Discover. DNS records were examined to identify the suspicious domain and its communication frequency, while connection records were used to investigate outbound data transfers.

### Investigation Setup

In Kibana Discover, the `zeek-*` data view was selected. The time picker in the upper-right corner was changed from its default recent range to an **absolute time range covering the 7 October 2025 (24-hour) capture**, and the search was refreshed. This ensured that the historical Zeek records were visible.

## Tasks

### Task 1 — C2 Domain

**Question:** What is the domain name used by the command-and-control (C2) server?

- **Answer:** `edge-metrics-sync.net`

DNS traffic was isolated in Kibana Discover by filtering for destination port `53`:

```kql
id.resp_p: 53
```

The `query` field was examined using **Top values**. Alongside domains associated with familiar services, `edge-metrics-sync.net` appeared in approximately **7.2%** of the displayed DNS records.

The domain was investigated further with:

```kql
query: "edge-metrics-sync.net"
```

This filter showed repeated requests to the same domain.

### Task 2 — Callback Interval

**Question:** What is the callback interval, in seconds, between the compromised host and the C2 server?

- **Answer:** `300`

The DNS records for the identified domain were filtered again:

```kql
query: "edge-metrics-sync.net"
```

The `@timestamp` values of consecutive requests were compared in Kibana Discover:

| Timestamp | Time since previous request |
|---|---|
| `21:21:39.890` | — |
| `21:26:45.287` | 305.397 seconds |
| `21:32:32.151` | 346.864 seconds |
| `21:37:45.702` | 313.551 seconds |

The requests followed an approximately five-minute pattern, with some variation between individual observations.

### Task 3 — Compromised Host

**Question:** What is the IP address of the compromised host?

- **Answer:** `10.10.14.160`

The C2 domain was filtered in Kibana Discover:

```kql
query: "edge-metrics-sync.net"
```

The **Top values** for `id.orig_h`, the source IP field, showed a single internal address associated with these DNS requests:

```text
10.10.14.160
```

This address falls within the `10.10.14.0/24` network specified in the scenario.

### Task 4 — Total C2 Callbacks

**Question:** How many check-ins (callbacks) did the compromised host make to the C2 domain over the capture window?

- **Answer:** `289`

The DNS records were filtered by the C2 domain:

```kql
query: "edge-metrics-sync.net"
```

Kibana Discover returned **289 matching records** over the capture window.

### Task 5 — Largest Outbound Data Transfer

**Question:** How many bytes of data were exfiltrated in the single largest outbound transfer to the C2 server?

- **Answer:** `54078822`

For this task, the investigation moved to Zeek connection logs (`zeek-conn`). The records were filtered to connections from the compromised workstation (`10.10.14.160`) to the C2 server (`203.0.113.77`):

```kql
_index: "zeek-conn" AND id.orig_h: "10.10.14.160" AND id.resp_h: "203.0.113.77"
```

The relevant fields were:

- `id.orig_h` — source IP address
- `id.resp_h` — destination IP address
- `orig_bytes` — bytes sent by the connection originator
- `resp_bytes` — bytes received by the connection originator

The `orig_bytes` field was added as a column in Discover. After removing the existing timestamp sort, the field was sorted **high to low** to identify the largest outbound transfer to the C2 server.

The highest recorded value was **54,078,822 bytes**.

## Findings and Indicators

The analysis identified recurring DNS requests to the C2 domain from a single workstation and a large outbound data transfer associated with the compromised host.

| Indicator | Value |
|---|---|
| C2 domain | `edge-metrics-sync[.]net` |
| C2 server IP (lab) | `203.0.113.77` |
| Compromised host | `10.10.14.160` |
| Callback interval | `300 seconds` |
| Total callbacks | `289` |
| Largest outbound transfer | `54,078,822 bytes` |

---

*This write-up is intended for educational purposes and authorized security research.*
