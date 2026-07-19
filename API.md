# Openworld Node Agent API

Base URL: `http://<node-address>:1234/api/v1`

All requests require the `X-API-Key` header.

---

## Health

```
GET /health
```

Returns server status. No auth required.

**Response**
```json
{
  "status": "ok",
  "version": "v1",
  "time": "2026-07-18T12:00:00"
}
```

---

## Create VPS

```
POST /vps
```

Creates a Docker container using sysbox-runc.

**Body**
```json
{
  "uuid": "vps-uuid-here",
  "hostname": "vps-abcd12",
  "cpu": 2,
  "ram": "512m",
  "swap": "1024m",
  "network": "bridge",
  "ip": "2a11:6c7:2200:b101::10",
  "dns": ["1.1.1.1", "8.8.8.8"],
  "image": "ubuntu-22.04",
  "rootPassword": "secure-password"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uuid` | string | yes | VPS UUID |
| `hostname` | string | yes | Container name |
| `cpu` | int | yes | CPU cores |
| `ram` | string | yes | Memory limit (e.g. `512m`) |
| `swap` | string | yes | Memory + swap limit |
| `network` | string | yes | Docker network name |
| `ip` | string | no | IPv4 or IPv6 address (auto-assigned if omitted) |
| `dns` | string[] | no | DNS servers (defaults to 1.1.1.1, 8.8.8.8) |
| `image` | string | yes | Docker image name |
| `rootPassword` | string | yes | Root password passed as env |
| `readBps` | int | no | Read rate limit in Mbps (0 = unlimited) |
| `writeBps` | int | no | Write rate limit in Mbps (0 = unlimited) |
| `diskMb` | int | no | Disk size in MB for .img file (0 = no image, use directory) |

**Response** `201`
```json
{
  "containerId": "a1b2c3d4...",
  "hostname": "vps-abcd12",
  "status": "created"
}
```

**Errors**
- `400` — missing fields or invalid parameters
- `409` — container already exists
- `500` — docker error

---

## Destroy VPS

```
DELETE /vps/<hostname>?uuid=<vps-uuid>
```

Removes container and data directory.

**Response**
```json
{
  "hostname": "vps-abcd12",
  "status": "destroyed"
}
```

**Errors**
- `400` — invalid hostname or missing uuid
- `404` — not found (still returns 200)

---

## Start VPS

```
POST /vps/<hostname>/start
```

**Response**
```json
{
  "hostname": "vps-abcd12",
  "status": "running"
}
```

**Errors**
- `404` — container not found
- `500` — docker error

---

## Stop VPS

```
POST /vps/<hostname>/stop
```

Gracefully stops with 10s timeout.

**Response**
```json
{
  "hostname": "vps-abcd12",
  "status": "stopped"
}
```

**Errors**
- `404` — container not found
- `500` — docker error

---

## Restart VPS

```
POST /vps/<hostname>/restart
```

Restarts with 10s timeout.

**Response**
```json
{
  "hostname": "vps-abcd12",
  "status": "running"
}
```

**Errors**
- `404` — container not found
- `500` — docker error

---

## Get VPS Status

```
GET /vps/<hostname>/status
```

Returns container state and IP addresses.

**Response**
```json
{
  "hostname": "vps-abcd12",
  "status": "running",
  "running": true,
  "pid": 12345,
  "startedAt": "2026-07-18T10:00:00Z",
  "finishedAt": "0001-01-01T00:00:00Z",
  "ips": {
    "bridge": "172.17.0.2",
    "bridge_ipv6": "2a11:6c7:..."
  }
}
```

Status values: `running`, `exited`, `created`, `paused`, `restarting`, `removing`, `dead`, `offline`

---

## Get VPS Stats

```
GET /vps/<hostname>/stats
```

Returns live resource usage. Returns `null` metrics if container is not running.

**Response**
```json
{
  "hostname": "vps-abcd12",
  "status": "running",
  "metrics": {
    "cpu": "12.34%",
    "memoryUsage": "256MiB",
    "memoryLimit": "512MiB",
    "netIn": "1.5MiB",
    "netOut": "800KiB",
    "blockIn": "10MB",
    "blockOut": "5MB"
  }
}
```

If stopped:
```json
{
  "hostname": "vps-abcd12",
  "status": "exited",
  "metrics": null
}
```

---

## Legacy Endpoints

These map to the old API format for backward compatibility:

| Legacy | Maps to |
|--------|---------|
| `POST /dockercreatevps` | `POST /vps` |
| `POST /vps_action` | `POST /vps/<hostname>/<action>` |
| `GET /dockerstatsvps?container_id=X` | `GET /vps/<hostname>/stats` |

**vps_action body**
```json
{
  "hostname": "vps-abcd12",
  "action": "start"
}
```

---

## Error Format

All errors return:
```json
{
  "error": "description of what went wrong"
}
```

Common status codes:
- `400` — bad request / validation
- `401` — missing or invalid API key
- `404` — resource not found
- `405` — method not allowed
- `409` — conflict (already exists)
- `500` — server / docker error

---

## Network Management

### List Networks

```
GET /networks
```

**Response**
```json
{
  "networks": [
    {"id": "abc123", "name": "route64-docker", "driver": "bridge", "scope": "local"}
  ]
}
```

### Create Network

```
POST /networks
```

**Body**
```json
{
  "name": "route64-docker",
  "subnet": "2a11:6c7:2200:b101::/64",
  "gateway": "2a11:6c7:2200:b101::1",
  "ipv6": true,
  "enableMasquerade": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Network name |
| `subnet` | string | no | Subnet CIDR |
| `gateway` | string | no | Gateway address |
| `ipv6` | bool | no | Enable IPv6 (default true) |
| `enableMasquerade` | bool | no | IP masquerade (default false) |

**Response** `201`
```json
{
  "networkId": "abc123...",
  "name": "route64-docker",
  "status": "created"
}
```

### Inspect Network

```
GET /networks/<name>
```

**Response**
```json
{
  "name": "route64-docker",
  "id": "abc123...",
  "driver": "bridge",
  "scope": "local",
  "enableIPv6": true,
  "ipam": {
    "Driver": "default",
    "Config": [
      {"Subnet": "2a11:6c7:2200:b101::/64", "Gateway": "2a11:6c7:2200:b101::1"}
    ]
  },
  "containers": {
    "def456": {"name": "vps-abcd12", "ipv4": "", "ipv6": "2a11:6c7:2200:b101::2/64"}
  }
}
```

### Delete Network

```
DELETE /networks/<name>
```

**Response**
```json
{
  "name": "route64-docker",
  "status": "removed"
}
```

### Connect Container to Network

```
POST /networks/<name>/connect
```

**Body**
```json
{
  "container": "vps-abcd12",
  "ip": "2a11:6c7:2200:b101::10"
}
```

**Response**
```json
{
  "network": "route64-docker",
  "container": "vps-abcd12",
  "status": "connected"
}
```

### Disconnect Container from Network

```
POST /networks/<name>/disconnect
```

**Body**
```json
{
  "container": "vps-abcd12",
  "force": false
}
```

**Response**
```json
{
  "network": "route64-docker",
  "container": "vps-abcd12",
  "status": "disconnected"
}
```

---

## Abuse Detection

The abuse agent (`agent.py`) monitors containers for resource abuse and mining. Run separately:

```bash
python3 agent.py
```

### Trigger Manual Scan

```
POST /abuse/scan
```

Runs an immediate scan of all containers.

**Response**
```json
{
  "status": "scan complete",
  "violations": {
    "vps-abcd12": [
      {"type": "cpu", "detail": "CPU at 98.2%", "time": "2026-07-18T12:00:00"}
    ]
  },
  "banned": {
    "vps-abcd12": {"until": 1721305200, "reason": "exceeded 3 violations"}
  }
}
```

### Get Violations

```
GET /abuse/violations
```

Returns current violations and banned containers.

### Unsuspend Container

```
POST /abuse/unsuspend/<hostname>
```

Manually removes ban and starts the container.

**Response**
```json
{
  "hostname": "vps-abcd12",
  "status": "unsuspended"
}
```

### Get Thresholds

```
GET /abuse/config
```

**Response**
```json
{
  "cpu_max_percent": 90,
  "ram_max_percent": 95,
  "disk_max_gb": 0,
  "diskio_max_mbps": 200,
  "net_max_mbps": 500,
  "check_interval": 30,
  "ban_duration_minutes": 30,
  "max_violations_before_ban": 3
}
```

### Update Thresholds

```
POST /abuse/config
```

**Body** (partial update)
```json
{
  "cpu_max_percent": 80,
  "ban_duration_minutes": 60
}
```

### What It Detects

| Type | Detection |
|------|-----------|
| **CPU** | Usage above threshold for sustained period |
| **RAM** | Memory usage above threshold |
| **Disk** | Disk usage above limit (if set) |
| **Disk I/O** | Block read+write above threshold (default 200MB) |
| **Network** | Network I/O above threshold |
| **Mining** | Known mining processes (xmrig, minerd, etc.) |
| **Mining** | Connections to known mining pool ports |

### Behavior

1. Container exceeds threshold → violation recorded
2. Violations reach `max_violations_before_ban` → container stopped
3. Mining detected → container stopped immediately, ban extended 10x
4. Ban expires → container auto-started on next scan
5. Manual unsuspend via API clears all violations
