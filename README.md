# Technitium API Proxy

A security proxy for [Technitium DNS Server](https://technitium.com/dns/) that adds fine-grained access control to the Technitium HTTP API. It runs as a standalone FastAPI service, forwarding allowed requests to the upstream Technitium server while enforcing token-based policies.

Clients use the standard [Technitium API](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md). They just point at the proxy instead of Technitium directly.

---

## Features

- YAML-driven configuration (`config.yml`) with per-token access policies
- Zone-scoped tokens that restrict which DNS zones a token can access
- Operation filtering to limit tokens to specific CRUD operations (`get`, `add`, `update`, `delete`)
- Record type filtering to restrict tokens to specific DNS record types (`A`, `AAAA`, `CNAME`, `TXT`, etc.)
- Subdomain filtering to limit tokens to manage records under a specific subdomain prefix
- Global read-only tokens that allow full read access across all zones without write permissions
- Tiered endpoint classification where only record and zone-list endpoints are proxied; zone management and admin endpoints are blocked
- Zone list filtering where `/api/zones/list` responses only show zones the token is allowed to access
- Structured audit logging via structlog
- Multi-arch Docker images (linux/amd64, linux/arm64)
- Standalone binary builds via PyInstaller

---

## How It Works

The proxy sits between clients and the Technitium DNS Server:

```
Client --> Proxy (port 31399) --> Technitium (port 5380)
```

1. Client sends a request with their token (via `X-API-Token` header or `?token=` query param)
2. Proxy validates the token against the configured policy
3. If allowed, the request is forwarded to Technitium
4. The response is returned to the client (with zone list filtering applied if applicable)

### Endpoint Tiers

| Tier | Endpoints | Access |
|------|-----------|--------|
| Tier 1 | `/api/zones/records/*`, `/api/zones/list` | Allowed (with policy checks) |
| Tier 2 | `/api/zones/create`, `/api/zones/delete`, `/api/zones/enable`, `/api/zones/disable`, `/api/zones/import`, `/api/zones/export` | Blocked |
| Tier 3 | All other `/api/*` (admin, settings, etc.) | Blocked |

---

## Docker

### Docker Compose

```yaml
services:
  technitium-api-proxy:
    image: spaleks/technitium-api-proxy:latest
    # or quay.io/spaleks/technitium-api-proxy:latest
    ports:
      - "31399:31399"
    volumes:
      - ./config.yml:/app/config.yml:ro
```

### Standalone

```bash
docker run --rm \
  -p 31399:31399 \
  -v "$(pwd)/config.yml:/app/config.yml:ro" \
  spaleks/technitium-api-proxy:latest
```

---

## Configuration (`config.yml`)

```yaml
technitium:
  url: "http://localhost:5380"
  token: "your-admin-api-token"
  verify_ssl: true

tokens:
  # Full access to a zone
  - name: "full-access"
    token: "client-secret-token"
    zones:
      - name: "example.com"
        allowed_record_types: ["A", "AAAA", "CNAME", "TXT"]
        allowed_operations: ["list", "get", "add", "update", "delete"]

  # Only manage records under app.example.com (regex pattern)
  # Allows: app.example.com, api.app.example.com, v2.app.example.com
  # Denies: www.example.com, mail.example.com
  - name: "app-team"
    token: "app-team-secret"
    zones:
      - name: "example.com"
        subdomain_filter: "^app\\."
        allowed_record_types: ["A", "AAAA", "CNAME"]
        allowed_operations: ["list", "get", "add", "update", "delete"]

  # Read-only access to all zones (no zone scoping)
  - name: "monitoring"
    token: "monitoring-secret"
    global_read_only: true
```

### Token Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Display name for audit logs |
| `token` | string | required | The secret token clients use to authenticate |
| `global_read_only` | bool | `false` | Allow read-only access to all zones (ignores `zones`) |
| `zones` | list | `[]` | Zone-level access policies |

### Zone Policy Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | DNS zone name (e.g. `example.com`) |
| `allowed_record_types` | list | `[]` (all) | Restrict to specific record types (`A`, `AAAA`, `CNAME`, `TXT`, `MX`, etc.) |
| `allowed_operations` | list | `[]` (all) | Restrict to specific operations (`get`, `add`, `update`, `delete`) |
| `subdomain_filter` | string | `null` | Regex pattern to match against the domain (case-insensitive) |

Empty lists mean "all allowed". Omit `allowed_record_types` to allow all record types, omit `allowed_operations` to allow all operations.

---

## Usage (Local)

### Binary

Download the binary from the [releases](https://github.com/spaaleks/technitium-api-proxy/releases) page:

```bash
chmod +x technitium-api-proxy
CONFIG_PATH=./config.yml ./technitium-api-proxy
```

### From Source

```bash
git clone https://github.com/spaaleks/technitium-api-proxy.git
cd technitium-api-proxy
bin/start.sh
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_PATH` | `config.yml` | Path to the YAML configuration file |
| `HOST` | `0.0.0.0` | Host/IP to bind |
| `PORT` | `31399` | Port to bind |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warning`, `error`) |

---

## Authentication

Clients authenticate by passing their token in one of two ways:

**Header** (preferred):
```bash
curl -H "X-API-Token: your-token" http://proxy:31399/api/zones/list
```

**Query parameter**:
```bash
curl http://proxy:31399/api/zones/list?token=your-token
```

The header takes precedence if both are provided.

---

## Credits

Inspired by [powerdns-api-proxy](https://github.com/akquinet/powerdns-api-proxy) and the Technitium feature request [TechnitiumSoftware/DnsServer#958](https://github.com/TechnitiumSoftware/DnsServer/issues/958).

---

## License

MIT
