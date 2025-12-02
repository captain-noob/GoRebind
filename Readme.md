# goRebind :  Dynamic Reverse Proxy and DNS Resolver

This project provides a combined service: a high-performance HTTP reverse proxy and an optional local DNS server. It is designed to dynamically route traffic based on the requested host and includes advanced configuration options for SSL, outbound proxying, and HTTP/2 handling.

## Features

- Dynamic Routing: Maps source hostnames (e.g., example.local) to target URLs (e.g., https://www.google.com) via a simple JSON configuration file.
- Local DNS Resolver (Optional): When enabled, it responds to A record queries for configured hosts with a specified local IP address, eliminating the need to modify your local host files.
- Proxy Stability Fixes: Includes specific httputil.ReverseProxy configurations to stabilize connections, specifically by handling Connection: close headers to prevent tls: user canceled errors.
- Flexible TLS Handling: Allows skipping SSL certificate verification for local or development targets.
- HTTP/2 Control: Flag to force-enable or prevent HTTP/2 negotiation based on your backend or network requirements.

#### How to Build & Run

**2. Build:**

```bash
go build -o redirector .
```

**3. Run (Basic):**
```bash
./redirector
# Output: No config specified. Using generated filename: redirector-config.json ...

```

**4. Run (With DNS):**
```bash
./redirector -config config.json -port 8080 -dns -I wlan0
```


**4. Run (Custom):**
```bash
./redirector -config config.json -port 8080 
```

### 3. Example Config File

Create a file named `config.json`:

```json
[
  {
    "source": "api.localhost",
    "target": "https://jsonplaceholder.typicode.com"
  },
  {
    "source": "local-app.com",
    "target": "http://127.0.0.1:9090"
  },
  {
    "source": "secure.internal",
    "target": "https://192.168.1.50"
  }
]
```

### Command Line Flags

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-port` | `int` | `80` | Port for the HTTP reverse proxy to listen on. |
| `-config` | `string` | (auto-detect) | Path to the JSON configuration file. |
| `-skip-ssl-verify` | `bool` | `true` | Skips TLS certificate verification for upstream targets. Useful for self-signed certificates. |
| `-proxy` | `string` | `""` | Outbound HTTP proxy URL (e.g., `http://user:pass@10.0.0.1:8080`). |
| `-http2` | `bool` | `false` | **Force-enable HTTP/2.** Set to `true` if your targets support H2 and you require it. *(Note: Setting this to `false` applies stability fixes to prevent the 'tls: user canceled' error.)* |
| **DNS Flags** | | | |
| `-dns` | `bool` | `false` | Enable the local DNS server on port 53 (UDP). |
| `-interface`, `-I` | `string` | `""` | Network interface name (e.g., `eth0` or `en0`). The IPv4 address of this interface will be returned for all matched hostnames. **Required if `-dns` is enabled.** |
| `-verbose` | `bool` | `false` | Enable verbose logging. Only shows DNS queries that result in a system lookup (misses). |


### FAQ

#### Troubleshooting: `httputil: ReverseProxy read error... tls: user canceled`

This error often occurs when an intermediate proxy (like Burp Suite or Zap) is used, and the underlying connection is closed prematurely by the backend.

**Workaround for Burp Suite:**

1. Navigate to **Settings** > **Proxy** > **HTTP**.

2. Go to the **Match and Replace** rules section.

3. Add a new rule:

   * **Type:** `Response header`

   * **Match:** `Connection: close`

   * **Replace:** `Connection: keep-alive`

#### Find interface name in Windows

```powershell
PS c:\>netsh interface show interface

Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Disconnected   Dedicated        Local Area Connection
Enabled        Connected      Dedicated        VMware Network Adapter VMnet1
Enabled        Connected      Dedicated        WiFi
Enabled        Disconnected   Dedicated        Ethernet
```