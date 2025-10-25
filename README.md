# Zyxel NR5307 API Wrapper

Python API wrapper for the Zyxel NR5307 5G router providing programmatic access to all (known) router functions via DAL and CGI endpoints.

> **Note:** This wrapper was developed and tested on the Zyxel NR5307. It may work with other Zyxel router models using similar firmware (e.g., VMG8825, LTE3301, LTE3302), but compatibility with other models is untested.

## Features

- **52 endpoints** - 36 DAL OIDs + 16 CGI endpoints
- **Automatic authentication** - Interactive, saved credentials, environment variables, or manual
- **Secure credential storage** - Encrypted with restricted permissions (chmod 600)
- **Session management** - Automatic cookie handling and reuse
- **Production ready** - Type hints, error handling, comprehensive documentation

## Installation

```bash
git clone <repository-url>
cd ZyxelNR5307api
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Quick Start

```python
from api.router_api import RouterAPI

# Authenticate (checks saved credentials, prompts if needed)
api = RouterAPI.login_interactive()

# Get router information
status = api.get_status()
devices = api.get_lanhosts()
wifi = api.get_wlan()

print(f"Model: {status['Object'][0]['DeviceInfo']['ModelName']}")
print(f"Devices: {len(devices['Object'][0]['lanhosts'])}")
```

## Authentication

### Interactive Login (Recommended)

```python
from api.router_api import RouterAPI

api = RouterAPI.login_interactive()
```

### Saved Credentials

```python
api = RouterAPI.from_saved_credentials()  # Uses ~/.zyxel_router
```

### Environment Variables

```bash
export ROUTER_IP="192.168.1.1"
export ROUTER_USERNAME="admin"
export ROUTER_PASSWORD="password"
```

```python
api = RouterAPI.from_env()
```

### Direct Login

```python
api = RouterAPI.login(
    router_ip="192.168.1.1",
    username="admin",
    password="password",
    save_credentials=True
)
```

### Manual Session

```python
api = RouterAPI(router_ip="192.168.1.1", session_cookie="SESSION_COOKIE")
```

## API Reference

### Network

- `get_lanhosts()` - Connected devices (MAC, IP, hostname)
- `get_lan()` - LAN configuration
- `get_cellwan_status()` - Cellular WAN status and signal
- `get_nat()` - NAT configuration
- `get_static_dhcp()` - Static DHCP leases
- `get_dns()` - DNS configuration
- `get_ddns()` - Dynamic DNS settings
- `get_arp_table()` - ARP table
- `get_routing_table()` - Routing table

### WiFi

- `get_wlan()` - WiFi configuration (SSID, security)
- `get_wifi_easy_mesh()` - Mesh network settings
- `get_wifi_mlo()` - Multi-link operation
- `get_wps()` - WPS configuration
- `get_wlan_table()` - Connected WiFi clients

### Security

- `get_firewall()` - Firewall rules
- `get_trust_domain()` - Trusted domain settings
- `get_cyber_secure()` - Security features
- `get_paren_ctl()` - Parental controls

### Quality of Service

- `get_qos()` - QoS configuration (bandwidth limits, auto-mapping)

### System

- `get_status()` - Complete system status
- `get_mgmt_srv()` - Management services
- `get_user_account()` - User accounts
- `get_login_privilege()` - Login privileges
- `get_log()` - System logs
- `get_logset()` - Log settings
- `get_tr69()` - TR-069 configuration
- `check_login_status()` - Verify session

### Monitoring

- `get_traffic_status()` - Interface traffic statistics
- `get_card_info()` - SIM card information
- `check_wan_connection_status()` - WAN connection status

### Additional Endpoints

`get_ethwanlan()`, `get_dhcp_server()`, `get_port_trigger()`, `get_port_fwd()`, `get_dmz()`, `get_alg()`, `get_backup_restore_config()`, `get_firmware_config()`, `get_remote_mgmt()`, `get_time()`, `get_snmp()`, `get_email_ntfy()`, `get_wireless()`, `get_menu_list()`, `check_fsecure_license()`

## Usage Examples

### Monitor Network

```python
from api.router_api import RouterAPI
import time

api = RouterAPI.login_interactive()

while True:
    devices = api.get_lanhosts()['Object'][0]['lanhosts']
    active = [d for d in devices if d.get('Active')]
    
    status = api.get_status()
    signal = status['Object'][0]['CellIntfInfo']['RSSI']
    
    print(f"Devices: {len(active)}, Signal: {signal} dBm")
    time.sleep(30)
```

### Track New Devices

```python
from api.router_api import RouterAPI
import time

api = RouterAPI.from_saved_credentials()

known_macs = set()
while True:
    devices = api.get_lanhosts()['Object'][0]['lanhosts']
    current_macs = {d['PhysAddress'] for d in devices if d.get('Active')}
    
    if new := current_macs - known_macs:
        for mac in new:
            device = next(d for d in devices if d['PhysAddress'] == mac)
            print(f"New device: {device.get('HostName', 'Unknown')} ({device['IPAddress']})")
    
    known_macs = current_macs
    time.sleep(30)
```

### Configuration Backup

```python
from api.router_api import RouterAPI
import json
from datetime import datetime

api = RouterAPI.from_env()

backup = {
    'timestamp': datetime.now().isoformat(),
    'status': api.get_status(),
    'lan': api.get_lan(),
    'wlan': api.get_wlan(),
    'firewall': api.get_firewall(),
    'nat': api.get_nat()
}

filename = f"router_backup_{datetime.now().strftime('%Y%m%d')}.json"
with open(filename, 'w') as f:
    json.dump(backup, f, indent=2)
```

### Monitor Traffic

```python
from api.router_api import RouterAPI
import time

api = RouterAPI.login_interactive()

while True:
    traffic = api.get_traffic_status()
    obj = traffic['Object'][0]
    
    for idx, iface in enumerate(obj.get('ipIface', [])):
        if iface.get('Status') == 'Up':
            stats = obj['ipIfaceSt'][idx]
            print(f"{iface['Name']}: ↓{stats['BytesReceived']} ↑{stats['BytesSent']}")
    
    time.sleep(10)
```

## Response Format

All DAL endpoints return JSON:

```json
{
  "result": "ZCFG_SUCCESS",
  "ReplyMsg": "Success",
  "Object": [
    {
      "Index": 1,
      "Enable": true,
      ...
    }
  ]
}
```

## Error Handling

```python
from api.router_api import RouterAPI
import requests

try:
    api = RouterAPI.login_interactive()
    status = api.get_status()
except ValueError as e:
    print(f"Authentication failed: {e}")
except requests.exceptions.ConnectionError:
    print("Cannot connect to router")
except requests.exceptions.Timeout:
    print("Request timed out")
except Exception as e:
    print(f"Error: {e}")
```

## Example Scripts

```bash
# Display comprehensive router information
python examples/router_info.py

# Real-time monitoring dashboard
python examples/router_monitor.py

# Manage saved credentials
python examples/router_credentials.py
```

## Project Structure

```
ZyxelNR5307api/
├── api/
│   ├── router_auth.py    # Authentication and credential management
│   └── router_api.py     # Main API wrapper (all endpoints)
├── examples/
│   ├── router_info.py    # Display router information
│   ├── router_monitor.py # Real-time monitoring
│   └── router_credentials.py # Credential management
├── README.md
└── requirements.txt
```

## Advanced Features

### Custom DAL Query

```python
response = api.dal_query('custom_oid', params={'key': 'value'})
```

### Custom CGI Call

```python
response = api.cgi_call('CustomEndpoint', data={'param': 'value'})
```

### Retry Logic

```python
import time

def get_with_retry(func, max_retries=3):
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                raise

status = get_with_retry(lambda: api.get_status())
```

## Security

Credentials are stored in `~/.zyxel_router` with chmod 600:

```json
{
  "router_ip": "192.168.1.1",
  "username": "admin",
  "password": "password",
  "session_cookie": "active_session"
}
```

**Best Practices:**
- Use `login_interactive()` for CLI tools
- Use `from_env()` for automation and containers
- Never hardcode credentials in scripts
- Don't commit `~/.zyxel_router` to version control
- Session cookies are automatically managed and reused

## Troubleshooting

### 401 Unauthorized / Invalid Username or Password

**Symptom:** Getting "401 Client Error: Unauthorized" or "Invalid Username or Password" even though credentials worked before.

**Cause:** Your saved session cookie has expired (typically after router reboot or timeout).

**Fix:**
```bash
# Option 1: Delete saved credentials and re-authenticate
rm ~/.zyxel_router
python examples/router_info.py  # Will prompt for credentials

# Option 2: Use the credentials manager
python examples/router_credentials.py
# Choose option 4 to delete, then re-run your script

# Option 3: Force new login in your script
python3 -c "from api.router_api import RouterAPI; api = RouterAPI.login('192.168.1.1', 'admin', 'password', save_credentials=True)"
```

### Other Common Issues

**Connection refused:** Verify router IP and network connectivity

**Authentication failed on first login:** Check username/password, ensure router is accessible via browser first

**No saved credentials:** Run `login()` with `save_credentials=True` first

**SSL errors:** SSL verification is disabled by default (router uses self-signed certificate)

## Requirements

- Python 3.8+
- requests >= 2.31.0
- pycryptodome >= 3.19.0
- urllib3 >= 2.0.0

## License

MIT License

