# Zyxel NR5307 API Wrapper

Python API wrapper for the Zyxel NR5307 5G router providing programmatic access to all (known) router functions via DAL and CGI endpoints.

> **Note:** This wrapper was developed and tested on the Zyxel NR5307. It may work with other Zyxel router models using similar firmware (e.g., VMG8825, LTE3301, LTE3302), but compatibility with other models is untested.

## Features

- **51 endpoints** - 36 DAL OIDs + 15 CGI endpoints
- **Automatic authentication** - Interactive, saved credentials, environment variables, or manual
- **Auto session recovery** - Automatically re-authenticates when sessions expire (401 errors)
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

### DAL OID Endpoints (36)

**Network:**
- `get_lanhosts()` - Connected devices
- `get_lan()` - LAN configuration
- `get_lanadv()` - Advanced LAN settings
- `get_ethwanlan()` - Ethernet WAN/LAN config
- `get_cellwan_status()` - Cellular WAN status
- `get_cellwan_sim()` - SIM card info
- `get_cellwan_psru()` - Cellular PSRU
- `get_nat()` - NAT configuration
- `get_nat_conf()` - NAT configuration details
- `get_static_dhcp()` - Static DHCP assignments
- `get_dns()` - DNS configuration
- `get_ddns()` - Dynamic DNS settings

**WiFi:**
- `get_wlan()` - WLAN configuration
- `get_wlan_sch_access()` - WLAN scheduled access
- `get_wifi_easy_mesh()` - WiFi Easy Mesh settings
- `get_wifi_mlo()` - WiFi Multi-Link Operation
- `get_wifi_others()` - Other WiFi settings
- `get_wps()` - WPS settings

**Security:**
- `get_firewall()` - Firewall configuration
- `get_trust_domain()` - Trusted domain settings
- `get_cyber_secure()` - Cyber security features
- `get_paren_ctl()` - Parental controls

**System:**
- `get_status()` - Complete system status (17KB+ JSON)
- `get_cardpage_status()` - Card page status
- `get_backup_restore_config()` - Backup/restore config
- `get_mgmt_srv()` - Management server settings
- `get_sp_mgmt_srv()` - Service provider mgmt server
- `get_user_account()` - User account information
- `get_login_privilege()` - Login privileges
- `get_logset()` - Log settings
- `get_tr69()` - TR-069 configuration
- `get_one_connect()` - One Connect settings
- `get_email_ntfy()` - Email notifications

**Monitoring & QoS:**
- `get_traffic_status()` - Traffic statistics
- `get_qos()` - QoS configuration
- `get_pingtest()` - Ping test

### CGI Endpoints (15)

- `get_arp_table()` - ARP table
- `get_card_info()` - SIM card information
- `get_diagnostic_result()` - Diagnostic results
- `get_home_networking()` - Home networking info
- `get_log()` - System logs
- `get_login_account_level()` - Login account level
- `get_menu_list()` - Menu structure
- `get_mtd_size()` - MTD partition size
- `get_routing_table()` - Routing table
- `get_steering_status()` - Band steering status
- `get_wan_lan_list()` - WAN/LAN interface list
- `get_wlan_table()` - WLAN client table
- `get_wireless()` - Wireless information
- `check_fsecure_license()` - F-Secure license status
- `check_login_status()` - Verify session status

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

# Complete status JSON dump
python examples/router_status.py

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
│   ├── router_status.py  # Complete status JSON dump
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

### Automatic Session Recovery

The API now automatically handles expired sessions!

When your session expires (401 Unauthorized), the API will:
1. Detect the session has expired
2. Clear the expired session from saved credentials
3. Automatically prompt you to re-authenticate
4. Retry the original request with the fresh session
5. Continue without interruption

**Example:**
```python
api = RouterAPI.login_interactive()

# Session expires after some time...
status = api.get_status()  # If session expired:
# ⚠️  Session expired (401 Unauthorized)
#    Re-authenticating...
#
# 💾 Found saved credentials for admin@192.168.1.1
# Use saved credentials? (yes/no) [yes]:
#    ✅ Re-authentication successful!
#
# [✓] Request completed successfully
```

**Manual Session Reset (if needed):**
```bash
# Option 1: Delete saved credentials completely
rm ~/.zyxel_router
python examples/router_info.py

# Option 2: Use the credentials manager
python examples/router_credentials.py
# Choose option 4 to delete, then re-run your script
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

