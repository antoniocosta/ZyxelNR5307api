#!/usr/bin/env python3
"""
Zyxel NR5307 Router API Wrapper

A comprehensive Python API wrapper providing programmatic access to
Zyxel NR5307 5G router functions.

Supported Endpoints:
- 35 DAL OIDs (Device Abstraction Layer)
- 16 CGI Endpoints
- Full authentication support
- Session management
- Network monitoring
- Device management
- WiFi configuration
- System information

Usage:
    from router_api import RouterAPI
    
    api = RouterAPI(
        router_ip="192.168.1.1",
        session_cookie="your_session_cookie"
    )
    
    # Get system information
    status = api.get_status()
    print(f"Model: {status['ModelName']}")
    print(f"Firmware: {status['SoftwareVersion']}")
    
    # Get connected devices
    devices = api.get_lanhosts()
    print(f"Devices: {len(devices['Object'])}")
    
    # Get WiFi settings
    wifi = api.get_wlan()
    print(f"SSID: {wifi['Object'][0]['SSID']}")
    
    # Get cellular status
    cellular = api.get_cellwan_status()
    print(f"Signal: {cellular['Object'][0]['SignalStrength']}")
"""

import requests
import json
import base64
import os
from typing import Dict, List, Any, Optional
from urllib3.exceptions import InsecureRequestWarning
from pathlib import Path

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import auth module (handle both relative and absolute imports)
try:
    from .router_auth import AuthManager
except ImportError:
    from router_auth import AuthManager

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("Warning: pycryptodome not installed. AES decryption unavailable.")
    print("Install with: pip install pycryptodome")


class RouterAPI:
    """Complete API wrapper for Zyxel NR5307 router"""
    
    def __init__(self, router_ip: str = "192.168.1.1", 
                 session_cookie: Optional[str] = None,
                 aes_key: Optional[str] = None,
                 use_https: bool = False,
                 _auth_method: Optional[str] = None,
                 _credentials_file: Optional[Path] = None):
        """
        Initialize Router API
        
        Args:
            router_ip: Router IP address
            session_cookie: Session cookie value (from login)
            aes_key: AES encryption key (base64 encoded, from localStorage)
            use_https: Use HTTPS instead of HTTP
            _auth_method: Internal - authentication method used
            _credentials_file: Internal - credentials file path
        """
        self.router_ip = router_ip
        self.base_url = f"{'https' if use_https else 'http'}://{router_ip}"
        self.session_cookie = session_cookie
        self.aes_key = aes_key
        self.use_https = use_https
        self._auth_method = _auth_method  # 'interactive', 'saved', etc.
        self._credentials_file = _credentials_file
        self._retry_count = 0  # Track retries to prevent infinite loops
        
        # Setup session
        self.session = requests.Session()
        self.session.verify = False
        
        if session_cookie:
            self.session.cookies.set('Session', session_cookie)
            self.session.cookies.set('_TESTCOOKIESUPPORT', '1')
    
    # ========================================================================
    # Convenience Authentication Methods
    # ========================================================================
    
    @classmethod
    def login(cls, router_ip: str = "192.168.1.1", 
              username: str = "admin", 
              password: str = "",
              save_credentials: bool = False,
              use_https: bool = True,
              aes_key: Optional[str] = None) -> 'RouterAPI':
        """
        Create API instance by logging in with username/password
        
        Args:
            router_ip: Router IP address
            username: Username (default: 'admin')
            password: Password
            save_credentials: Save credentials to ~/.zyxel_router
            use_https: Use HTTPS (default: True)
            aes_key: Optional AES encryption key
            
        Returns:
            RouterAPI instance
            
        Raises:
            ValueError: If login fails
            
        Example:
            >>> api = RouterAPI.login(
            ...     router_ip="192.168.1.1",
            ...     username="admin",
            ...     password="mypassword",
            ...     save_credentials=True
            ... )
        """
        auth = AuthManager()
        session_cookie = auth.login(router_ip, username, password, save_credentials, use_https)
        
        if not session_cookie:
            raise ValueError("Login failed. Check credentials and router IP.")
        
        return cls(router_ip=router_ip, session_cookie=session_cookie, 
                   aes_key=aes_key, use_https=use_https, _auth_method='login')
    
    @classmethod
    def from_saved_credentials(cls, credentials_file: Optional[Path] = None,
                               aes_key: Optional[str] = None) -> 'RouterAPI':
        """
        Create API instance using saved credentials from ~/.zyxel_router
        
        Args:
            credentials_file: Optional custom credentials file path
            aes_key: Optional AES encryption key
            
        Returns:
            RouterAPI instance
            
        Raises:
            ValueError: If no saved credentials found or login fails
            
        Example:
            >>> api = RouterAPI.from_saved_credentials()
        """
        auth = AuthManager(credentials_file)
        router_ip, session_cookie, use_https = auth.login_from_saved()
        
        if not router_ip or not session_cookie:
            raise ValueError("No saved credentials found or login failed. "
                           "Use RouterAPI.login_interactive() to login.")
        
        return cls(router_ip=router_ip, session_cookie=session_cookie,
                   aes_key=aes_key, use_https=use_https, _auth_method='saved',
                   _credentials_file=credentials_file)
    
    @classmethod
    def from_env(cls, aes_key: Optional[str] = None) -> 'RouterAPI':
        """
        Create API instance using environment variables
        
        Environment variables:
            ROUTER_IP: Router IP address (default: 192.168.1.1)
            ROUTER_SESSION_COOKIE: Session cookie (if available)
            ROUTER_USERNAME: Username (if session not available)
            ROUTER_PASSWORD: Password (if session not available)
            ROUTER_AES_KEY: AES encryption key (optional)
        
        Returns:
            RouterAPI instance
            
        Raises:
            ValueError: If required environment variables not set
            
        Example:
            >>> # Set environment variables first:
            >>> # export ROUTER_IP="192.168.1.1"
            >>> # export ROUTER_SESSION_COOKIE="abc123..."
            >>> api = RouterAPI.from_env()
        """
        auth = AuthManager()
        router_ip, session_cookie, use_https = auth.login_from_env()
        
        if not router_ip or not session_cookie:
            raise ValueError("Could not authenticate from environment variables. "
                           "Set ROUTER_SESSION_COOKIE or ROUTER_USERNAME/ROUTER_PASSWORD.")
        
        # Check for AES key in env if not provided
        if not aes_key:
            aes_key = os.getenv('ROUTER_AES_KEY')
        
        return cls(router_ip=router_ip, session_cookie=session_cookie,
                   aes_key=aes_key, use_https=use_https, _auth_method='env')
    
    @classmethod
    def login_interactive(cls, save_prompt: bool = True,
                         aes_key: Optional[str] = None,
                         credentials_file: Optional[Path] = None) -> 'RouterAPI':
        """
        Create API instance with interactive login prompts
        
        This will:
        1. Check for saved credentials and offer to use them
        2. Prompt for credentials if needed
        3. Login to router
        4. Optionally save credentials for future use
        
        Args:
            save_prompt: Prompt user to save credentials (default: True)
            aes_key: Optional AES encryption key
            credentials_file: Optional custom credentials file path
            
        Returns:
            RouterAPI instance
            
        Raises:
            ValueError: If login fails
            
        Example:
            >>> api = RouterAPI.login_interactive()
            # Prompts for credentials and handles everything automatically
        """
        auth = AuthManager(credentials_file)
        router_ip, session_cookie, use_https = auth.login_interactive(save_prompt)
        
        if not router_ip or not session_cookie:
            raise ValueError("Login failed or cancelled.")
        
        return cls(router_ip=router_ip, session_cookie=session_cookie,
                   aes_key=aes_key, use_https=use_https, _auth_method='interactive',
                   _credentials_file=credentials_file)
    
    def _reauthenticate(self) -> bool:
        """
        Re-authenticate when session expires
        
        Returns:
            True if re-authentication successful
        """
        if self._retry_count > 0:
            # Already tried to re-auth, don't retry again
            return False
        
        self._retry_count += 1
        
        print("\n⚠️  Session expired (401 Unauthorized)")
        print("   Re-authenticating...\n")
        
        # Clear expired session from saved credentials
        auth = AuthManager(self._credentials_file)
        auth.store.clear_session()
        
        # Re-authenticate based on original method
        if self._auth_method in ['interactive', 'saved']:
            # Use interactive login (will prompt for password if needed)
            router_ip, session_cookie, use_https = auth.login_interactive(save_prompt=False)
            
            if router_ip and session_cookie:
                self.router_ip = router_ip
                self.session_cookie = session_cookie
                self.use_https = use_https
                self.base_url = f"{'https' if use_https else 'http'}://{router_ip}"
                
                # Update session cookies
                self.session.cookies.set('Session', session_cookie)
                self.session.cookies.set('_TESTCOOKIESUPPORT', '1')
                
                print("   ✅ Re-authentication successful!\n")
                return True
        
        print("   ❌ Re-authentication failed\n")
        return False
    
    def _request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with proper headers and auto-retry on session expiry"""
        headers = kwargs.pop('headers', {})
        headers.setdefault('X-Requested-With', 'XMLHttpRequest')
        headers.setdefault('Accept', 'application/json')
        headers.setdefault('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36')
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = self.session.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            self._retry_count = 0  # Reset retry count on success
            return response
        except requests.exceptions.HTTPError as e:
            # Check if it's a 401 Unauthorized error
            if e.response.status_code == 401:
                # Try to re-authenticate
                if self._reauthenticate():
                    # Retry the request with new session
                    response = self.session.request(method, url, headers=headers, **kwargs)
                    response.raise_for_status()
                    self._retry_count = 0  # Reset retry count on success
                    return response
            # Re-raise the error if not 401 or re-auth failed
            raise
    
    def _decrypt_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt AES-encrypted response"""
        if not HAS_CRYPTO:
            raise RuntimeError("pycryptodome required for decryption. Install with: pip install pycryptodome")
        
        if not self.aes_key:
            raise ValueError("AES key not set. Cannot decrypt response.")
        
        try:
            ct = base64.b64decode(response_data["content"])
            iv = base64.b64decode(response_data["iv"])
            key = base64.b64decode(self.aes_key)
            
            cipher = AES.new(key, AES.MODE_CBC, iv[:16])
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            
            return json.loads(pt)
        except Exception as e:
            raise RuntimeError(f"Decryption failed: {e}")
    
    def dal_query(self, oid: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Query a DAL OID endpoint
        
        Args:
            oid: The OID to query (e.g., 'login_privilege')
            params: Optional query parameters
            
        Returns:
            Dict containing the response data (decrypted if encrypted)
        """
        endpoint = f"/cgi-bin/DAL?oid={oid}"
        if params:
            param_str = '&'.join([f"{k}={v}" for k, v in params.items()])
            endpoint += f"&{param_str}"
        
        response = self._request('GET', endpoint)
        response.raise_for_status()
        
        data = response.json()
        
        # Check if response is encrypted
        if 'content' in data and 'iv' in data:
            if self.aes_key:
                return self._decrypt_response(data)
            else:
                raise ValueError("Response is encrypted but no AES key provided")
        
        return data
    
    # ========================================================================
    # DAL OID Methods - Auto-generated from discovered endpoints
    # ========================================================================
    
    def get_pingtest(self) -> Dict[str, Any]:
        """Query PINGTEST endpoint"""
        return self.dal_query("PINGTEST")
    
    def get_traffic_status(self) -> Dict[str, Any]:
        """Query Traffic_Status endpoint"""
        return self.dal_query("Traffic_Status")
    
    def get_backup_restore_config(self) -> Dict[str, Any]:
        """Query backupRestore_config endpoint"""
        return self.dal_query("backupRestore_config")
    
    def get_cardpage_status(self) -> Dict[str, Any]:
        """Query cardpage_status endpoint"""
        return self.dal_query("cardpage_status")
    
    def get_cellwan_psru(self) -> Dict[str, Any]:
        """Query cellwan_psru endpoint"""
        return self.dal_query("cellwan_psru")
    
    def get_cellwan_sim(self) -> Dict[str, Any]:
        """Query cellwan_sim endpoint"""
        return self.dal_query("cellwan_sim")
    
    def get_cellwan_status(self) -> Dict[str, Any]:
        """Query cellwan_status endpoint - Get cellular WAN status"""
        return self.dal_query("cellwan_status")
    
    def get_cyber_secure(self) -> Dict[str, Any]:
        """Query cyber_secure endpoint"""
        return self.dal_query("cyber_secure")
    
    def get_ddns(self) -> Dict[str, Any]:
        """Query ddns endpoint - Get Dynamic DNS configuration"""
        return self.dal_query("ddns")
    
    def get_dns(self) -> Dict[str, Any]:
        """Query dns endpoint - Get DNS configuration"""
        return self.dal_query("dns")
    
    def get_email_ntfy(self) -> Dict[str, Any]:
        """Query email_ntfy endpoint - Get email notification settings"""
        return self.dal_query("email_ntfy")
    
    def get_ethwanlan(self) -> Dict[str, Any]:
        """Query ethwanlan endpoint - Get Ethernet WAN/LAN configuration"""
        return self.dal_query("ethwanlan")
    
    def get_firewall(self) -> Dict[str, Any]:
        """Query firewall endpoint - Get firewall configuration"""
        return self.dal_query("firewall")
    
    def get_lan(self) -> Dict[str, Any]:
        """Query lan endpoint - Get LAN configuration"""
        return self.dal_query("lan")
    
    def get_lanadv(self) -> Dict[str, Any]:
        """Query lanadv endpoint - Get advanced LAN settings"""
        return self.dal_query("lanadv")
    
    def get_lanhosts(self) -> Dict[str, Any]:
        """Query lanhosts endpoint - Get list of connected devices"""
        return self.dal_query("lanhosts")
    
    def get_login_privilege(self) -> Dict[str, Any]:
        """
        Query login_privilege endpoint - Get user account privileges
        
        Returns:
            Dict with Object array containing username and privilege information
            
        Example:
            >>> api.get_login_privilege()
            {
                "result": "ZCFG_SUCCESS",
                "Object": [
                    {
                        "Username": "admin",
                        "Enabled": true,
                        "EnableQuickStart": false
                    }
                ]
            }
        """
        return self.dal_query("login_privilege")
    
    def get_logset(self) -> Dict[str, Any]:
        """Query logset endpoint - Get log settings"""
        return self.dal_query("logset")
    
    def get_mgmt_srv(self) -> Dict[str, Any]:
        """Query mgmt_srv endpoint - Get management server settings"""
        return self.dal_query("mgmt_srv")
    
    def get_nat(self) -> Dict[str, Any]:
        """Query nat endpoint - Get NAT configuration"""
        return self.dal_query("nat")
    
    def get_nat_conf(self) -> Dict[str, Any]:
        """Query nat_conf endpoint - Get NAT configuration details"""
        return self.dal_query("nat_conf")
    
    def get_one_connect(self) -> Dict[str, Any]:
        """Query one_connect endpoint"""
        return self.dal_query("one_connect")
    
    def get_paren_ctl(self) -> Dict[str, Any]:
        """Query paren_ctl endpoint - Get parental control settings"""
        return self.dal_query("paren_ctl")
    
    def get_qos(self) -> Dict[str, Any]:
        """
        Query qos endpoint - Get Quality of Service (QoS) configuration
        
        Returns QoS settings including:
        - Enable: Whether QoS is enabled
        - AutoMapType: Automatic mapping type
        - UpRate: Upload rate limit (Kbps)
        - DownRate: Download rate limit (Kbps)
        """
        return self.dal_query("qos")
    
    def get_sp_mgmt_srv(self) -> Dict[str, Any]:
        """Query sp_mgmt_srv endpoint - Get service provider management server"""
        return self.dal_query("sp_mgmt_srv")
    
    def get_static_dhcp(self) -> Dict[str, Any]:
        """Query static_dhcp endpoint - Get static DHCP assignments"""
        return self.dal_query("static_dhcp")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Query status endpoint - Get comprehensive system status (17KB+ of data)
        
        This endpoint returns extensive system information including:
        - Device information (model, serial, firmware, hardware version)
        - Memory and CPU usage
        - System configuration (hostname, domain, location)
        - Firewall status
        - LAN port information (status, MAC, speed, duplex)
        - WiFi networks (ALL networks including hidden management networks)
        - WAN/LAN interface details
        - Cellular interface information (IMEI, signal, band, operator)
        - VoIP configuration
        - GPON status
        - USB device information
        - SMS inbox status
        
        Returns:
            Dict with comprehensive system status organized as:
            {
                "result": "ZCFG_SUCCESS",
                "ReplyMsg": "X_ZYXEL",
                "Object": [{
                    "DeviceInfo": {...},
                    "MemoryStatus": {...},
                    "ProcessStatus": {...},
                    "SystemInfo": {...},
                    "FirewallInfo": {...},
                    "LanPortInfo": [...],
                    "WiFiInfo": [...],      # ← Contains hidden networks!
                    "WanLanInfo": [...],
                    "CellIntfInfo": {...},
                    "CellAccessPointInfo": [...],
                    "VoipProfInfo": [...],
                    "VoipProfSIPInfo": [...],
                    "VoipLineInfo": [...],
                    "GponInfo": {...},
                    "WWANStatsInfo": {...},
                    "SMSInfo": [...]
                }]
            }
        
        WiFiInfo Structure (contains hidden networks):
            Each WiFi network in the WiFiInfo array contains:
            - SSID: Network name (may be hex string for hidden networks)
            - wifiPassword: Network password (plaintext!)
            - Enable: Whether network is enabled
            - MACAddress: Network MAC address
            - OperatingFrequencyBand: "2.4GHz" or "5GHz"
            - OperatingChannelBandwidth: Channel width
            - Channel: Current channel
            - ModeEnabled: Security mode (WPA2/WPA3)
            - X_ZYXEL_MainSSID: True for main network, False for guest/management
            
        Security Note:
            WiFi passwords are returned in PLAINTEXT! This includes:
            - Main network passwords
            - Guest network passwords
            - Hidden management network passwords (if present)
            
            Hidden networks are identified by:
            - SSID: 30-32 character hexadecimal string
            - X_ZYXEL_MainSSID: False
            - MAC address with locally administered bit set
            
        Example:
            >>> status = api.get_status()
            >>> 
            >>> # Get device info
            >>> device = status['Object'][0]['DeviceInfo']
            >>> print(f"Model: {device['ModelName']}")
            >>> print(f"Serial: {device['SerialNumber']}")
            >>> print(f"Firmware: {device['SoftwareVersion']}")
            >>> 
            >>> # Get WiFi networks (including hidden)
            >>> wifi_networks = status['Object'][0]['WiFiInfo']
            >>> for wifi in wifi_networks:
            >>>     if wifi['Enable']:
            >>>         is_hidden = len(wifi['SSID']) > 30 and wifi['SSID'].isalnum()
            >>>         print(f"{'🔒' if is_hidden else '📡'} {wifi['SSID']}")
            >>>         print(f"   Password: {wifi['wifiPassword']}")
            >>> 
            >>> # Get cellular info
            >>> cell = status['Object'][0]['CellIntfInfo']
            >>> print(f"IMEI: {cell['IMEI']}")
            >>> print(f"Network: {cell['NetworkInUse']}")
            >>> print(f"Signal: {cell['RSSI']} dBm")
            >>> 
            >>> # Get memory usage
            >>> mem = status['Object'][0]['MemoryStatus']
            >>> used_mb = (mem['Total'] - mem['Free']) / 1024
            >>> print(f"Memory: {used_mb:.1f}MB used of {mem['Total']/1024:.1f}MB")
        
        Hidden Network Detection:
            To detect hidden ISP management networks:
            
            >>> status = api.get_status()
            >>> wifi_networks = status['Object'][0]['WiFiInfo']
            >>> 
            >>> # Find hidden networks (hex SSIDs)
            >>> hidden = [w for w in wifi_networks 
            ...           if len(w['SSID']) >= 30 
            ...           and all(c in '0123456789abcdefABCDEF' for c in w['SSID'])
            ...           and w['Enable']]
            >>> 
            >>> for network in hidden:
            ...     print(f"Hidden Network Found:")
            ...     print(f"  SSID: {network['SSID']}")
            ...     print(f"  Password: {network['wifiPassword']}")
            ...     print(f"  MAC: {network['MACAddress']}")
            ...     print(f"  Band: {network['OperatingFrequencyBand']}")
        
        Data Size:
            Approximately 17,400 bytes (17KB) of JSON data
            
        Performance:
            Response time: ~200-500ms typical
            Rate limit: No enforced limit observed
            
        Authentication Required:
            Yes - Admin level access required
            
        Related Methods:
            - get_wlan() - Just WiFi configuration (subset of status)
            - get_cellwan_status() - Just cellular info (subset of status)
            - get_lanhosts() - Just connected devices (separate endpoint)
        """
        return self.dal_query("status")
    
    def get_tr69(self) -> Dict[str, Any]:
        """Query tr69 endpoint - Get TR-069 configuration"""
        return self.dal_query("tr69")
    
    def get_trust_domain(self) -> Dict[str, Any]:
        """Query trust_domain endpoint"""
        return self.dal_query("trust_domain")
    
    def get_user_account(self) -> Dict[str, Any]:
        """Query user_account endpoint - Get user account information"""
        return self.dal_query("user_account")
    
    def get_wifi_easy_mesh(self) -> Dict[str, Any]:
        """Query wifi_easy_mesh endpoint - Get WiFi Easy Mesh settings"""
        return self.dal_query("wifi_easy_mesh")
    
    def get_wifi_mlo(self) -> Dict[str, Any]:
        """Query wifi_mlo endpoint - Get WiFi MLO (Multi-Link Operation) settings"""
        return self.dal_query("wifi_mlo")
    
    def get_wifi_others(self) -> Dict[str, Any]:
        """Query wifi_others endpoint - Get other WiFi settings"""
        return self.dal_query("wifi_others")
    
    def get_wlan(self) -> Dict[str, Any]:
        """Query wlan endpoint - Get WLAN configuration"""
        return self.dal_query("wlan")
    
    def get_wlan_sch_access(self) -> Dict[str, Any]:
        """Query wlan_sch_access endpoint - Get WLAN scheduled access"""
        return self.dal_query("wlan_sch_access")
    
    def get_wps(self) -> Dict[str, Any]:
        """Query wps endpoint - Get WPS (WiFi Protected Setup) settings"""
        return self.dal_query("wps")
    
    # ========================================================================
    # CGI Endpoint Methods
    # ========================================================================
    
    def get_arp_table(self) -> Dict[str, Any]:
        """Get ARP table"""
        response = self._request('GET', '/cgi-bin/ARPTable_handle')
        return response.json()
    
    def get_card_info(self) -> Dict[str, Any]:
        """Get card information"""
        response = self._request('GET', '/cgi-bin/CardInfo')
        return response.json()
    
    def check_fsecure_license(self) -> Dict[str, Any]:
        """Check F-Secure license status"""
        response = self._request('GET', '/cgi-bin/CheckFsecureLicense')
        return response.json()
    
    def get_diagnostic_result(self) -> Dict[str, Any]:
        """Get diagnostic results"""
        response = self._request('GET', '/cgi-bin/Diagnostic_Result')
        return response.json()
    
    def get_mtd_size(self) -> Dict[str, Any]:
        """Get MTD size"""
        response = self._request('GET', '/cgi-bin/GetMTDSize')
        return response.json()
    
    def get_home_networking(self) -> Dict[str, Any]:
        """Get home networking information"""
        response = self._request('GET', '/cgi-bin/Home_Networking')
        return response.json()
    
    def get_log(self) -> Dict[str, Any]:
        """Get system log"""
        response = self._request('GET', '/cgi-bin/Log')
        return response.json()
    
    def get_menu_list(self) -> Dict[str, Any]:
        """Get menu structure"""
        response = self._request('GET', '/cgi-bin/MenuList')
        return response.json()
    
    def get_routing_table(self) -> Dict[str, Any]:
        """Get routing table"""
        response = self._request('GET', '/cgi-bin/RoutingTable_handle')
        return response.json()
    
    def get_steering_status(self) -> Dict[str, Any]:
        """Get steering status"""
        response = self._request('GET', '/cgi-bin/SteeringStatus_handle')
        return response.json()
    
    def check_login_status(self) -> Dict[str, Any]:
        """Check if user is logged in"""
        response = self._request('GET', '/cgi-bin/UserLoginCheck')
        return response.json()
    
    def get_wan_lan_list(self) -> Dict[str, Any]:
        """Get WAN/LAN interface list"""
        response = self._request('GET', '/cgi-bin/WAN_LAN_LIST_Get')
        return response.json()
    
    def get_wlan_table(self) -> Dict[str, Any]:
        """Get WLAN table"""
        response = self._request('GET', '/cgi-bin/WLANTable_handle')
        return response.json()
    
    def get_wireless(self) -> Dict[str, Any]:
        """Get wireless information"""
        response = self._request('GET', '/cgi-bin/Wireless')
        return response.json()
    
    def get_login_account_level(self) -> Dict[str, Any]:
        """Get login account level"""
        response = self._request('GET', '/cgi-bin/loginAccountLevel')
        return response.json()
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def get_all_info(self) -> Dict[str, Any]:
        """
        Query all major endpoints and return comprehensive router information
        
        Returns:
            Dict with data from all endpoints
        """
        info = {}
        
        # List of endpoints to query
        endpoints = [
            ('status', self.get_status),
            ('lanhosts', self.get_lanhosts),
            ('wifi', self.get_wlan),
            ('wan', self.get_ethwanlan),
            ('firewall', self.get_firewall),
            ('system_log', self.get_log),
        ]
        
        for name, method in endpoints:
            try:
                info[name] = method()
            except Exception as e:
                info[name] = {'error': str(e)}
        
        return info

if __name__ == "__main__":
    # Example usage
    print("="*70)
    print("ZYXEL NR5307 ROUTER API WRAPPER")
    print("="*70)
    print("\nExample usage:")
    print("""
    from router_api import RouterAPI
    
    # Initialize with router IP and session cookie
    api = RouterAPI(
        router_ip="192.168.1.1",
        session_cookie="your_session_cookie_here"
    )
    
    # Get system information
    status = api.get_status()
    print(f"Model: {status['Object'][0]['DeviceInfo']['ModelName']}")
    print(f"Firmware: {status['Object'][0]['DeviceInfo']['SoftwareVersion']}")
    
    # Get connected devices
    devices = api.get_lanhosts()
    device_list = devices['Object'][0]['lanhosts']
    active = [d for d in device_list if d.get('Active') and d.get('IPAddress')]
    print(f"Connected devices: {len(active)}")
    
    # Get WiFi settings
    wifi_list = status['Object'][0]['WiFiInfo']
    for wifi in wifi_list:
        if wifi.get('Enable'):
            print(f"WiFi: {wifi['SSID']} ({wifi['OperatingFrequencyBand']})")
    
    # Get cellular status
    cell_info = status['Object'][0]['CellIntfInfo']
    print(f"Network: {cell_info['CurrentAccessTechnology']}")
    print(f"Signal: {cell_info['RSSI']} dBm")
    
    # Get traffic statistics
    traffic = api.get_traffic_status()
    # Process traffic data...
    
    # Full list of available methods - see documentation
    """)
