#!/usr/bin/env python3
"""
Router Information Tool

Simple example showing how to get comprehensive router information.
All authentication is handled automatically by the API.
"""

import sys
import json
from pathlib import Path

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import the API
sys.path.insert(0, str(Path(__file__).parent.parent / "api"))
from router_api import RouterAPI


def main():
    # Handle command-line arguments
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
        print("="*70)
        print("📡 ZYXEL NR5307 API - ROUTER INFORMATION TOOL")
        print("="*70)
        print("\nUsage:")
        print("  python router_info.py              # Interactive login")
        print("  python router_info.py --help       # Show this help")
        print("\nEnvironment Variables:")
        print("  ROUTER_IP              Router IP address")
        print("  ROUTER_SESSION_COOKIE  Active session cookie (for automation)")
        print("  ROUTER_USERNAME        Username (if session not available)")
        print("  ROUTER_PASSWORD        Password (if session not available)")
        return 0
    
    print("="*70)
    print("📡 ZYXEL NR5307 API - ROUTER INFORMATION TOOL")
    print("="*70)
    
    # Initialize API with automatic authentication
    # This handles everything: saved credentials, env vars, or interactive prompts
    try:
        # Try environment variables first
        try:
            api = RouterAPI.from_env()
            print("\n✅ Authenticated using environment variables")
        except ValueError:
            # Fall back to saved credentials or interactive login
            try:
                api = RouterAPI.from_saved_credentials()
                print("\n✅ Authenticated using saved credentials")
            except ValueError:
                # Interactive login
                api = RouterAPI.login_interactive()
    except ValueError as e:
        print(f"\n❌ Authentication failed: {e}")
        return 1
    except KeyboardInterrupt:
        print("\n\n❌ Cancelled by user")
        return 1
    
    print("\n" + "="*70)
    print("🔌 CONNECTED TO ROUTER")
    print("="*70)
    print(f"   Router IP: {api.router_ip}")
    print(f"   Session: Active")
    
    print("\n" + "="*70)
    print("📊 ROUTER INFORMATION")
    print("="*70)
    
    # 1. Login Status
    print("\n" + "─"*70)
    print("🔐 LOGIN STATUS")
    print("─"*70)
    try:
        login_status = api.check_login_status()
        if login_status.get('result') == 'ZCFG_SUCCESS':
            level = login_status.get('loginLevel') or login_status.get('Level') or 'high'
            account = login_status.get('Account') or login_status.get('loginAccount') or 'admin'
            
            level_map = {
                'high': 'Administrator',
                'medium': 'User',
                'low': 'Guest',
                'supervisor': 'Supervisor'
            }
            level_display = level_map.get(level.lower(), level.title())
            
            print(f"   ✅ Connected as: {account}")
            print(f"   🎯 Privilege Level: {level_display}")
        else:
            print(f"   ⚠️  Status: {login_status.get('result', 'Unknown')}")
    except Exception as e:
        print(f"   ⚠️  Could not verify login status: {e}")
    
    # 2. System Information
    print("\n" + "─"*70)
    print("🖥️  SYSTEM INFORMATION")
    print("─"*70)
    try:
        status = api.get_status()
        
        if status.get('Object') and len(status['Object']) > 0:
            device_info = status['Object'][0].get('DeviceInfo', {})
            system_info = status['Object'][0].get('SystemInfo', {})
            
            model = device_info.get('ModelName', 'N/A')
            serial = device_info.get('SerialNumber', 'N/A')
            firmware = device_info.get('SoftwareVersion', 'N/A')
            hardware = device_info.get('HardwareVersion', 'N/A')
            uptime_sec = device_info.get('UpTime', 0)
            hostname = system_info.get('HostName', 'N/A')
            
            # Convert uptime to readable format
            days = uptime_sec // 86400
            hours = (uptime_sec % 86400) // 3600
            minutes = (uptime_sec % 3600) // 60
            uptime_str = f"{days}d {hours}h {minutes}m"
            
            print(f"   Model: {model}")
            print(f"   Hostname: {hostname}")
            print(f"   Serial Number: {serial}")
            print(f"   Firmware: {firmware}")
            print(f"   Hardware: {hardware}")
            print(f"   Uptime: {uptime_str}")
        else:
            print("   ⚠️  No system data available")
    except Exception as e:
        print(f"   ❌ Failed to get system info: {e}")
    
    # 3. Cellular WAN Status
    print("\n" + "─"*70)
    print("📡 CELLULAR STATUS")
    print("─"*70)
    try:
        status_response = api.get_status()
        
        if status_response.get('Object') and len(status_response['Object']) > 0:
            cell_info = status_response['Object'][0].get('CellIntfInfo', {})
            
            status_val = cell_info.get('Status', 'N/A')
            tech = cell_info.get('CurrentAccessTechnology', 'N/A')
            network = cell_info.get('NetworkInUse', 'N/A')
            rssi = cell_info.get('RSSI', 'N/A')
            rsrp = cell_info.get('X_ZYXEL_RSRP', 'N/A')
            rsrq = cell_info.get('X_ZYXEL_RSRQ', 'N/A')
            sinr = cell_info.get('X_ZYXEL_SINR', 'N/A')
            band = cell_info.get('X_ZYXEL_CurrentBand', 'N/A')
            imei = cell_info.get('IMEI', 'N/A')
            
            # Parse network string
            if network != 'N/A' and '_' in str(network):
                parts = str(network).split('_')
                operator = parts[1] if len(parts) > 1 else 'N/A'
            else:
                operator = network
            
            print(f"   Status: {status_val}")
            print(f"   Operator: {operator}")
            print(f"   Network: {tech} (Band {band})")
            print(f"   Signal Strength (RSSI): {rssi} dBm")
            print(f"   RSRP: {rsrp} dBm")
            print(f"   RSRQ: {rsrq} dB")
            print(f"   SINR: {sinr} dB")
            print(f"   IMEI: {imei}")
        else:
            print("   ⚠️  No cellular data available")
    except Exception as e:
        print(f"   ⚠️  Cellular info not available: {e}")
    
    # 4. WiFi Information
    print("\n" + "─"*70)
    print("📶 WiFi INFORMATION")
    print("─"*70)
    try:
        status = api.get_status()
        
        if status.get('Object') and len(status['Object']) > 0:
            wifi_list = status['Object'][0].get('WiFiInfo', [])
            main_networks = [w for w in wifi_list if w.get('Enable') and w.get('X_ZYXEL_MainSSID')]
            
            if main_networks:
                for idx, wifi in enumerate(main_networks, 1):
                    freq_band = wifi.get('OperatingFrequencyBand', 'N/A')
                    ssid = wifi.get('SSID', 'N/A')
                    enabled = wifi.get('Enable', False)
                    security = wifi.get('ModeEnabled', 'N/A')
                    channel = wifi.get('Channel', 'Auto')
                    bandwidth = wifi.get('OperatingChannelBandwidth', 'N/A')
                    standards = wifi.get('OperatingStandards', 'N/A')
                    rate = wifi.get('X_ZYXEL_Rate', 'N/A')
                    
                    print(f"\n   WiFi {idx} ({freq_band}):")
                    print(f"   • SSID: {ssid}")
                    print(f"   • Status: {'Enabled' if enabled else 'Disabled'}")
                    print(f"   • Security: {security}")
                    print(f"   • Channel: {channel} ({bandwidth})")
                    print(f"   • Standards: {standards}")
                    print(f"   • Max Rate: {rate}")
            else:
                print("   ⚠️  No active WiFi networks")
        else:
            print("   ⚠️  No WiFi data available")
    except Exception as e:
        print(f"   ❌ Failed to get WiFi info: {e}")
    
    # 5. Connected Devices
    print("\n" + "─"*70)
    print("🌐 CONNECTED DEVICES")
    print("─"*70)
    try:
        devices = api.get_lanhosts()
        
        if devices.get('Object') and len(devices['Object']) > 0:
            device_list = devices['Object'][0].get('lanhosts', [])
        else:
            device_list = []
        
        if not device_list:
            print("   ⚠️  No devices returned from API")
        else:
            active_devices = [d for d in device_list if d.get('Active') and d.get('IPAddress')]
            
            print(f"   Total Active Devices: {len(active_devices)}")
            
            if active_devices:
                print("\n   Connected Devices:")
                for device in active_devices[:10]:  # Show first 10
                    hostname = device.get('HostName', 'Unknown')
                    device_name = device.get('DeviceName', hostname)
                    cur_hostname = device.get('curHostName', '')
                    ip = device.get('IPAddress', 'N/A')
                    mac = device.get('PhysAddress', 'N/A')
                    connection = device.get('X_ZYXEL_ConnectionType', 'Unknown')
                    
                    display_name = cur_hostname or device_name
                    if not display_name or display_name == 'Unknown':
                        display_name = hostname
                    if display_name == 'Unknown':
                        display_name = f"Device-{mac[:8]}"
                    
                    print(f"   • {display_name:<30} {ip:<15} ({connection})")
                
                if len(active_devices) > 10:
                    print(f"\n   ... and {len(active_devices) - 10} more devices")
            else:
                print("   ⚠️  No active devices detected")
    except Exception as e:
        print(f"   ❌ Failed to get device list: {e}")
    
    print("\n" + "="*70)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
