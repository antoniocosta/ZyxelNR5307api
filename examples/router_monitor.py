#!/usr/bin/env python3
"""
Router Monitoring Example

This script monitors the router's status and connected devices in real-time.
Press Ctrl+C to stop monitoring.
"""

import sys
import time
from pathlib import Path

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "api"))
from router_api import RouterAPI


def main():
    print("="*70)
    print("📊 ROUTER MONITORING")
    print("="*70)
    
    # Initialize API with automatic authentication
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
    
    print("\n🔄 Press Ctrl+C to stop monitoring")
    print("="*70)
    
    # Track bandwidth
    prev_traffic = None
    prev_time = None
    
    try:
        while True:
            print("\n" + "="*70)
            print(f"⏰ {time.strftime('%H:%M:%S')}")
            print("="*70)
            
            # 1. System Status
            try:
                status_response = api.get_status()
                
                if status_response.get('Object') and len(status_response['Object']) > 0:
                    device_info = status_response['Object'][0].get('DeviceInfo', {})
                    
                    model = device_info.get('ModelName', 'N/A')
                    uptime_sec = device_info.get('UpTime', 0)
                    
                    # Convert uptime
                    days = uptime_sec // 86400
                    hours = (uptime_sec % 86400) // 3600
                    minutes = (uptime_sec % 3600) // 60
                    uptime_str = f"{days}d {hours}h {minutes}m"
                    
                    print(f"\n📊 System Status:")
                    print(f"   Model: {model}")
                    print(f"   Uptime: {uptime_str}")
                else:
                    print(f"\n📊 System Status: Unable to retrieve")
            except Exception as e:
                print(f"\n⚠️  Status check failed: {e}")
            
            # 2. Get traffic statistics
            try:
                traffic_response = api.get_traffic_status()
                current_time = time.time()
                
                if traffic_response.get('Object') and len(traffic_response['Object']) > 0:
                    obj = traffic_response['Object'][0]
                    
                    # Get ipIface and ipIfaceSt lists
                    ip_ifaces = obj.get('ipIface', [])
                    ip_iface_stats = obj.get('ipIfaceSt', [])
                    
                    # Find the primary WAN interface and sum its traffic
                    sent_bytes = 0
                    received_bytes = 0
                    
                    for idx, iface in enumerate(ip_ifaces):
                        # Only count WAN interfaces that are up
                        if (iface.get('Status') == 'Up' and 
                            iface.get('Name') == 'WAN' and
                            idx < len(ip_iface_stats)):
                            
                            stats = ip_iface_stats[idx]
                            sent_bytes += stats.get('BytesSent', 0)
                            received_bytes += stats.get('BytesReceived', 0)
                    
                    if not prev_traffic:
                        # First iteration - store baseline
                        print(f"\n📊 Traffic Status:")
                        print(f"   (Calculating...)")
                        
                        prev_traffic = {
                            'sent': sent_bytes,
                            'received': received_bytes
                        }
                        prev_time = current_time
                    else:
                        # Calculate speed
                        time_diff = current_time - prev_time
                        
                        if time_diff > 0 and sent_bytes > 0 and received_bytes > 0:
                            # Calculate bytes per second
                            sent_diff = sent_bytes - prev_traffic['sent']
                            received_diff = received_bytes - prev_traffic['received']
                            
                            # Handle counter rollover
                            if sent_diff < 0:
                                sent_diff = 0
                            if received_diff < 0:
                                received_diff = 0
                            
                            # Convert to Mbps
                            upload_mbps = (sent_diff / time_diff * 8) / 1_000_000
                            download_mbps = (received_diff / time_diff * 8) / 1_000_000
                            
                            # Format for display
                            if download_mbps >= 1:
                                download_str = f"{download_mbps:.2f} Mbps"
                            else:
                                download_kbps = download_mbps * 1000
                                download_str = f"{download_kbps:.1f} Kbps"
                            
                            if upload_mbps >= 1:
                                upload_str = f"{upload_mbps:.2f} Mbps"
                            else:
                                upload_kbps = upload_mbps * 1000
                                upload_str = f"{upload_kbps:.1f} Kbps"
                            
                            print(f"\n📊 Traffic Status:")
                            print(f"   ↓ Download: {download_str}")
                            print(f"   ↑ Upload: {upload_str}")
                        else:
                            print(f"\n📊 Traffic Status:")
                            print(f"   (No traffic detected)")
                        
                        # Store current values
                        prev_traffic = {
                            'sent': sent_bytes,
                            'received': received_bytes
                        }
                        prev_time = current_time
                        
            except Exception as e:
                print(f"\n⚠️  Traffic status failed: {e}")
            
            # 3. Connected Devices
            try:
                devices_response = api.get_lanhosts()
                
                if devices_response.get('Object') and len(devices_response['Object']) > 0:
                    device_list = devices_response['Object'][0].get('lanhosts', [])
                    active_devices = [d for d in device_list if d.get('Active') and d.get('IPAddress')]
                    
                    print(f"\n🌐 Connected Devices: {len(active_devices)}")
                    
                    if active_devices:
                        for i, device in enumerate(active_devices[:10], 1):
                            hostname = device.get('curHostName') or device.get('DeviceName') or device.get('HostName', 'Unknown')
                            ip = device.get('IPAddress', 'N/A')
                            connection = device.get('X_ZYXEL_ConnectionType', 'Unknown')
                            
                            if hostname == 'Unknown':
                                mac = device.get('PhysAddress', 'N/A')
                                hostname = f"Device-{mac[:8]}"
                            
                            print(f"   {i}. {hostname} - {ip} ({connection})")
                        
                        if len(active_devices) > 10:
                            print(f"   ... and {len(active_devices) - 10} more")
                else:
                    print(f"\n🌐 Connected Devices: 0")
                    
            except Exception as e:
                print(f"\n⚠️  Device list failed: {e}")
            
            # Wait before next update
            print("\n⏳ Refreshing in 10 seconds...")
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\n\n" + "="*70)
        print("👋 Monitoring stopped")
        print("="*70)
        return 0


if __name__ == "__main__":
    sys.exit(main())
