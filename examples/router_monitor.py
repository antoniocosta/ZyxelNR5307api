#!/usr/bin/env python3
"""
Router Monitoring Example - N78 Band Quality Monitor

This script monitors the router's 5G N78 band signal quality in real-time.
Displays RSSI, RSRP, RSRQ, and SINR metrics with quality assessments.
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


# Signal Quality Evaluation Functions
def evaluate_rssi(rssi):
    """
    Evaluate RSSI (Received Signal Strength Indicator)
    Range: -50 (excellent) to -120 (very poor) dBm
    """
    if rssi >= -65:
        return "Excellent", "🟢"
    elif rssi >= -75:
        return "Good", "🟢"
    elif rssi >= -85:
        return "Fair", "🟡"
    elif rssi >= -95:
        return "Poor", "🟠"
    else:
        return "Very Poor", "🔴"


def draw_rssi_bar(rssi):
    """Draw RSSI quality bar with filled indicator"""
    bar_width = 62
    min_val, max_val = -120, -50
    
    # Calculate position (0 to bar_width)
    if rssi <= min_val:
        position = 0
    elif rssi >= max_val:
        position = bar_width
    else:
        position = int((rssi - min_val) / (max_val - min_val) * bar_width)
    
    # Create bar with filled portion
    bar = "❚" * position + "─" * (bar_width - position)
    
    # Thresholds: -96, -85, -75, -65 (perfectly aligned)
    return f"   {bar}\n   -120          -96            -85            -75              -65\n   Very Poor     Poor           Fair           Good        Excellent"


def draw_rsrp_bar(rsrp):
    """Draw RSRP quality bar with filled indicator"""
    bar_width = 62
    min_val, max_val = -140, -44
    
    # Calculate position
    if rsrp <= min_val:
        position = 0
    elif rsrp >= max_val:
        position = bar_width
    else:
        position = int((rsrp - min_val) / (max_val - min_val) * bar_width)
    
    # Create bar with filled portion
    bar = "❚" * position + "─" * (bar_width - position)
    
    # Thresholds: -110, -100, -90, -80 (perfectly aligned)
    return f"   {bar}\n   -140          -110           -100           -90              -80\n   Very Poor     Poor           Fair           Good        Excellent"


def draw_rsrq_bar(rsrq):
    """Draw RSRQ quality bar with filled indicator"""
    bar_width = 62
    min_val, max_val = -20, -3
    
    # Calculate position
    if rsrq <= min_val:
        position = 0
    elif rsrq >= max_val:
        position = bar_width
    else:
        position = int((rsrq - min_val) / (max_val - min_val) * bar_width)
    
    # Create bar with filled portion
    bar = "❚" * position + "─" * (bar_width - position)
    
    # Thresholds: -16, -12, -9, -3 (perfectly aligned)
    return f"   {bar}\n   -20           -16            -12            -9                -3\n   Very Poor     Poor           Fair           Good        Excellent"


def draw_sinr_bar(sinr):
    """Draw SINR quality bar with filled indicator"""
    bar_width = 62
    min_val, max_val = -10, 30
    
    # Calculate position
    if sinr <= min_val:
        position = 0
    elif sinr >= max_val:
        position = bar_width
    else:
        position = int((sinr - min_val) / (max_val - min_val) * bar_width)
    
    # Create bar with filled portion
    bar = "❚" * position + "─" * (bar_width - position)
    
    # Thresholds: 0, 13, 20, 30 (perfectly aligned)
    return f"   {bar}\n   -10           0              13             20               30+\n   Very Poor     Poor           Fair           Good        Excellent"


def evaluate_rsrp(rsrp):
    """
    Evaluate RSRP (Reference Signal Received Power)
    Best indicator of 4G/5G coverage strength
    Range: -44 (max) to -140 (min) dBm
    """
    if rsrp >= -80:
        return "Excellent", "🟢"
    elif rsrp >= -90:
        return "Good", "🟢"
    elif rsrp >= -100:
        return "Fair", "🟡"
    elif rsrp >= -110:
        return "Poor", "🟠"
    else:
        return "Very Poor", "🔴"


def evaluate_rsrq(rsrq):
    """
    Evaluate RSRQ (Reference Signal Received Quality)
    Reflects interference and load
    Range: -3 (excellent) to -20 (bad) dB
    """
    if rsrq >= -9:
        return "Excellent", "🟢"
    elif rsrq >= -12:
        return "Fair", "🟡"
    elif rsrq >= -15:
        return "Poor", "🟠"
    else:
        return "Very Poor", "🔴"


def evaluate_sinr(sinr):
    """
    Evaluate SINR (Signal-to-Interference plus Noise Ratio)
    Most important for actual throughput
    Range: <0 (unusable) to 20+ (excellent)
    """
    if sinr >= 20:
        return "Excellent", "🟢"
    elif sinr >= 13:
        return "Good", "🟢"
    elif sinr >= 0:
        return "Fair", "🟡"
    else:
        return "Poor/Unusable", "🔴"


def get_overall_quality(rsrp, rsrq, sinr):
    """
    Calculate overall signal quality based on key metrics
    SINR is weighted most heavily as it's the real throughput indicator
    """
    # Score each metric
    rsrp_score = 0
    if rsrp >= -80: rsrp_score = 4
    elif rsrp >= -90: rsrp_score = 3
    elif rsrp >= -100: rsrp_score = 2
    elif rsrp >= -110: rsrp_score = 1
    
    rsrq_score = 0
    if rsrq >= -9: rsrq_score = 4
    elif rsrq >= -12: rsrq_score = 3
    elif rsrq >= -15: rsrq_score = 2
    else: rsrq_score = 1
    
    sinr_score = 0
    if sinr >= 20: sinr_score = 4
    elif sinr >= 13: sinr_score = 3
    elif sinr >= 0: sinr_score = 2
    else: sinr_score = 1
    
    # Weight SINR more heavily (50%), RSRP (30%), RSRQ (20%)
    overall = (sinr_score * 0.5) + (rsrp_score * 0.3) + (rsrq_score * 0.2)
    
    if overall >= 3.5:
        return "Excellent - Full 5G speeds possible", "🟢"
    elif overall >= 2.5:
        return "Good - Strong throughput", "🟢"
    elif overall >= 1.5:
        return "Fair - Limited throughput", "🟡"
    else:
        return "Poor - Weak signal, consider repositioning", "🔴"


def main():
    print("="*70)
    print("📶 5G N78 BAND QUALITY MONITOR")
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
            
            # 1. Get cellular WAN status
            try:
                cellwan_response = api.get_cellwan_status()
                
                if cellwan_response.get('Object') and len(cellwan_response['Object']) > 0:
                    cell_data = cellwan_response['Object'][0]
                    
                    # Extract basic info (note the INTF_ prefix)
                    operator = cell_data.get('INTF_Network_In_Use', 'N/A')
                    technology = cell_data.get('INTF_Current_Access_Technology', 'N/A')
                    primary_band = cell_data.get('INTF_Current_Band', 'N/A')
                    
                    # Check for N78 in NSA (Non-Standalone Access) mode
                    nsa_band = cell_data.get('NSA_Band', '')
                    nsa_enabled = cell_data.get('NSA_Enable', False)
                    
                    print(f"\n📡 Network Information:\n")
                    print(f"   Operator: {operator}")
                    print(f"   Technology: {technology}")
                    print(f"   Primary Band: {primary_band}")
                    if nsa_enabled and nsa_band:
                        print(f"   5G NSA Band: {nsa_band}")
                    
                    # Check if we have N78 band data (in NSA mode or SCC_Info)
                    has_n78 = nsa_enabled and nsa_band == 'N78'
                    
                    # Extract N78 signal metrics from NSA fields
                    if has_n78:
                        rssi = cell_data.get('NSA_RSRP')  # NSA doesn't have separate RSSI, use RSRP
                        rsrp = cell_data.get('NSA_RSRP')
                        rsrq = cell_data.get('NSA_RSRQ')
                        sinr = cell_data.get('NSA_SINR')
                        
                        # Also check SCC_Info for potentially better N78 data
                        scc_info = cell_data.get('SCC_Info', [])
                        for scc in scc_info:
                            if scc.get('Band') == 'N78' and scc.get('Enable'):
                                # Use SCC data if available (might be more accurate)
                                rssi = scc.get('RSSI')
                                rsrp = scc.get('RSRP')
                                rsrq = scc.get('RSRQ')
                                sinr = scc.get('SINR')
                                break
                    else:
                        # Fallback to primary interface metrics
                        rssi = cell_data.get('INTF_RSSI')
                        rsrp = cell_data.get('INTF_RSRP')
                        rsrq = cell_data.get('INTF_RSRQ')
                        sinr = cell_data.get('INTF_SINR')
                    
                    # Display N78 band quality if available
                    if has_n78:
                        print(f"\n📶 N78 Band Signal Quality:\n")
                        
                        # Display metrics with quality assessment (all aligned)
                        if rssi is not None:
                            try:
                                rssi_val = int(rssi)
                                quality, emoji = evaluate_rssi(rssi_val)
                                # Right-align description to 26 chars
                                print(f"   RSSI: {rssi_val:4d} dBm  {emoji} {quality:15s}  {'(Total received power)':>26}")
                                print(draw_rssi_bar(rssi_val))
                            except (ValueError, TypeError):
                                print(f"   RSSI: {rssi} dBm (Unable to evaluate)")
                        else:
                            print(f"   RSSI: N/A")
                        
                        print()  # Spacing
                        
                        if rsrp is not None:
                            try:
                                rsrp_val = int(rsrp)
                                quality, emoji = evaluate_rsrp(rsrp_val)
                                # Right-align description to 26 chars
                                print(f"   RSRP: {rsrp_val:4d} dBm  {emoji} {quality:15s}  {'(Coverage strength)':>26}")
                                print(draw_rsrp_bar(rsrp_val))
                            except (ValueError, TypeError):
                                print(f"   RSRP: {rsrp} dBm (Unable to evaluate)")
                        else:
                            print(f"   RSRP: N/A")
                        
                        print()  # Spacing
                        
                        if rsrq is not None:
                            try:
                                rsrq_val = int(rsrq)
                                quality, emoji = evaluate_rsrq(rsrq_val)
                                # Right-align description to 26 chars
                                print(f"   RSRQ: {rsrq_val:4d} dB   {emoji} {quality:15s}  {'(Signal quality)':>26}")
                                print(draw_rsrq_bar(rsrq_val))
                            except (ValueError, TypeError):
                                print(f"   RSRQ: {rsrq} dB (Unable to evaluate)")
                        else:
                            print(f"   RSRQ: N/A")
                        
                        print()  # Spacing
                        
                        if sinr is not None:
                            try:
                                sinr_val = int(sinr)
                                quality, emoji = evaluate_sinr(sinr_val)
                                # Right-align description to 26 chars
                                print(f"   SINR: {sinr_val:4d} dB   {emoji} {quality:15s}  {'(Throughput indicator)':>26}")
                                print(draw_sinr_bar(sinr_val))
                            except (ValueError, TypeError):
                                print(f"   SINR: {sinr} dB (Unable to evaluate)")
                        else:
                            print(f"   SINR: N/A")
                        
                        # Overall assessment
                        if rsrp is not None and rsrq is not None and sinr is not None:
                            try:
                                rsrp_val = int(rsrp)
                                rsrq_val = int(rsrq)
                                sinr_val = int(sinr)
                                overall, emoji = get_overall_quality(rsrp_val, rsrq_val, sinr_val)
                                print(f"\n   {emoji} Overall: {overall}")
                            except (ValueError, TypeError):
                                pass
                        
                        # Ideal target ranges - removed since bars now show thresholds
                        
                        # Recommendations based on metrics
                        recommendations = []
                        if rsrp is not None and int(rsrp) < -100:
                            recommendations.append("• Weak coverage - consider antenna position/orientation")
                        if rsrq is not None and int(rsrq) < -12:
                            recommendations.append("• High interference - check for obstructions or congestion")
                        if sinr is not None and int(sinr) < 13:
                            recommendations.append("• Low SINR - throughput will be limited")
                        
                        if recommendations:
                            print(f"\n   💡 Recommendations:")
                            for rec in recommendations:
                                print(f"      {rec}")
                    else:
                        print(f"\n⚠️  Not currently on N78 band")
                        print(f"   Current primary band: {primary_band}")
                        if nsa_band:
                            print(f"   NSA band: {nsa_band} (not N78)")
                        print(f"   (Monitoring N78 band only)")
                        
                        # Still show current signal if available
                        if rssi is not None or rsrp is not None or rsrq is not None or sinr is not None:
                            print(f"\n   Current Signal Metrics:")
                            if rssi is not None: print(f"   RSSI: {rssi} dBm")
                            if rsrp is not None: print(f"   RSRP: {rsrp} dBm")
                            if rsrq is not None: print(f"   RSRQ: {rsrq} dB")
                            if sinr is not None: print(f"   SINR: {sinr} dB")
                else:
                    print(f"\n⚠️  Unable to retrieve cellular WAN status")
                    
            except Exception as e:
                print(f"\n⚠️  Cellular status check failed: {e}")
            
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
                        print(f"\n📊 Traffic Status:\n")
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
                            
                            print(f"\n📊 Traffic Status:\n")
                            print(f"   ↓ Download: {download_str}")
                            print(f"   ↑ Upload: {upload_str}")
                        else:
                            print(f"\n📊 Traffic Status:\n")
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
                    
                    print(f"\n🌐 Connected Devices: {len(active_devices)}\n")
                    
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
                    print(f"\n🌐 Connected Devices: 0\n")
                    
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
