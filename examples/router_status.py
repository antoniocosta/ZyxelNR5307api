#!/usr/bin/env python3
"""
Display Complete Router Status

This script fetches and displays the complete JSON response from the
router's status endpoint (17KB+ of comprehensive system information).

Usage:
    python router_status.py
"""

import sys
import os
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.router_api import RouterAPI


def main():
    """Fetch and display complete router status"""
    
    print("=" * 70)
    print("Zyxel NR5307 - Complete Status Dump")
    print("=" * 70)
    print()
    
    # Authenticate
    try:
        print("[*] Authenticating...")
        api = RouterAPI.login_interactive()
        print("[✓] Authentication successful\n")
    except Exception as e:
        print(f"[!] Authentication failed: {e}")
        return 1
    
    # Get system status
    print("[*] Fetching system status (17KB+ of data)...")
    try:
        status = api.get_status()
        print("[✓] Status retrieved successfully\n")
    except Exception as e:
        print(f"[!] Failed to fetch status: {e}")
        return 1
    
    # Print complete JSON
    print("=" * 70)
    print("COMPLETE STATUS JSON:")
    print("=" * 70)
    print()
    print(json.dumps(status, indent=2))
    print()
    print("=" * 70)
    print("✅ Complete!")
    print("=" * 70)
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
