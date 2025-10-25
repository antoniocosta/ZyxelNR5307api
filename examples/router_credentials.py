#!/usr/bin/env python3
"""
Router Authentication Endpoints Test

Tests authentication and user-related endpoints.
Shows complete raw responses from each endpoint.
"""

import sys
import os
import json
from pathlib import Path

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import the API
sys.path.insert(0, str(Path(__file__).parent.parent / "api"))
from router_api import RouterAPI


def main():
    print("="*70)
    print("🔐 ROUTER AUTHENTICATION ENDPOINTS")
    print("="*70)
    print("\nShows raw responses from authentication-related endpoints.\n")
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
    
    print("\n" + "="*70)
    print("🧪 TESTING AUTH-RELATED ENDPOINTS")
    print("="*70)
    
    # Test auth-related endpoints
    tests = [
        {
            'name': 'login_privilege',
            'description': 'User login privileges',
            'method': lambda: api.get_login_privilege()
        },
        {
            'name': 'user_account',
            'description': 'User account information',
            'method': lambda: api.get_user_account()
        },
        {
            'name': 'check_login_status',
            'description': 'Current login session status',
            'method': lambda: api.check_login_status()
        }
    ]
    
    for test in tests:
        print("\n" + "─"*70)
        print(f"📡 ENDPOINT: {test['name']}")
        print("─"*70)
        print(f"   Description: {test['description']}\n")
        
        try:
            response = test['method']()
            
            print(f"   Response status: {response.get('result', 'N/A')}")
            print("\n   RAW RESPONSE:")
            
            # Pretty print the full response
            json_str = json.dumps(response, indent=2)
            for line in json_str.split('\n'):
                print('   ' + line)
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("\n" + "="*70)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
