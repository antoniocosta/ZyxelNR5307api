#!/usr/bin/env python3
"""
Authentication and Session Management for Zyxel Router API

Handles login, credential storage, and session management.
"""

import os
import json
import stat
import base64
import getpass
import requests
from pathlib import Path
from typing import Optional, Dict, Tuple

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default credentials file location
DEFAULT_CREDENTIALS_FILE = Path.home() / ".zyxel_router"


class CredentialStore:
    """Manages secure storage of router credentials"""
    
    def __init__(self, credentials_file: Optional[Path] = None):
        """
        Initialize credential store
        
        Args:
            credentials_file: Path to credentials file (default: ~/.zyxel_router)
        """
        self.credentials_file = credentials_file or DEFAULT_CREDENTIALS_FILE
    
    def save(self, router_ip: str, username: str, password: str, 
             session_cookie: Optional[str] = None) -> bool:
        """
        Save credentials to file with secure permissions
        
        Args:
            router_ip: Router IP address
            username: Username
            password: Password
            session_cookie: Optional session cookie
            
        Returns:
            True if saved successfully
        """
        try:
            credentials = {
                "router_ip": router_ip,
                "username": username,
                "password": password,
                "session_cookie": session_cookie
            }
            
            # Write to file
            with open(self.credentials_file, 'w') as f:
                json.dump(credentials, f, indent=2)
            
            # Set permissions to 600 (rw for user only)
            os.chmod(self.credentials_file, stat.S_IRUSR | stat.S_IWUSR)
            
            return True
        except Exception as e:
            print(f"⚠️  Could not save credentials: {e}")
            return False
    
    def load(self) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Load credentials from file
        
        Returns:
            Tuple of (router_ip, username, password, session_cookie)
        """
        try:
            if not self.credentials_file.exists():
                return None, None, None, None
            
            # Check file permissions
            file_stat = os.stat(self.credentials_file)
            if file_stat.st_mode & 0o077:  # Others have permissions
                print(f"⚠️  Warning: {self.credentials_file} has insecure permissions")
                print(f"   Run: chmod 600 {self.credentials_file}")
            
            with open(self.credentials_file, 'r') as f:
                credentials = json.load(f)
            
            return (
                credentials.get('router_ip'),
                credentials.get('username'),
                credentials.get('password'),
                credentials.get('session_cookie')
            )
        except Exception:
            return None, None, None, None
    
    def delete(self) -> bool:
        """Delete saved credentials file"""
        try:
            if self.credentials_file.exists():
                self.credentials_file.unlink()
                return True
        except Exception as e:
            print(f"⚠️  Could not delete credentials: {e}")
        return False
    
    def exists(self) -> bool:
        """Check if credentials file exists"""
        return self.credentials_file.exists()


def login_to_router(router_ip: str, username: str, password: str, 
                    use_https: bool = True) -> Optional[str]:
    """
    Login to router and get session cookie
    
    Args:
        router_ip: Router IP address
        username: Username (usually 'admin')
        password: Password
        use_https: Try HTTPS first (default: True)
        
    Returns:
        Session cookie string or None if login failed
    """
    # Encode password to base64
    password_b64 = base64.b64encode(password.encode()).decode()
    
    # Login payload
    login_data = {
        "Input_Account": username,
        "Input_Passwd": password_b64,
        "currLang": "en",
        "RememberPassword": 0,
        "SHA512_password": False
    }
    
    # Try protocols in order of preference
    protocols = ['https', 'http'] if use_https else ['http', 'https']
    
    for protocol in protocols:
        try:
            url = f"{protocol}://{router_ip}/UserLogin"
            
            response = requests.post(
                url,
                json=login_data,
                verify=False,
                timeout=10,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0'
                }
            )
            
            if response.status_code == 200:
                session_cookie = response.cookies.get('Session')
                
                if session_cookie:
                    return session_cookie
                else:
                    # Check response for error
                    try:
                        data = response.json()
                        if data.get('result') != 'ZCFG_SUCCESS':
                            # Login failed (wrong credentials)
                            return None
                    except:
                        pass
            
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except Exception:
            continue
    
    # Could not connect via any protocol
    return None


class AuthManager:
    """High-level authentication manager"""
    
    def __init__(self, credentials_file: Optional[Path] = None):
        """
        Initialize auth manager
        
        Args:
            credentials_file: Path to credentials file
        """
        self.store = CredentialStore(credentials_file)
    
    def login(self, router_ip: str, username: str, password: str,
              save_credentials: bool = False, use_https: bool = True) -> Optional[str]:
        """
        Login to router and optionally save credentials
        
        Args:
            router_ip: Router IP address
            username: Username
            password: Password
            save_credentials: Save credentials to file
            use_https: Use HTTPS (default: True)
            
        Returns:
            Session cookie or None if login failed
        """
        session_cookie = login_to_router(router_ip, username, password, use_https)
        
        if session_cookie and save_credentials:
            self.store.save(router_ip, username, password, session_cookie)
        
        return session_cookie
    
    def login_from_saved(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Login using saved credentials
        
        Returns:
            Tuple of (router_ip, session_cookie, use_https)
        """
        router_ip, username, password, saved_session = self.store.load()
        
        if not router_ip or not username or not password:
            return None, None, None
        
        # Try to reuse existing session first
        if saved_session:
            return router_ip, saved_session, True
        
        # Login and get new session
        session_cookie = login_to_router(router_ip, username, password)
        
        if session_cookie:
            # Update stored session
            self.store.save(router_ip, username, password, session_cookie)
            return router_ip, session_cookie, True
        
        return None, None, None
    
    def login_from_env(self) -> Tuple[Optional[str], Optional[str], bool]:
        """
        Login using environment variables
        
        Environment variables:
            ROUTER_IP: Router IP address
            ROUTER_SESSION_COOKIE: Session cookie (if available)
            ROUTER_USERNAME: Username (if session not available)
            ROUTER_PASSWORD: Password (if session not available)
        
        Returns:
            Tuple of (router_ip, session_cookie, use_https)
        """
        router_ip = os.getenv('ROUTER_IP', '192.168.1.1')
        session_cookie = os.getenv('ROUTER_SESSION_COOKIE')
        
        if session_cookie:
            # Use provided session cookie
            return router_ip, session_cookie, True
        
        # Try to login with username/password from env
        username = os.getenv('ROUTER_USERNAME')
        password = os.getenv('ROUTER_PASSWORD')
        
        if username and password:
            session_cookie = login_to_router(router_ip, username, password)
            if session_cookie:
                return router_ip, session_cookie, True
        
        return None, None, False
    
    def login_interactive(self, save_prompt: bool = True) -> Tuple[Optional[str], Optional[str], bool]:
        """
        Interactive login with prompts
        
        Args:
            save_prompt: Prompt user to save credentials
            
        Returns:
            Tuple of (router_ip, session_cookie, use_https)
        """
        # Check for saved credentials
        saved_ip, saved_user, saved_pass, saved_session = self.store.load()
        
        if saved_ip and saved_user:
            print(f"\n💾 Found saved credentials for {saved_user}@{saved_ip}")
            use_saved = input("Use saved credentials? (yes/no) [yes]: ").strip().lower()
            
            if use_saved != 'no':
                router_ip = saved_ip
                username = saved_user
                password = saved_pass
                
                # Try saved session first
                if saved_session:
                    print(f"   🔄 Trying saved session...")
                    return router_ip, saved_session, True
                
                print(f"   ✅ Using saved credentials")
            else:
                router_ip = input(f"Router IP [{saved_ip}]: ").strip() or saved_ip
                username = input(f"Username [{saved_user}]: ").strip() or saved_user
                password = getpass.getpass("Password: ").strip()
        else:
            if save_prompt:
                print("\n⚠️  Your credentials will NOT be stored by default.")
                print("   (You'll be asked if you want to save them after login)\n")
            
            print("📋 Enter Router Credentials:\n")
            router_ip = input("Router IP [192.168.1.1]: ").strip() or "192.168.1.1"
            username = input("Username [admin]: ").strip() or "admin"
            password = getpass.getpass("Password: ").strip()
        
        if not password:
            print("\n❌ Password is required")
            return None, None, False
        
        # Login
        print(f"\n🔄 Logging in as '{username}' to {router_ip}...")
        session_cookie = login_to_router(router_ip, username, password)
        
        if not session_cookie:
            print("\n❌ Login failed!")
            print("\n💡 Troubleshooting:")
            print(f"   • Verify router IP is correct: {router_ip}")
            print("   • Check username and password")
            print(f"   • Try accessing router in browser: http://{router_ip}")
            return None, None, False
        
        print(f"   ✅ Login successful!")
        
        # Ask to save credentials
        if save_prompt and not (saved_ip and saved_user and saved_pass):
            print(f"\n💾 Save credentials for future use?")
            print(f"   (Stored in {self.store.credentials_file} with permissions 600)")
            save = input("   Save? (yes/no) [no]: ").strip().lower()
            
            if save == 'yes':
                if self.store.save(router_ip, username, password, session_cookie):
                    print("   ✅ Credentials saved")
                    print("   💡 Next time you run this, it won't ask for password")
        elif saved_ip and saved_user and saved_pass:
            # Update existing credentials with new session
            self.store.save(router_ip, username, password, session_cookie)
        
        return router_ip, session_cookie, True


# Convenience functions
def get_session_interactive() -> Tuple[Optional[str], Optional[str]]:
    """
    Interactive session acquisition
    
    Returns:
        Tuple of (router_ip, session_cookie)
    """
    auth = AuthManager()
    router_ip, session_cookie, _ = auth.login_interactive()
    return router_ip, session_cookie


def get_session_from_env() -> Tuple[Optional[str], Optional[str]]:
    """
    Get session from environment variables
    
    Returns:
        Tuple of (router_ip, session_cookie)
    """
    auth = AuthManager()
    router_ip, session_cookie, _ = auth.login_from_env()
    return router_ip, session_cookie
