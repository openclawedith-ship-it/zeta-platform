#!/usr/bin/env python3
"""
ZETA ∞ Vulnerability Scanner Engine
Combines nuclei, manual Python checks, and correlation
"""
import subprocess
import json
import os
from pathlib import Path
import importlib

class VulnScanner:
    """Autonomous vulnerability scanner with nuclei + manual checks"""
    
    def __init__(self):
        self.results = []
        self.tools = {}
        # Check available tools
        self.has_nuclei = os.system("which nuclei >/dev/null 2>&1") == 0
        self.has_ffuf = os.system("which ffuf >/dev/null 2>&1") == 0
        self.has_sqlmap = importlib.util.find_spec("sqlmap") is not None
        
    def scan_nuclei(self, target, severity_filter=None):
        """Run nuclei scan with optional severity filter"""
        if not self.has_nuclei:
            return {"error": "nuclei not available"}
        
        cmd = ["nuclei", "-target", target, "-json", "-silent", "-timeout", "30"]
        if severity_filter:
            cmd.extend(["-severity", severity_filter])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            findings = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        findings.append(json.loads(line))
                    except:
                        pass
            return {"tool": "nuclei", "findings": findings, "count": len(findings)}
        except Exception as e:
            return {"error": str(e)}
    
    def scan_headers(self, target):
        """Check for missing security headers"""
        import requests
        try:
            resp = requests.get(target, timeout=10, verify=False)
            headers = dict(resp.headers)
            missing = []
            required = {
                'Strict-Transport-Security': 'HSTS not set',
                'X-Content-Type-Options': 'X-Content-Type-Options missing',
                'X-Frame-Options': 'Clickjacking protection missing',
                'Content-Security-Policy': 'No CSP defined',
                'X-XSS-Protection': 'XSS protection header missing',
                'Referrer-Policy': 'Referrer policy not set',
                'Permissions-Policy': 'Permissions policy not set',
            }
            for header, issue in required.items():
                if header.lower() not in {h.lower() for h in headers}:
                    missing.append(issue)
            
            # Check for information leakage
            server = headers.get('Server', 'Unknown')
            x_powered_by = headers.get('X-Powered-By', '')
            
            findings = []
            for m in missing:
                findings.append({"severity": "INFO", "type": "missing_header", "detail": m})
            if x_powered_by:
                findings.append({"severity": "LOW", "type": "info_disclosure", "detail": f"X-Powered-By: {x_powered_by}"})
            if server != 'Unknown':
                findings.append({"severity": "INFO", "type": "info_disclosure", "detail": f"Server: {server}"})
            
            return {"findings": findings, "count": len(findings)}
        except Exception as e:
            return {"error": str(e)}
    
    def scan_sqli_basic(self, target):
        """Basic SQL injection test (safe, detection only)"""
        import requests
        payloads = [
            ("'", "single quote"),
            ("\"", "double quote"),
            (";--", "SQL comment"),
            ("' OR '1'='1", "OR boolean"),
        ]
        findings = []
        try:
            base = requests.get(target, timeout=10, verify=False).text
            for payload, desc in payloads:
                test_url = target.rstrip('/') + payload
                try:
                    resp = requests.get(test_url, timeout=10, verify=False, allow_redirects=False)
                    if resp.status_code != 200 and resp.status_code != 404:
                        findings.append({
                            "severity": "MEDIUM",
                            "type": "potential_sqli",
                            "detail": f"{desc} → status {resp.status_code}",
                            "payload": payload
                        })
                except:
                    pass
            return {"findings": findings, "count": len(findings)}
        except Exception as e:
            return {"error": str(e)}
    
    def scan_xss_basic(self, target):
        """Basic XSS reflection test"""
        import requests
        token = "ZETAXSS7392"
        try:
            resp = requests.get(f"{target}?q={token}", timeout=10, verify=False)
            if token in resp.text:
                return {
                    "findings": [{
                        "severity": "MEDIUM",
                        "type": "potential_xss",
                        "detail": f"Parameter 'q' reflects input"
                    }],
                    "count": 1
                }
            return {"findings": [], "count": 0}
        except Exception as e:
            return {"error": str(e)}
    
    def full_scan(self, target):
        """Run comprehensive vulnerability scan"""
        results = {}
        results["target"] = target
        results["nuclei"] = self.scan_nuclei(target)
        results["headers"] = self.scan_headers(target)
        results["sqli"] = self.scan_sqli_basic(target)
        results["xss"] = self.scan_xss_basic(target)
        
        total = sum(r.get("count", 0) for r in results.values() if isinstance(r, dict))
        results["summary"] = f"Total findings: {total}"
        
        return results

if __name__ == "__main__":
    import sys
    scanner = VulnScanner()
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    print(f"[*] Scanning: {target}")
    results = scanner.full_scan(target)
    print(json.dumps(results, indent=2))
