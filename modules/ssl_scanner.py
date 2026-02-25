"""SSL/TLS Security Scanner Module."""

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from .base import BaseScanner


class SSLScanner(BaseScanner):
    """Scan SSL/TLS configuration for security issues."""
    
    # Weak cipher suites to check
    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"
    ]
    
    # Deprecated protocols
    DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
    
    def scan(self) -> Dict[str, Any]:
        """Run SSL/TLS security scan."""
        results = {
            "status": "completed",
            "certificate": {},
            "protocols": {},
            "cipher_suites": [],
            "findings": [],
        }
        
        # Get certificate info
        cert_info = self._get_certificate()
        if cert_info:
            results["certificate"] = cert_info
            self._analyze_certificate(cert_info)
        else:
            results["status"] = "error"
            results["error"] = "Could not retrieve SSL certificate"
            self.add_finding(
                title="SSL Certificate Not Found",
                description=f"Could not retrieve SSL certificate from {self.target}:443",
                severity="high",
                remediation="Ensure HTTPS is properly configured on port 443."
            )
        
        # Check supported protocols
        results["protocols"] = self._check_protocols()
        
        # Check cipher suites
        results["cipher_suites"] = self._get_cipher_suites()
        
        results["findings"] = self.get_findings()
        return results
    
    def _get_certificate(self) -> Optional[Dict[str, Any]]:
        """Retrieve and parse SSL certificate."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            # Parse cert using cryptography library for reliable results
            cert_info = {
                "subject": {},
                "issuer": {},
                "serial_number": None,
                "not_before": None,
                "not_after": None,
                "san": [],
                "current_cipher": cipher[0] if cipher else None,
                "protocol_version": version,
            }
            
            # Use cryptography to parse the DER cert
            if HAS_CRYPTO and cert_der:
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Subject
                for attr in cert.subject:
                    cert_info["subject"][attr.oid._name] = attr.value
                
                # Issuer
                for attr in cert.issuer:
                    cert_info["issuer"][attr.oid._name] = attr.value
                
                cert_info["serial_number"] = str(cert.serial_number)
                cert_info["not_before"] = cert.not_valid_before_utc.isoformat()
                cert_info["not_after"] = cert.not_valid_after_utc.isoformat()
                
                # SAN
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    cert_info["san"] = [name.value for name in san_ext.value]
                except x509.ExtensionNotFound:
                    cert_info["san"] = []
                
                # Expiration
                now = datetime.now(timezone.utc)
                cert_info["expires_in_days"] = (cert.not_valid_after_utc - now).days
                cert_info["expired"] = cert_info["expires_in_days"] < 0
                
                # Key info
                pub_key = cert.public_key()
                cert_info["key_size"] = pub_key.key_size
                cert_info["signature_algorithm"] = cert.signature_algorithm_oid._name
                
                from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
                if isinstance(pub_key, rsa.RSAPublicKey):
                    cert_info["key_type"] = "RSA"
                elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                    cert_info["key_type"] = "ECDSA"
                    cert_info["curve"] = pub_key.curve.name
                elif isinstance(pub_key, dsa.DSAPublicKey):
                    cert_info["key_type"] = "DSA"
                else:
                    cert_info["key_type"] = "Unknown"
            
            return cert_info
            
        except socket.timeout:
            return None
        except ssl.SSLError as e:
            return None
        except Exception as e:
            return None
    
    def _analyze_certificate(self, cert: Dict[str, Any]):
        """Analyze certificate for security issues."""
        
        # Check expiration
        expires_in = cert.get("expires_in_days", 0)
        if cert.get("expired"):
            self.add_finding(
                title="SSL Certificate Expired",
                description=f"The SSL certificate expired {abs(expires_in)} days ago.",
                severity="critical",
                remediation="Renew the SSL certificate immediately."
            )
        elif expires_in <= 7:
            self.add_finding(
                title="SSL Certificate Expiring Soon",
                description=f"The SSL certificate expires in {expires_in} days.",
                severity="high",
                remediation="Renew the SSL certificate before expiration."
            )
        elif expires_in <= 30:
            self.add_finding(
                title="SSL Certificate Expiring",
                description=f"The SSL certificate expires in {expires_in} days.",
                severity="medium",
                remediation="Plan to renew the SSL certificate soon."
            )
        
        # Check key size
        key_size = cert.get("key_size", 0)
        key_type = cert.get("key_type", "RSA")
        
        # RSA keys need 2048+, ECDSA 256+ is fine
        if key_type == "RSA" and key_size and key_size < 2048:
            self.add_finding(
                title="Weak RSA Key Size",
                description=f"SSL certificate uses a {key_size}-bit RSA key, which is considered weak.",
                severity="high",
                remediation="Use at least 2048-bit RSA keys."
            )
        elif key_type == "ECDSA" and key_size and key_size < 256:
            self.add_finding(
                title="Weak ECDSA Key Size",
                description=f"SSL certificate uses a {key_size}-bit ECDSA key, which is considered weak.",
                severity="high",
                remediation="Use at least 256-bit ECDSA keys."
            )
        
        # Check signature algorithm
        sig_algo = cert.get("signature_algorithm", "").lower()
        if "sha1" in sig_algo or "md5" in sig_algo:
            self.add_finding(
                title="Weak Signature Algorithm",
                description=f"Certificate uses weak signature algorithm: {sig_algo}",
                severity="high",
                remediation="Use SHA-256 or stronger for certificate signing."
            )
        
        # Check if cert covers the domain
        san_list = cert.get("san", [])
        cn = cert.get("subject", {}).get("commonName", "")
        covered = False
        
        for name in san_list + [cn]:
            if name == self.target:
                covered = True
                break
            if name.startswith("*."):
                # Wildcard check
                wildcard_domain = name[2:]
                if self.target.endswith(wildcard_domain) and self.target.count(".") == name.count("."):
                    covered = True
                    break
        
        if not covered:
            self.add_finding(
                title="Certificate Domain Mismatch",
                description=f"Certificate does not cover {self.target}. Listed names: {san_list}",
                severity="high",
                remediation="Ensure the certificate includes the correct domain names."
            )
    
    def _check_protocols(self) -> Dict[str, bool]:
        """Check which SSL/TLS protocols are supported."""
        protocols = {
            "SSLv2": False,
            "SSLv3": False,
            "TLSv1": False,
            "TLSv1.1": False,
            "TLSv1.2": False,
            "TLSv1.3": False,
        }
        
        protocol_map = {
            "TLSv1.2": ssl.PROTOCOL_TLS,
            "TLSv1.3": ssl.PROTOCOL_TLS,
        }
        
        # Check TLS 1.2 and 1.3 (most common)
        for proto_name, proto_const in protocol_map.items():
            try:
                context = ssl.SSLContext(proto_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        version = ssock.version()
                        if version:
                            protocols[version] = True
            except Exception:
                pass
        
        # Flag deprecated protocols if detected
        for proto in self.DEPRECATED_PROTOCOLS:
            if protocols.get(proto):
                self.add_finding(
                    title=f"Deprecated Protocol Supported: {proto}",
                    description=f"{proto} is deprecated and has known vulnerabilities.",
                    severity="high" if proto in ["SSLv2", "SSLv3"] else "medium",
                    remediation=f"Disable {proto} and use TLS 1.2 or higher."
                )
        
        # Check if TLS 1.2+ is supported
        if not protocols.get("TLSv1.2") and not protocols.get("TLSv1.3"):
            self.add_finding(
                title="Modern TLS Not Supported",
                description="Neither TLS 1.2 nor TLS 1.3 appears to be supported.",
                severity="high",
                remediation="Enable TLS 1.2 and/or TLS 1.3 support."
            )
        
        return protocols
    
    def _get_cipher_suites(self) -> List[str]:
        """Get supported cipher suites."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cipher = ssock.cipher()
                    shared = ssock.shared_ciphers()
                    
                    ciphers = [cipher[0]] if cipher else []
                    if shared:
                        ciphers.extend([c[0] for c in shared])
                    
                    # Check for weak ciphers
                    for c in ciphers:
                        for weak in self.WEAK_CIPHERS:
                            if weak.lower() in c.lower():
                                self.add_finding(
                                    title=f"Weak Cipher Suite: {c}",
                                    description=f"The cipher suite {c} contains weak algorithms.",
                                    severity="medium",
                                    remediation="Disable weak cipher suites in your TLS configuration."
                                )
                                break
                    
                    return list(set(ciphers))
        except Exception:
            return []
