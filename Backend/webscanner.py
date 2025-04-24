import os
import socket
import select
import requests
import datetime
import OpenSSL
import re
import certifi
import hashlib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import init
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import time

init()

# ------------------ Individual Scanner Functions ------------------

def port_scan(target, start_port=20, end_port=100):
    open_ports = []
    try:
        target_ip = socket.gethostbyname(target)
        for port in range(start_port, end_port + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if sock.connect_ex((target_ip, port)) == 0:
                    open_ports.append(port)
    except:
        pass
    return open_ports

def get_all_forms(url):
    try:
        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36"
        res = session.get(url, timeout=5)
        res.raise_for_status()
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        return []



'''def check_headers(url):
    """
    Analyzes HTTP response headers for security configurations.
    Prints details of each security header on separate lines, including status and recommendations.
    """
    def analyze_header(header_name, header_value, headers):
        """
        Analyzes a specific header and returns a list of details (status, value, recommendation).
        """
        details = []
        header_lower = header_name.lower()

        if header_lower == "content-security-policy":
            if not header_value:
                details.append(f"Content-Security-Policy: Missing")
                details.append(f"Recommendation: Implement CSP to control resource loading (e.g., 'default-src \"self\"')")
            else:
                details.append(f"Content-Security-Policy: Present")
                details.append(f"Value: {header_value}")
                if "default-src" not in header_value:
                    details.append("Recommendation: Include 'default-src' for a strong baseline policy")
                else:
                    details.append("Status: Configured with default-src")

        elif header_lower == "strict-transport-security":
            if not header_value:
                details.append(f"Strict-Transport-Security: Missing")
                details.append(f"Recommendation: Add HSTS to enforce HTTPS (e.g., 'max-age=31536000; includeSubDomains')")
            else:
                details.append(f"Strict-Transport-Security: Present")
                details.append(f"Value: {header_value}")
                if "max-age=0" in header_value:
                    details.append("Warning: max-age=0 disables HSTS")
                    details.append("Recommendation: Set max-age to at least 31536000 (1 year)")
                elif "max-age" not in header_value:
                    details.append("Warning: max-age directive missing")
                    details.append("Recommendation: Specify a max-age (e.g., 31536000)")
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "x-frame-options":
            if not header_value:
                details.append(f"X-Frame-Options: Missing")
                details.append(f"Recommendation: Add 'DENY' or 'SAMEORIGIN' to prevent clickjacking")
            else:
                details.append(f"X-Frame-Options: Present")
                details.append(f"Value: {header_value}")
                if header_value.upper() not in ["DENY", "SAMEORIGIN"]:
                    details.append("Warning: Invalid or deprecated value")
                    details.append("Recommendation: Use 'DENY' or 'SAMEORIGIN'")
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "x-content-type-options":
            if not header_value:
                details.append(f"X-Content-Type-Options: Missing")
                details.append(f"Recommendation: Add 'nosniff' to prevent MIME-type sniffing")
            else:
                details.append(f"X-Content-Type-Options: Present")
                details.append(f"Value: {header_value}")
                if header_value.lower() != "nosniff":
                    details.append("Warning: Value is not 'nosniff'")
                    details.append("Recommendation: Set to 'nosniff'")
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "referrer-policy":
            if not header_value:
                details.append(f"Referrer-Policy: Missing")
                details.append(f"Recommendation: Set a policy like 'strict-origin-when-cross-origin' to control referrer info")
            else:
                details.append(f"Referrer-Policy: Present")
                details.append(f"Value: {header_value}")
                valid_policies = [
                    "no-referrer", "no-referrer-when-downgrade", "origin", 
                    "origin-when-cross-origin", "same-origin", 
                    "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"
                ]
                if header_value.lower() not in valid_policies:
                    details.append("Warning: Invalid policy")
                    details.append("Recommendation: Use a secure policy like 'strict-origin-when-cross-origin'")
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "permissions-policy":
            if not header_value:
                details.append(f"Permissions-Policy: Missing")
                details.append(f"Recommendation: Use to restrict features like geolocation (e.g., 'geolocation=()')")
            else:
                details.append(f"Permissions-Policy: Present")
                details.append(f"Value: {header_value}")
                details.append("Status: Configured (review policy for appropriateness)")

        elif header_lower == "x-xss-protection":
            if not header_value:
                details.append(f"X-XSS-Protection: Missing")
                details.append(f"Recommendation: Consider '0' to disable (modern browsers rely on CSP)")
            else:
                details.append(f"X-XSS-Protection: Present")
                details.append(f"Value: {header_value}")
                if header_value != "0":
                    details.append("Warning: Legacy header may interfere with CSP")
                    details.append("Recommendation: Set to '0' or rely on CSP")
        print("The details for the check header function are ",details)
        return details'''

'''def check_headers(url):
    """
    Analyzes HTTP response headers for security configurations.
    Returns a list of details, CVE details, and recommendations.
    """
    all_details = []  # Accumulate the details here

    try:
        response = requests.get(url, verify=False)  # Disable SSL verification for simplicity; REMOVE IN PRODUCTION
        headers = response.headers
    except requests.exceptions.RequestException as e:
        all_details.append(f"Error fetching URL: {e}")
        return all_details # Return the list even if there is error

    def analyze_header(header_name, header_value, headers):
        """
        Analyzes a specific header and returns a list of details (status, value, recommendation, CVE info).
        """
        details = []
        header_lower = header_name.lower()

        if header_lower == "content-security-policy":
            if not header_value:
                details.append(f"Content-Security-Policy: Missing")
                details.append(f"Recommendation: Implement CSP to control resource loading (e.g., 'default-src \"self\"')")
                cve_id = "CVE-2015-3183"  # Example CVE for CSP bypass
                cve_link = f"https://www.cve.org/CVERecord?id={cve_id}"
                details.append(f"Potential Vulnerability (Missing CSP): {cve_id} - {cve_link} (CSP Bypass)")

            else:
                details.append(f"Content-Security-Policy: Present")
                details.append(f"Value: {header_value}")
                if "default-src" not in header_value:
                    details.append("Recommendation: Include 'default-src' for a strong baseline policy")
                    cve_id = "CVE-2015-8854"  # Example CVE for CSP unsafe-inline
                    cve_link = f"https://www.cve.org/CVERecord?id={cve_id}"
                    details.append(f"Potential Vulnerability (default-src missing): {cve_id} - {cve_link} (Unsafe-inline scripts)")

                else:
                    details.append("Status: Configured with default-src")

        elif header_lower == "strict-transport-security":
            if not header_value:
                details.append(f"Strict-Transport-Security: Missing")
                details.append(f"Recommendation: Add HSTS to enforce HTTPS (e.g., 'max-age=31536000; includeSubDomains')")
                cve_id = "CVE-2015-0931"  # Example CVE for HSTS missing
                cve_link = f"https://www.cve.org/CVERecord?id={cve_id}"
                details.append(f"Potential Vulnerability (Missing HSTS): {cve_id} - {cve_link} (HTTPS Downgrade)")
            else:
                details.append(f"Strict-Transport-Security: Present")
                details.append(f"Value: {header_value}")
                if "max-age=0" in header_value:
                    details.append("Warning: max-age=0 disables HSTS")
                    details.append("Recommendation: Set max-age to at least 31536000 (1 year)")
                elif "max-age" not in header_value:
                    details.append("Warning: max-age directive missing")
                    details.append("Recommendation: Specify a max-age (e.g., 31536000)")
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "x-frame-options":
            if not header_value:
                details.append(f"X-Frame-Options: Missing")
                details.append(f"Recommendation: Add 'DENY' or 'SAMEORIGIN' to prevent clickjacking")
                cve_id = "CVE-2002-0093"  # Example CVE for clickjacking
                cve_link = f"https://www.cve.org/CVERecord?id={cve_id}"
                details.append(f"Potential Vulnerability (Missing XFO): {cve_id} - {cve_link} (Clickjacking)")
            else:
                details.append(f"X-Frame-Options: Present")
                details.append(f"Value: {header_value}")
                if header_value.upper() not in ["DENY", "SAMEORIGIN"]:
                    details.append("Warning: Invalid or deprecated value")
                    details.append("Recommendation: Use 'DENY' or 'SAMEORIGIN'")
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "x-content-type-options":
            if not header_value:
                details.append(f"X-Content-Type-Options: Missing")
                details.append(f"Recommendation: Add 'nosniff' to prevent MIME-type sniffing")
                cve_id = "CVE-2014-6602"  # Example CVE for MIME confusion
                cve_link = f"https://www.cve.org/CVERecord?id={cve_id}"
                details.append(f"Potential Vulnerability (Missing XCTO): {cve_id} - {cve_link} (MIME Confusion)")
            else:
                details.append(f"X-Content-Type-Options: Present")
                details.append(f"Value: {header_value}")
                if header_value.lower() != "nosniff":
                    details.append("Warning: Value is not 'nosniff'")
                    details.append("Recommendation: Set to 'nosniff'")
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "referrer-policy":
            if not header_value:
                details.append(f"Referrer-Policy: Missing")
                details.append(f"Recommendation: Set a policy like 'strict-origin-when-cross-origin' to control referrer info")
                cve_id = "CVE-2018-1002204"  # Example CVE for referrer leakage
                cve_link = f"https://www.cve.org/CVERecord?id={cve_id}"
                details.append(f"Potential Vulnerability (Missing Referrer-Policy): {cve_id} - {cve_link} (Referrer Leakage)")
            else:
                details.append(f"Referrer-Policy: Present")
                details.append(f"Value: {header_value}")
                valid_policies = [
                    "no-referrer", "no-referrer-when-downgrade", "origin",
                    "origin-when-cross-origin", "same-origin",
                    "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"
                ]
                if header_value.lower() not in valid_policies:
                    details.append("Warning: Invalid policy")
                    details.append("Recommendation: Use a secure policy like 'strict-origin-when-cross-origin'")
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "permissions-policy":
            if not header_value:
                details.append(f"Permissions-Policy: Missing")
                details.append(f"Recommendation: Use to restrict features like geolocation (e.g., 'geolocation=()')")
            else:
                details.append(f"Permissions-Policy: Present")
                details.append(f"Value: {header_value}")
                details.append("Status: Configured (review policy for appropriateness)")

        elif header_lower == "x-xss-protection":
            if not header_value:
                details.append(f"X-XSS-Protection: Missing")
                details.append(f"Recommendation: Consider '0' to disable (modern browsers rely on CSP)")
                cve_id = "CVE-2010-3687"  # Example CVE for XSS
                cve_link = f"https://www.cve.org/CVERecord?id={cve_id}"
                details.append(f"Potential Vulnerability (Missing X-XSS-Protection): {cve_id} - {cve_link} (XSS)")
            else:
                details.append(f"X-XSS-Protection: Present")
                details.append(f"Value: {header_value}")
                if header_value != "0":
                    details.append("Warning: Legacy header may interfere with CSP")
                    details.append("Recommendation: Set to '0' or rely on CSP")

        return details

    all_details.append(f"Analyzing headers for {url}:")
    for header_name, header_value in headers.items():
        analysis_results = analyze_header(header_name, header_value, headers)
        all_details.extend(analysis_results)  # Add the details from each header

    all_details.append("\nDisclaimer: CVEs provided are related to potential misconfigurations of the listed headers and may not be directly applicable to the specific site configuration.")
    return all_details'''
import requests
from urllib.parse import urlparse

def check_headers(url):
    """
    Analyzes HTTP response headers for security configurations.
    Prints details of each security header on separate lines, including status, recommendations, CVE scores, and links.
    """
    def analyze_header(header_name, header_value, headers):
        """
        Analyzes a specific header and returns a list of details (status, value, recommendation, CVE score, CVE link).
        """
        details = []
        header_lower = header_name.lower()

        if header_lower == "content-security-policy":
            if not header_value:
                details.extend([
                    f"Content-Security-Policy: Missing",
                    f"Recommendation: Implement CSP to control resource loading (e.g., 'default-src \"self\"')",
                    f"CVE Score: ~7.5 (e.g., CVE-2019-11743 - XSS due to missing CSP)",
                    f"CVE Link: https://cve.org/CVE-2019-11743"
                ])
            else:
                details.extend([
                    f"Content-Security-Policy: Present",
                    f"Value: {header_value}"
                ])
                if "default-src" not in header_value.lower():
                    details.append("Recommendation: Include 'default-src' for a strong baseline policy")
                else:
                    details.append("Status: Configured with default-src")

        elif header_lower == "strict-transport-security":
            if not header_value:
                details.extend([
                    f"Strict-Transport-Security: Missing",
                    f"Recommendation: Add HSTS to enforce HTTPS (e.g., 'max-age=31536000; includeSubDomains')",
                    f"CVE Score: ~5.9 (e.g., CVE-2016-0795 - SSL/TLS downgrade)",
                    f"CVE Link: https://cve.org/CVE-2016-0795"
                ])
            else:
                details.extend([
                    f"Strict-Transport-Security: Present",
                    f"Value: {header_value}"
                ])
                if "max-age=0" in header_value.lower():
                    details.extend([
                        "Warning: max-age=0 disables HSTS",
                        "Recommendation: Set max-age to at least 31536000 (1 year)"
                    ])
                elif "max-age" not in header_value.lower():
                    details.extend([
                        "Warning: max-age directive missing",
                        "Recommendation: Specify a max-age (e.g., 31536000)"
                    ])
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "x-frame-options":
            if not header_value:
                details.extend([
                    f"X-Frame-Options: Missing",
                    f"Recommendation: Add 'DENY' or 'SAMEORIGIN' to prevent clickjacking",
                    f"CVE Score: ~6.5 (e.g., CVE-2013-0288 - Clickjacking)",
                    f"CVE Link: https://cve.org/CVE-2013-0288"
                ])
            else:
                details.extend([
                    f"X-Frame-Options: Present",
                    f"Value: {header_value}"
                ])
                if header_value.upper() not in ["DENY", "SAMEORIGIN"]:
                    details.extend([
                        "Warning: Invalid or deprecated value",
                        "Recommendation: Use 'DENY' or 'SAMEORIGIN'"
                    ])
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "x-content-type-options":
            if not header_value:
                details.extend([
                    f"X-Content-Type-Options: Missing",
                    f"Recommendation: Add 'nosniff' to prevent MIME-type sniffing",
                    f"CVE Score: ~6.5 (e.g., CVE-2016-3714 - MIME sniffing)",
                    f"CVE Link: https://cve.org/CVE-2016-3714"
                ])
            else:
                details.extend([
                    f"X-Content-Type-Options: Present",
                    f"Value: {header_value}"
                ])
                if header_value.lower() != "nosniff":
                    details.extend([
                        "Warning: Value is not 'nosniff'",
                        "Recommendation: Set to 'nosniff'"
                    ])
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "referrer-policy":
            if not header_value:
                details.extend([
                    f"Referrer-Policy: Missing",
                    f"Recommendation: Set a policy like 'strict-origin-when-cross-origin' to control referrer info",
                    f"CVE Score: ~5.4 (e.g., CVE-2017-5121 - Referrer leakage)",
                    f"CVE Link: https://cve.org/CVE-2017-5121"
                ])
            else:
                details.extend([
                    f"Referrer-Policy: Present",
                    f"Value: {header_value}"
                ])
                valid_policies = [
                    "no-referrer", "no-referrer-when-downgrade", "origin",
                    "origin-when-cross-origin", "same-origin",
                    "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"
                ]
                if header_value.lower() not in valid_policies:
                    details.extend([
                        "Warning: Invalid policy",
                        "Recommendation: Use a secure policy like 'strict-origin-when-cross-origin'"
                    ])
                else:
                    details.append("Status: Properly configured")

        elif header_lower == "permissions-policy":
            if not header_value:
                details.extend([
                    f"Permissions-Policy: Missing",
                    f"Recommendation: Use to restrict features like geolocation (e.g., 'geolocation=()')",
                    f"CVE Score: ~6.1 (e.g., CVE-2020-15999 - Permissions misuse)",
                    f"CVE Link: https://cve.org/CVE-2020-15999"
                ])
            else:
                details.extend([
                    f"Permissions-Policy: Present",
                    f"Value: {header_value}"
                ])
                details.append("Status: Configured (review policy for appropriateness)")

        elif header_lower == "x-xss-protection":
            if not header_value:
                details.extend([
                    f"X-XSS-Protection: Missing",
                    f"Recommendation: Consider '0' to disable (modern browsers rely on CSP)",
                    f"CVE Score: ~6.1 (e.g., CVE-2019-9814 - XSS bypass)",
                    f"CVE Link: https://cve.org/CVE-2019-9814"
                ])
            else:
                details.extend([
                    f"X-XSS-Protection: Present",
                    f"Value: {header_value}"
                ])
                if header_value != "0":
                    details.extend([
                        "Warning: Legacy header may interfere with CSP",
                        "Recommendation: Set to '0' or rely on CSP"
                    ])
                else:
                    details.append("Status: Properly configured")

        return details

    # Clean URL input
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    if not domain:
        print("Error: No valid URL provided")
        return

    print(f"Checking HTTP headers for {url}...")
    
    try:
        # Send HEAD request to minimize data transfer
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        }
        response = requests.head(url, timeout=5, headers=headers, allow_redirects=True)
        
        # Fall back to GET if HEAD is not supported
        if response.status_code == 405 or not response.headers:
            response = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
        
        response.raise_for_status()
        response_headers = response.headers

        # Headers to analyze
        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-XSS-Protection"
        ]

        details = []
        # Analyze each security header
        for header in security_headers:
            header_value = response_headers.get(header, "")
            details.extend(analyze_header(header, header_value, response_headers))

        # Check for deprecated or insecure headers
        if "Server" in response_headers:
            details.extend([
                f"Server: Present",
                f"Value: {response_headers['Server']}",
                "Recommendation: Minimize server info disclosure"
            ])

        if "X-Powered-By" in response_headers:
            details.extend([
                f"X-Powered-By: Present",
                f"Value: {response_headers['X-Powered-By']}",
                "Recommendation: Remove to reduce information leakage"
            ])

        # Print results
        for detail in details:
            print(detail)
        
        print(f"HTTP header check complete for {url}")

    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to fetch headers: {str(e)}")
        print(f"HTTP header check complete for {url}")
        
def check_tls_cert(domain):
    """
    Checks the TLS certificate of a domain and prints details on separate lines.
    Prints: domain, valid from, valid until, key, SHA-256 fingerprint (unformatted), issuer, status.
    """
    def get_cert_chain(domain):
        try:
            ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
            sock = socket.socket()
            sock.settimeout(5)
            wrapped_sock = OpenSSL.SSL.Connection(ctx, sock)
            wrapped_sock.set_tlsext_host_name(domain.encode('ascii'))
            wrapped_sock.connect((domain, 443))
            while True:
                try:
                    wrapped_sock.do_handshake()
                    break
                except OpenSSL.SSL.WantReadError:
                    select.select([wrapped_sock], [], [])
            cert_chain = wrapped_sock.get_peer_cert_chain()
            wrapped_sock.close()
            return cert_chain
        except Exception as e:
            return e

    def validate_cert_chain(cert_chain):
        msgs = []
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ctx.set_default_verify_paths()
        cert_store = ctx.get_cert_store()
        for index, cert in reversed(list(enumerate(cert_chain))):
            sc = OpenSSL.crypto.X509StoreContext(cert_store, cert)
            try:
                sc.verify_certificate()
            except OpenSSL.crypto.X509StoreContextError as e:
                msgs.append(f"Validation error: {e}")
            if index > 0:
                cert_store.add_cert(cert)
        return msgs

    def analyze_certs(domain, cert_chain, utcnow):
        if cert_chain is None:
            return [f"Error: No certificate chain received for {domain}"]
        if isinstance(cert_chain, Exception):
            return [f"Error: Unable to obtain certificate chain: {str(cert_chain)}"]

        # Validate chain
        validation_msgs = validate_cert_chain(cert_chain)
        
        # Analyze the leaf certificate (first in chain)
        cert = cert_chain[0]  # Leaf certificate
        details = []

        # Domain
        details.append(f"Domain: {domain}")

        # Valid from (notBefore)
        not_before_str = cert.get_notBefore().decode('ascii', errors='ignore')
        try:
            not_before = datetime.datetime.strptime(not_before_str, '%Y%m%d%H%M%SZ')
            details.append(f"Valid from: {not_before}")
        except ValueError:
            details.append(f"Valid from: Invalid date")

        # Valid until (notAfter)
        not_after_str = cert.get_notAfter().decode('ascii', errors='ignore')
        try:
            not_after = datetime.datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ')
            details.append(f"Valid until: {not_after}")
        except ValueError:
            details.append(f"Valid until: Invalid date")

        # Key (public key algorithm and size)
        try:
            pubkey = cert.get_pubkey()
            key_type = pubkey.type()  # RSA, EC, etc.
            key_size = pubkey.bits()
            key_types = {OpenSSL.crypto.TYPE_RSA: "RSA", OpenSSL.crypto.TYPE_DSA: "DSA", 408: "EC"}  # 408 for EC
            key_name = key_types.get(key_type, f"Unknown ({key_type})")
            details.append(f"Key: {key_name} {key_size} bits")
        except Exception as e:
            details.append(f"Key: Error retrieving key info ({str(e)})")

        # Fingerprint (SHA-256, unformatted)
        try:
            cert_der = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
            sha256_fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
            details.append(f"Fingerprint SHA-256: {sha256_fingerprint}")
        except Exception as e:
            details.append(f"Fingerprint SHA-256: Error calculating fingerprint ({str(e)})")

        # Issuer
        issuer = cert.get_issuer().commonName or "Unknown"
        details.append(f"Issuer: {issuer}")

        # Add validation errors
        if validation_msgs:
            details.extend(validation_msgs)
        
        # Check expiration status
        try:
            if not_after < utcnow:
                details.append(f"Status: Certificate expired on {not_after}")
            elif not_after < (utcnow + datetime.timedelta(days=15)):
                details.append(f"Status: Certificate expires soon on {not_after} ({not_after - utcnow})")
            else:
                details.append(f"Status: Valid until {not_after}")
        except NameError:  # not_after not defined if date parsing failed
            pass

        return details

    # Clean domain input
    domain = domain.replace("http://", "").replace("https://", "").split('/')[0].strip()
    if not domain:
        print("Error: No valid domain provided")
        return

    print(f"Checking TLS certificate for {domain}...")
    cert_chain = get_cert_chain(domain)
    utcnow = datetime.datetime.utcnow()

    details = analyze_certs(domain, cert_chain, utcnow)
    for detail in details:
        print(detail)
    print(f"TLS certificate check complete for {domain}")



def check_sql_injection(url):
    """
    Tests a URL for SQL injection vulnerabilities by submitting payloads from a wordlist.
    Prints minimal results: number of forms tested, vulnerabilities found, and recommendations.
    
    Args:
        url (str): The URL to test.
    Returns:
        tuple: (number of vulnerable forms, list of summary details)
    """

    def get_form_details(form):
        form_details = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs = []

        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            if input_name:
                inputs.append({
                    "type": input_type,
                    "name": input_name,
                    "value": input_value
                })
        
        form_details["action"] = action
        form_details["method"] = method
        form_details["inputs"] = inputs
        return form_details

    def load_wordlist():
        wordlist_path = r"sql_injection_wordlist.txt"
        payloads = []
        try:
            if not os.path.exists(wordlist_path):
                return payloads
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
            return payloads
        except:
            return []

    def is_response_vulnerable(response):
        if not response:
            return False, "No response received"
        
        try:
            content = response.content.decode('utf-8', errors='ignore').lower()
            sql_error_messages = [
                "quoted string not properly terminated",
                "unclosed quotation mark after the character string",
                "you have an error in your sql syntax",
                "unknown column in 'field list'",
                "unexpected end of sql command",
                "warning: mysql_num_rows() expects parameter 1 to be resource",
                "warning: mysql_fetch_array() expects parameter 1 to be resource",
                "sql syntax error",
                "unrecognized token",
                "syntax error at or near",
                "division by zero",
                "missing right parenthesis",
                "incorrect integer value",
                "invalid sql statement",
                "subquery returns more than 1 row",
                "data truncation: data too long for column",
                "conversion failed when converting",
                "ora-00933: sql command not properly ended",
                "ora-00942: table or view does not exist",
                "sqlite3::sqlexception: unrecognized token",
                "postgresql error: fatal error",
                "mysql server version for the right syntax"
            ]
            for error in sql_error_messages:
                if error in content:
                    return True, f"SQL error detected"
            if response.status_code not in [200, 302]:
                return True, f"Unexpected status code: {response.status_code}"
            return False, "No issues detected"
        except Exception as e:
            return False, f"Error analyzing response: {str(e)}"

    def submit_form(form_details, url, payload):
        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36"
        target_url = urljoin(url, form_details["action"] or "")
        data = {}
        
        for input_tag in form_details["inputs"]:
            if input_tag["name"]:
                if input_tag["type"] in ["hidden"] or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + payload
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{payload}"
        
        try:
            if form_details["method"] == "post":
                return session.post(target_url, data=data, timeout=5, allow_redirects=True)
            return session.get(target_url, params=data, timeout=5, allow_redirects=True)
        except requests.exceptions.RequestException:
            return None


    # Load payloads from wordlist
    payloads = load_wordlist()
    details = []
    vulnerable_forms = 0

    if not payloads:
        details.append("No payloads available to test")
        return 0, details

    # Get forms
    forms = get_all_forms(url)
    if not forms:
        details.append("No forms found to test for SQL injection")
        return 0, details

    details.append(f"Tested {len(forms)} forms on {url}")

    for form_index, form in enumerate(forms, 1):
        form_details = get_form_details(form)
        form_action_url = urljoin(url, form_details["action"] or "")
        
        if not form_details["inputs"]:
            continue

        for payload in payloads:
            response = submit_form(form_details, url, payload)
            is_vuln, reason = is_response_vulnerable(response)
            
            if is_vuln:
                vulnerable_forms += 1
                details.append(f"Form {form_index} potentially vulnerable at {form_action_url}: {reason}")
                break

    if vulnerable_forms:
        details.append(f"Status: Found {vulnerable_forms} potentially vulnerable form(s)")
        details.append("Recommendation: Sanitize inputs, use prepared statements")
    else:
        details.append("Status: No SQL injection vulnerabilities detected")
        details.append("Recommendation: Continue to validate and sanitize inputs")

    return vulnerable_forms, details
                      


def detect_xss(url):
    """
    Detects XSS vulnerabilities in forms on a given URL.
    Returns a dictionary with detection result and all form details.
    """

    def get_form_details(form):
        details = {}
        try:
            action = form.attrs.get("action", "").lower()
            method = form.attrs.get("method", "get").lower()
        except:
            action = ""
            method = "get"
        
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        
        for select_tag in form.find_all("select"):
            inputs.append({"type": "select", "name": select_tag.attrs.get("name")})
        
        for textarea in form.find_all("textarea"):
            inputs.append({"type": "textarea", "name": textarea.attrs.get("name")})
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(form_details, url, value):
        target_url = urljoin(url, form_details["action"])
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            input_type = input.get("type")
            input_name = input.get("name")
            if input_type in ["text", "search", "textarea", "password"]:  # Include password
                data[input_name] = value
            elif input_type == "select":
                data[input_name] = "0"  # Set security_level to low
            elif input_name:
                data[input_name] = input.get("value", "")
        
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
            }
            if form_details["method"] == "post":
                return requests.post(target_url, data=data, headers=headers, timeout=5)
            return requests.get(target_url, params=data, headers=headers, timeout=5)
        except Exception as e:
            return None

    forms = get_all_forms(url)
    return_details = []
    
    try:
        with open(os.path.join(os.path.dirname(__file__), "morepayload.txt")) as x:
            for form in forms:
                form_details = get_form_details(form)
                form_details["vulnerable"] = False
                x.seek(0)  # Reset file pointer
                for line in x:
                    js_script = line.strip()
                    try:
                        response = submit_form(form_details, url, js_script)
                        if response and js_script in response.content.decode():
                            form_details["vulnerable"] = True
                            break
                    except Exception as e:
                        continue
                return_details.append(form_details)
    except FileNotFoundError:
        return {"result": "Error: payload_basic.txt not found", "details": []}

    return_val = {"result": "XSS Not Detected", "details": return_details}
    for form in return_details:
        if form["vulnerable"]:
            return_val["result"] = "XSS Detected"
            break

    return return_val


def directory_bruteforce(url, max_attempts=1000, timeout=5, delay=0.1):
    
    def load_wordlist(max_attempts):
        """
        Loads directory names from the wordlist file, up to max_attempts.
        """
        wordlist_path=r"Backend\directory_wordlist.txt"
        directories = []
        try:
            if not os.path.exists(wordlist_path):
                print(f"Error: Wordlist file {wordlist_path} not found")
                return directories
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                directories = [line.strip() for line in f if line.strip()]
            if not directories:
                print("Error: Wordlist is empty")
                return []
            return directories[:max_attempts]
        except Exception as e:
            print(f"Error loading wordlist: {str(e)}")
            return []

    def is_valid_response(response, content_check=True):
        """
        Checks if the response indicates a valid directory (not a false positive).
        """
        if not response:
            return False, "No response received"
        
        try:
            # Check status code
            if response.status_code not in [200, 301, 302]:
                return False, f"Status code: {response.status_code}"
            
            # Optional content check to avoid false positives (e.g., custom 404 pages)
            if content_check:
                content = response.text.lower()
                error_indicators = [
                    "404 not found",
                    "page not found",
                    "error 404",
                    "not found",
                    "forbidden",
                    "access denied"
                ]
                for indicator in error_indicators:
                    if indicator in content:
                        return False, f"False positive detected: {indicator}"
            
            return True, "Valid directory"
        except Exception as e:
            return False, f"Error analyzing response: {str(e)}"

    
    # Load directories from wordlist
    directories = load_wordlist(max_attempts)
    if not directories:
        print("No directories available to test")
        print(f"Directory brute-forcing complete for {url}")
        return []

    print(f"Loaded {len(directories)} directories from wordlist")

    # Initialize session
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36"

    found_dirs = []
    details = []

    for directory in directories:
        test_url = urljoin(url, directory + '/')
        details.append(f"Testing Directory: {test_url}")
        
        try:
            response = session.get(test_url, timeout=timeout, allow_redirects=True)
            is_valid, reason = is_valid_response(response)
            details.append(f"Result: {reason}")
            
            if is_valid:
                found_dirs.append(test_url)
                details.append(f"Found: Directory accessible at {test_url}")
            time.sleep(delay)  # Rate limiting
        except requests.exceptions.RequestException as e:
            details.append(f"Result: Error accessing {test_url}: {str(e)}")
            continue

    # Summarize results
    details.append(f"Status: Found {len(found_dirs)} accessible directories")
    if found_dirs:
        details.append("Recommendation: Review access controls for sensitive directories")
    else:
        details.append("Recommendation: No accessible directories found; continue monitoring")

    # Print results
    for detail in details:
        print(detail)
    print(f"Directory brute-forcing complete for {url}")

    return found_dirs


def extract_emails(text):
    pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    return re.findall(pattern, text)

def extract_phone_numbers(text):
    pattern = re.compile(r'(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})')
    return re.findall(pattern, text)

def scrape_contacts(target):
    try:
        response = requests.get(target)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()
        emails = extract_emails(text)
        phones = extract_phone_numbers(text)
        return emails, phones
    except:
        return [], []

# ------------------ Main Orchestrator Function ------------------


def run_all_scans(target_url):
    """
    Orchestrates all scanner functions for a target URL and returns a structured result for frontend display.
    Includes summarized results from port scanning, headers, TLS certificate, SQL injection, XSS, directory brute-forcing,
    and contact scraping.

    Args:
        target_url (str): The target URL to scan (e.g., 'https://example.com').

    Returns:
        dict: A JSON-compatible dictionary containing summarized results for each scanner.
    """
    # Initialize result dictionary
    result = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "target_url": target_url,
        "scans": {},
        "summary": {
            "total_scans": 7,
            "status": "Incomplete"
        }
    }

    # Clean URL input
    '''if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url'''
    parsed_url = urlparse(target_url)

    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    if not domain:
        result["scans"]["error"] = {
            "status": "Failed",
            "details": ["Error: No valid URL provided"],
            "recommendation": "Provide a valid URL (e.g., https://example.com)"
        }
        result["summary"]["status"] = "Failed"
        return result

    print(f"Starting full scan for {target_url}...")

    # Helper function to capture print output (minimal details)
    def capture_details(func, *args):
        from io import StringIO
        import sys
        old_stdout = sys.stdout
        sys.stdout = new_stdout = StringIO()
        try:
            result = func(*args)
            # Filter out verbose lines (e.g., "Testing Payload", "Form Action")
            details = [line for line in new_stdout.getvalue().strip().split('\n')
                      if not line.startswith(("Testing ", "Form Action:", "Inputs Found:", "Result:"))]
            return result, details
        except Exception as e:
            details = [line for line in new_stdout.getvalue().strip().split('\n')
                      if not line.startswith(("Testing ", "Form Action:", "Inputs Found:", "Result:"))]
            if not details or details == ['']:
                details = [f"Error: {str(e)}"]
            return None, details
        finally:
            sys.stdout = old_stdout

    # 1. Port Scan
    try:
        ports, port_details = capture_details(port_scan, domain)
        result["scans"]["port_scan"] = {
            "status": "Completed" if ports is not None else "Failed",
            "result": {"open_ports": ports or []},
            "details": [d for d in port_details if "Scanning port" not in d],  # Remove verbose port checks
            "recommendation": (f"Close unnecessary ports: {ports}" if ports else
                             "No open ports found in range 20-100")
        }
      
           
    except Exception as e:
        result["scans"]["port_scan"] = {
            "status": "Failed",
            "result": {"open_ports": []},
            "details": [f"Error: {str(e)}"],
            "recommendation": "Check network connectivity or domain resolution"
        }

    # 2. Check Headers
    try:
        _, header_details = capture_details(check_headers, target_url)
        issues = sum(1 for d in header_details if "Missing" in d or "Warning" in d)
        result["scans"]["check_headers"] = {
            "status": "Completed",
            "result": {"issues_count": issues},
            "details": header_details,
            "recommendation": (f"Implement {issues} missing or misconfigured headers" if issues else
                             "Headers well-configured")
        }
        
    except Exception as e:
        result["scans"]["check_headers"] = {
            "status": "Failed",
            "result": {"issues_count": 0},
            "details": [f"Error: {str(e)}"],
            "recommendation": "Verify URL accessibility"
        }


    # 3. Check TLS Certificate
    try:
        _, cert_details = capture_details(check_tls_cert, domain)
        issues = sum(1 for d in cert_details if "expired" in d.lower() or "expires soon" in d.lower() or "validation error" in d.lower())
        result["scans"]["check_tls_cert"] = {
            "status": "Completed",
            "result": {"issues_count": issues},
            "details": cert_details,
            "recommendation": (f"Address {issues} certificate issues (e.g., expiration)" if issues else
                             "Certificate valid")
        }
        
    except Exception as e:
        result["scans"]["check_tls_cert"] = {
            "status": "Failed",
    
            "details": [f"Error: {str(e)}"],
            "recommendation": "Ensure domain supports HTTPS"
        }

    # 4. Check SQL Injection
    try:
        vuln_forms, sql_details = capture_details(check_sql_injection, target_url)
        result["scans"]["check_sql_injection"] = {
            "status": "Completed",
            "result": {"vulnerable_forms": vuln_forms or 0},
            "details": sql_details,
            "recommendation": (f"Fix {vuln_forms} vulnerable form(s)" if vuln_forms else
                             "No SQL injection vulnerabilities detected")
        }
        
    except Exception as e:
        result["scans"]["check_sql_injection"] = {
            "status": "Failed",
            "result": {"vulnerable_forms": 0},
            "details": [f"Error: {str(e)}"],
            "recommendation": "Verify URL accessibility"
        }

    try:
        xss_result, xss_details = capture_details(detect_xss, target_url)
        vulnerable = xss_result["result"] == "XSS Detected" if xss_result else False
        result["scans"]["detect_xss"] = {
            "status": "Completed" if xss_result else "Failed",
            "result": {"vulnerable": vulnerable},
            "details": [d for d in xss_details if not d.startswith(("DEBUG: Testing form", "THE RESPONSE IS"))],
            "recommendation": ("Implement input sanitization and CSP" if vulnerable else
                             "No XSS vulnerabilities detected")
        }
       
            
    except Exception as e:
        result["scans"]["detect_xss"] = {
            "status": "Failed",
            "result": {"vulnerable": False},
            "details": [f"Error: {str(e)}"],
            "recommendation": "Verify URL accessibility"
        }


    # 6. Directory Brute-Forcing
    try:
        dirs, dir_details = capture_details(directory_bruteforce, target_url)
        result["scans"]["directory_bruteforce"] = {
            "status": "Completed" if dirs is not None else "Failed",
            "result": {"found_directories": dirs or []},
            "details": [d for d in dir_details if not d.startswith("Testing Directory:")],
            "recommendation": (f"Secure {len(dirs)} accessible directories" if dirs else
                             "No accessible directories found")
        }
        
    except Exception as e:
        result["scans"]["directory_bruteforce"] = {
            "status": "Failed",
            "result": {"found_directories": []},
            "details": [f"Error: {str(e)}"],
            "recommendation": "Verify URL accessibility"
        }

    # 7. Scrape Contacts
    try:
        emails, phones = scrape_contacts(target_url)
        contact_details = [
            f"Emails found: {len(emails)}",
            f"Phone numbers found: {len(phones)}"
        ]
        result["scans"]["scrape_contacts"] = {
            "status": "Completed",
            "result": {
                "emails_count": len(emails),
                "phones_count": len(phones)
            },
            "details": contact_details,
            "recommendation": (f"Protect {len(emails) + len(phones)} contact details" if (emails or phones) else
                             "No contact info found")
        }
    except Exception as e:
        result["scans"]["scrape_contacts"] = {
            "status": "Failed",
            "result": {"emails_count": 0, "phones_count": 0},
            "details": [f"Error: {str(e)}"],
            "recommendation": "Verify URL accessibility"
        }

    # Finalize summary
    result["summary"]["status"] = "Completed"
    print(f"Full scan complete for {target_url}")

    return result 