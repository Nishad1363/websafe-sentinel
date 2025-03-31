import socket
import requests
import datetime
import ssl
import re
import certifi
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import init

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

def header_analysis(target):
    try:
        response = requests.head(target, timeout=5)
        headers = response.headers
        security_headers = {
            "X-Frame-Options": "Clickjacking Protection",
            "Content-Security-Policy": "XSS Protection",
            "Strict-Transport-Security": "SSL/TLS Protection",
            "X-XSS-Protection": "XSS Filtering",
            "X-Content-Type-Options": "Prevent MIME Sniffing"
        }
        missing = []
        for header in security_headers:
            if header not in headers:
                missing.append(header)
        return missing
    except:
        return ["Could not fetch headers"]

def check_ssl_expiry(target):
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((target, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y GMT")
                days_left = (expiry_date - datetime.datetime.utcnow()).days
                if days_left > 30:
                    return f"Valid - {days_left} days left"
                elif days_left > 0:
                    return f"Expiring Soon - {days_left} days left"
                else:
                    return "Expired"
    except Exception as e:
        return f"SSL check failed: {e}"

def sql_injection_test(target):
    payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR 'a'='a"]
    for payload in payloads:
        try:
            response = requests.get(f"{target}?id={payload}", timeout=5)
            if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
                return True
        except:
            continue
    return False

def xss_test(target):
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    for payload in payloads:
        try:
            response = requests.get(f"{target}?q={payload}", timeout=5)
            if payload in response.text:
                return True
        except:
            continue
    return False

def directory_bruteforce(target):
    found_dirs = []
    common_dirs = ["admin", "login", "dashboard", "config", "backup", "test", "uploads"]
    for directory in common_dirs:
        url = f"{target}/{directory}/"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                found_dirs.append(url)
        except:
            continue
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
    print("🚀 Starting scan for:", target_url)

    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc

    print("🔍 Port scanning...")
    ports = port_scan(domain)

    print("🛡 Header analysis...")
    headers = header_analysis(target_url)

    print("🔐 SSL check...")
    ssl_status = check_ssl_expiry(domain)

    print("💉 SQLi test...")
    sqli = sql_injection_test(target_url)

    print("🧨 XSS test...")
    xss = xss_test(target_url)

    print("📁 Directory brute force...")
    dirs = directory_bruteforce(target_url)

    print("📞 Scraping emails and phones...")
    emails, phones = scrape_contacts(target_url)

    print("✅ Scan complete.")

    results = {
        "url": target_url,
        "open_ports": ports,
        "missing_headers": headers,
        "ssl_status": ssl_status,
        "sqli_found": sqli,
        "xss_found": xss,
        "directories_found": dirs,
        "emails": emails,
        "phone_numbers": phones
    }

    return results
