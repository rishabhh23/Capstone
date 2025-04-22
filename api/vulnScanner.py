import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import socket
import ssl

# -------------------------------
# SecurityScanner class
# -------------------------------
class SecurityScanner:
    def __init__(self, url):
        self.url = url if url.startswith(("http://", "https://")) else "http://" + url
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def scan(self):
        try:
            self.check_ssl_cert()
            self.check_security_headers()
            self.check_xss_vulnerabilities()
            self.check_sql_injection()
            self.check_open_ports()
            self.check_information_disclosure()
        except Exception as e:
            self.vulnerabilities.append(f"Error during scan: {str(e)}")
        return self.vulnerabilities

    def check_ssl_cert(self):
        parsed_url = urlparse(self.url)
        host = parsed_url.netloc.split(":")[0]

        try:
            if parsed_url.scheme.lower() == "https":
                context = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        if not cert:
                            self.vulnerabilities.append("SSL certificate not found or invalid.")
            else:
                self.vulnerabilities.append("Site does not use HTTPS – data in transit may be insecure.")
        except Exception as e:
            self.vulnerabilities.append(f"SSL Cert check failed: {str(e)}")

    def check_security_headers(self):
        try:
            r = self.session.get(self.url, timeout=5)
            required_headers = [
                "X-Frame-Options",
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options",
            ]
            for header in required_headers:
                if header not in r.headers:
                    self.vulnerabilities.append(f"Missing security header: {header}")
        except Exception as e:
            self.vulnerabilities.append(f"Security header check failed: {str(e)}")

    def check_xss_vulnerabilities(self):
        test_payload = "<script>alert('xss')</script>"
        test_url = urljoin(self.url, f"search?query={test_payload}")
        try:
            r = self.session.get(test_url, timeout=5)
            if test_payload in r.text:
                self.vulnerabilities.append("Potential XSS vulnerability found (reflected payload).")
        except Exception as e:
            self.vulnerabilities.append(f"XSS check failed: {str(e)}")

    def check_sql_injection(self):
        test_payload = "' OR '1'='1"
        test_url = urljoin(self.url, f"search?query={test_payload}")
        try:
            r = self.session.get(test_url, timeout=5)
            error_signatures = ["error in your SQL syntax", "sql syntax error", "unclosed quotation mark"]
            if any(err for err in error_signatures if err.lower() in r.text.lower()):
                self.vulnerabilities.append("Possible SQL injection vulnerability found.")
        except Exception as e:
            self.vulnerabilities.append(f"SQL injection check failed: {str(e)}")

    def check_open_ports(self):
        common_ports = [21, 22, 23, 80, 443, 3306, 8080]
        parsed_url = urlparse(self.url)
        host = parsed_url.netloc.split(":")[0]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    self.vulnerabilities.append(f"Open port detected: {port} (Host: {host})")
            except:
                continue

    def check_information_disclosure(self):
        sensitive_paths = ["/robots.txt", "/.git/", "/.env", "/backup.zip"]
        for path in sensitive_paths:
            try:
                r = self.session.get(urljoin(self.url, path), timeout=5)
                if r.status_code == 200:
                    self.vulnerabilities.append(f"Possible information disclosure: {path}")
            except:
                continue

# -------------------------------
# Helper function
# -------------------------------
def scan_website(url: str):
    scanner = SecurityScanner(url)
    return scanner.scan()

# -------------------------------
# Streamlit UI function
# -------------------------------
def vuln_scanner():
    st.title("🕷️ Advanced Web Vulnerability Scanner")
    st.markdown("Enter a target URL and perform common security checks like headers, SSL, XSS, SQLi, open ports, and more.")

    url = st.text_input("🔗 Enter URL to scan", placeholder="https://example.com")

    if st.button("🚀 Start Scan"):
        if url.strip():
            with st.spinner(f"Scanning {url.strip()}..."):
                results = scan_website(url.strip())

            st.subheader("📊 Scan Results")
            if results:
                for vuln in results:
                    st.error(vuln)
            else:
                st.success("✅ No vulnerabilities found!")
        else:
            st.warning("⚠️ Please enter a valid URL.")

# -------------------------------
# Entry Point
# -------------------------------
if __name__ == "__main__":
    main()
