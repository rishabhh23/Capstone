import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import socket
import ssl

# ---------------------------------------
# 1. SecurityScanner class (mimics your Flask version)
# ---------------------------------------
class SecurityScanner:
    def __init__(self, url):
        # Ensure the URL starts with http:// or https://
        self.url = url if url.startswith(("http://", "https://")) else "http://" + url
        self.vulnerabilities = []
        
        # Use a session with a more realistic User-Agent
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def scan(self):
        """
        Orchestrates all checks and returns a list of vulnerabilities found.
        """
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
        """
        Check the SSL certificate (if https is used). If it fails or is invalid, log it.
        """
        parsed_url = urlparse(self.url)
        host = parsed_url.netloc.split(":")[0]  # strip any port from netloc

        try:
            # Only attempt SSL check if the scheme is HTTPS, or if you want to try anyway:
            if parsed_url.scheme.lower() == "https":
                context = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        # If we reach here, we have a certificate. You could parse for validity or expiration:
                        # For example, check for subject or issuer:
                        if not cert:
                            self.vulnerabilities.append("SSL certificate not found or invalid.")
            else:
                # Not strictly a vulnerability, but can mention that the site is using HTTP
                self.vulnerabilities.append("Site does not use HTTPS – data in transit may be insecure.")
        except Exception as e:
            self.vulnerabilities.append(f"SSL Cert check failed: {str(e)}")

    def check_security_headers(self):
        """
        Look for missing security headers that are commonly recommended.
        """
        try:
            r = self.session.get(self.url, timeout=5)
            # Common recommended headers:
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
        """
        Simple example: see if injecting a script into a 'search' parameter is reflected.
        """
        test_payload = "<script>alert('xss')</script>"
        # This assumes a page or endpoint '/search?query=' exists. Adjust as needed.
        test_url = urljoin(self.url, f"search?query={test_payload}")
        try:
            r = self.session.get(test_url, timeout=5)
            # If the payload comes back in the response, it might be a sign of a reflection point
            if test_payload in r.text:
                self.vulnerabilities.append("Potential XSS vulnerability found (reflected payload).")
        except Exception as e:
            self.vulnerabilities.append(f"XSS check failed: {str(e)}")

    def check_sql_injection(self):
        """
        Attempt a naive SQL injection. If an error pattern or suspicious behavior is detected, report it.
        """
        # Another naive approach: a commonly used injection test
        test_payload = "' OR '1'='1"
        test_url = urljoin(self.url, f"search?query={test_payload}")
        try:
            r = self.session.get(test_url, timeout=5)
            # A typical SQL error signature in response (very naive)
            error_signatures = ["error in your SQL syntax", "sql syntax error", "unclosed quotation mark after the character string"]
            if any(err for err in error_signatures if err.lower() in r.text.lower()):
                self.vulnerabilities.append("Possible SQL injection vulnerability found.")
        except Exception as e:
            self.vulnerabilities.append(f"SQL injection check failed: {str(e)}")

    def check_open_ports(self):
        """
        Check a few common ports to see if they are open, which might indicate unexpected services exposed.
        """
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
            except Exception as e:
                # If we can't check the port, just continue
                pass

    def check_information_disclosure(self):
        """
        Check for common sensitive endpoints that might disclose info if publicly accessible.
        """
        # Feel free to add more: '/.git/', '/.env', '/.DS_Store', etc.
        sensitive_paths = ["/robots.txt", "/.git/", "/.env", "/backup.zip"]
        for path in sensitive_paths:
            url_to_test = urljoin(self.url, path)
            try:
                r = self.session.get(url_to_test, timeout=5)
                if r.status_code == 200:
                    self.vulnerabilities.append(f"Possible information disclosure: {path}")
            except:
                # If request fails, ignore
                pass

# ---------------------------------------
# 2. Helper function that uses the SecurityScanner class
# ---------------------------------------
def scan_website(url: str):
    scanner = SecurityScanner(url)
    return scanner.scan()

# ---------------------------------------
# 3. Streamlit UI
# ---------------------------------------
def vuln_scanner():
    st.title("🕷️ Advanced Web Vulnerability Scanner")

    url = st.text_input("Enter URL to scan", placeholder="example.com")

    if st.button("Start Scan"):
        if url.strip():
            with st.spinner(f"Scanning {url}..."):
                results = scan_website(url.strip())

            st.subheader("📊 Scan Results")
            if results:
                for vuln in results:
                    st.write(f"- {vuln}")
            else:
                st.success("No vulnerabilities found!")
        else:
            st.warning("Please enter a valid URL")

if __name__ == "__main__":
    main()
