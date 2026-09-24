#!/usr/bin/env python3
"""
SentryURL - URL Safety Checker
Usage: python url_checker.py <url>
"""

import argparse
import re
import socket
import ssl
import sys
from urllib.parse import urlparse
from datetime import datetime

import requests

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class URLSafetyChecker:
    def __init__(self, url):
        self.original_url = url
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        self.url = url
        self.parsed = urlparse(self.url)
        self.domain = self.parsed.hostname or ''
        self.issues = []
        self.warnings = []
        self.score = 100

    def add_issue(self, message, severity='high'):
        if severity == 'high':
            self.issues.append(message)
            self.score -= 20
        else:
            self.warnings.append(message)
            self.score -= 10

    def check_url_structure(self):
        print(f"\n{Colors.BOLD}[1] URL Structure Analysis{Colors.RESET}")

        ip_pattern = r'^\d{1,3}(?:\.\d{1,3}){3}$'
        if re.match(ip_pattern, self.domain):
            self.add_issue("Domain is an IP address (common phishing tactic)")
            print(f"  {Colors.RED}✗ IP address used instead of domain{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}✓ Domain name looks normal{Colors.RESET}")

        if '@' in self.url:
            self.add_issue("URL contains '@' symbol (can hide real destination)")
            print(f"  {Colors.RED}✗ '@' symbol found in URL{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}✓ No '@' symbol trick{Colors.RESET}")

        subdomain_count = self.domain.count('.')
        if subdomain_count > 3:
            self.add_issue(f"Too many subdomains ({subdomain_count})", 'medium')
            print(f"  {Colors.YELLOW}⚠ Unusual subdomains: {subdomain_count}{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}✓ Normal subdomain structure{Colors.RESET}")

        if len(self.url) > 100:
            self.add_issue("URL is unusually long", 'medium')
            print(f"  {Colors.YELLOW}⚠ Long URL: {len(self.url)} chars{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}✓ Normal URL length{Colors.RESET}")

        if self.domain.count('-') > 2:
            self.add_issue("Excessive hyphens in domain", 'medium')
            print(f"  {Colors.YELLOW}⚠ Multiple hyphens in domain{Colors.RESET}")

        if 'xn--' in self.domain.lower():
            self.add_issue("Domain uses Punycode (possible homograph attack)")
            print(f"  {Colors.RED}✗ Punycode domain detected{Colors.RESET}")

    def check_ssl(self):
        print(f"\n{Colors.BOLD}[2] SSL/TLS Certificate Check{Colors.RESET}")
        if self.parsed.scheme != 'https':
            self.add_issue("Site does not use HTTPS")
            print(f"  {Colors.RED}✗ No HTTPS - not encrypted{Colors.RESET}")
            return

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    issued_to = dict(x[0] for x in cert['subject'])
                    expiry_date = datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                    )
                    days_left = (expiry_date - datetime.now()).days

                    print(f"  {Colors.GREEN}✓ Valid SSL certificate{Colors.RESET}")
                    print(f"    Issued to: {issued_to.get('commonName', 'N/A')}")
                    print(f"    Issued by: {issuer.get('organizationName', 'N/A')}")
                    print(f"    Expires in: {days_left} days")

                    if days_left < 15:
                        self.add_issue(f"SSL expiring soon ({days_left} days)", 'medium')
                        print(f"  {Colors.YELLOW}⚠ Expiring soon!{Colors.RESET}")

        except ssl.SSLCertVerificationError:
            self.add_issue("SSL certificate verification failed")
            print(f"  {Colors.RED}✗ Invalid/untrusted certificate{Colors.RESET}")
        except Exception as e:
            self.add_issue(f"SSL check failed: {str(e)}", 'medium')
            print(f"  {Colors.YELLOW}⚠ Could not verify SSL: {str(e)}{Colors.RESET}")

    def check_domain_age(self):
        print(f"\n{Colors.BOLD}[3] Domain Age Check{Colors.RESET}")
        if not WHOIS_AVAILABLE:
            print(f"  {Colors.YELLOW}⚠ Install: pip install python-whois{Colors.RESET}")
            return

        try:
            w = whois.whois(self.domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                if creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(tzinfo=None)

                age_days = (datetime.now() - creation_date).days
                print(f"  Domain created: {creation_date.strftime('%Y-%m-%d')}")
                print(f"  Age: {age_days / 365:.1f} years")

                if age_days < 90:
                    self.add_issue(
                        f"Domain very new ({age_days} days) - phishing red flag"
                    )
                    print(f"  {Colors.RED}✗ Less than 90 days old!{Colors.RESET}")
                elif age_days < 365:
                    self.add_issue(f"Domain relatively new ({age_days} days)", 'medium')
                    print(f"  {Colors.YELLOW}⚠ Less than 1 year old{Colors.RESET}")
                else:
                    print(f"  {Colors.GREEN}✓ Established domain history{Colors.RESET}")
            else:
                print(f"  {Colors.YELLOW}⚠ Creation date not found{Colors.RESET}")

        except Exception as e:
            print(f"  {Colors.YELLOW}⚠ WHOIS lookup failed: {str(e)}{Colors.RESET}")

    def check_http_response(self):
        print(f"\n{Colors.BOLD}[4] HTTP Response & Security Headers{Colors.RESET}")

        try:
            response = requests.get(
                self.url,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "SentryURL/1.0"}
            )

            if response.history:
                print(f"  {Colors.YELLOW}⚠ {len(response.history)} redirect(s):{Colors.RESET}")
                for i, resp in enumerate(response.history):
                    print(f"    {i + 1}. {resp.url} -> {resp.status_code}")
                print(f"    Final: {response.url}")

                if len(response.history) > 2:
                    self.add_issue(
                        f"Multiple redirects ({len(response.history)})", 'medium'
                    )
            else:
                print(f"  {Colors.GREEN}✓ No suspicious redirects{Colors.RESET}")

            print(f"  Status Code: {response.status_code}")

            headers = response.headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'X-Content-Type-Options': 'Content-Type protection',
                'X-Frame-Options': 'Clickjacking protection',
                'Content-Security-Policy': 'CSP'
            }

            missing = [
                name for h, name in security_headers.items()
                if h not in headers
            ]

            if missing:
                print(
                    f"  {Colors.YELLOW}⚠ Missing headers: "
                    f"{', '.join(missing)}{Colors.RESET}"
                )
                self.add_issue(
                    f"Missing security headers: {', '.join(missing)}", 'medium'
                )
            else:
                print(
                    f"  {Colors.GREEN}✓ All key security headers present"
                    f"{Colors.RESET}"
                )

        except requests.exceptions.SSLError:
            self.add_issue("SSL error during connection")
            print(f"  {Colors.RED}✗ SSL Error{Colors.RESET}")
        except requests.exceptions.ConnectionError:
            self.add_issue("Could not connect to site")
            print(f"  {Colors.RED}✗ Connection failed{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.YELLOW}⚠ Error: {str(e)}{Colors.RESET}")

    def generate_report(self):
        print(f"\n{Colors.BOLD}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}FINAL REPORT: {self.original_url}{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 50}{Colors.RESET}")

        self.score = max(0, self.score)

        if self.score >= 80:
            verdict = f"{Colors.GREEN}SAFE{Colors.RESET}"
        elif self.score >= 50:
            verdict = f"{Colors.YELLOW}SUSPICIOUS - Review Needed{Colors.RESET}"
        else:
            verdict = f"{Colors.RED}HIGH RISK{Colors.RESET}"

        print(f"\nSafety Score: {self.score}/100")
        print(f"Verdict: {verdict}\n")

        if self.issues:
            print(f"{Colors.RED}Critical Issues:{Colors.RESET}")
            for issue in self.issues:
                print(f"  • {issue}")

        if self.warnings:
            print(f"\n{Colors.YELLOW}Warnings:{Colors.RESET}")
            for warning in self.warnings:
                print(f"  • {warning}")

        if not self.issues and not self.warnings:
            print(f"{Colors.GREEN}No issues detected.{Colors.RESET}")

        print()

    def run_all_checks(self):
        print(
            f"{Colors.BOLD}{Colors.BLUE}"
            f"Scanning: {self.original_url}"
            f"{Colors.RESET}"
        )
        self.check_url_structure()
        self.check_ssl()
        self.check_domain_age()
        self.check_http_response()
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(description='SentryURL - URL Safety Checker')
    parser.add_argument('url', nargs='?', help='URL to check')
    parser.add_argument('-f', '--file', help='File with list of URLs')
    args = parser.parse_args()

    if args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]

        for url in urls:
            URLSafetyChecker(url).run_all_checks()
            print("\n" + "-" * 60 + "\n")

    elif args.url:
        URLSafetyChecker(args.url).run_all_checks()

    else:
        print(f"{Colors.BOLD}SentryURL - URL Safety Checker{Colors.RESET}")

        while True:
            url = input("\nURL (or 'quit'): ").strip()

            if url.lower() in ('quit', 'exit', 'q'):
                break

            if url:
                URLSafetyChecker(url).run_all_checks()


if __name__ == '__main__':
    main()
