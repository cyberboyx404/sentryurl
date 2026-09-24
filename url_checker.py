#!/usr/bin/env python3
"""
SentryURL - URL Safety & Phishing Indicator Scanner

Usage:
    python url_checker.py
    python url_checker.py <url>
    python url_checker.py -f urls.txt

Mode:
    Defensive / Authorized Security Testing
"""

import argparse
import re
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

import requests

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


# ============================================================
# Colors
# ============================================================

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


# ============================================================
# Banner
# ============================================================

BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
   ____             _                  _   _ ____  _
  / ___|  ___ _ __ | |_ _ __ _   _  | | | |  _ \\| |
  \\___ \\ / _ \\ '_ \\| __| '__| | | | | | | | |_) | |
   ___) |  __/ | | | |_| |  | |_| | | |_| |  _ <| |
  |____/ \\___|_| |_|\\__|_|   \\__, |  \\___/|_| \\_\\_|
                             |___/
{Colors.RESET}
{Colors.BOLD}{Colors.WHITE}  SentryURL v1.0{Colors.RESET}
  URL Safety & Phishing Indicator Scanner

{Colors.CYAN}  Author : cyberboyx404
  Version: 1.0.0
  Mode   : Defensive / Authorized Security Testing
{Colors.RESET}
"""


# ============================================================
# URL Safety Checker
# ============================================================

class URLSafetyChecker:

    def __init__(self, url):

        self.original_url = url.strip()

        # Automatically use HTTPS when scheme is missing
        if not self.original_url.startswith(
            ('http://', 'https://')
        ):
            self.url = 'https://' + self.original_url
        else:
            self.url = self.original_url

        self.parsed = urlparse(self.url)
        self.domain = self.parsed.hostname or ''

        self.issues = []
        self.warnings = []

        self.score = 100


    # ========================================================
    # Score Handling
    # ========================================================

    def add_issue(self, message, severity='high'):

        if severity == 'high':
            self.issues.append(message)
            self.score -= 20

        else:
            self.warnings.append(message)
            self.score -= 10


    # ========================================================
    # URL Structure
    # ========================================================

    def check_url_structure(self):

        print(
            f"\n{Colors.BOLD}"
            f"[1] URL Structure Analysis"
            f"{Colors.RESET}"
        )

        # IP address
        ip_pattern = r'^\d{1,3}(?:\.\d{1,3}){3}$'

        if re.match(ip_pattern, self.domain):

            self.add_issue(
                "Domain is an IP address "
                "(common phishing indicator)"
            )

            print(
                f"  {Colors.RED}"
                f"✗ IP address used instead of domain"
                f"{Colors.RESET}"
            )

        else:

            print(
                f"  {Colors.GREEN}"
                f"✓ Domain name looks normal"
                f"{Colors.RESET}"
            )


        # @ trick
        if '@' in self.url:

            self.add_issue(
                "URL contains '@' symbol "
                "(can hide the real destination)"
            )

            print(
                f"  {Colors.RED}"
                f"✗ '@' symbol found in URL"
                f"{Colors.RESET}"
            )

        else:

            print(
                f"  {Colors.GREEN}"
                f"✓ No '@' symbol trick"
                f"{Colors.RESET}"
            )


        # Subdomains
        subdomain_count = self.domain.count('.')

        if subdomain_count > 3:

            self.add_issue(
                f"Too many subdomains ({subdomain_count})",
                'medium'
            )

            print(
                f"  {Colors.YELLOW}"
                f"⚠ Unusual subdomains: "
                f"{subdomain_count}"
                f"{Colors.RESET}"
            )

        else:

            print(
                f"  {Colors.GREEN}"
                f"✓ Normal subdomain structure"
                f"{Colors.RESET}"
            )


        # URL length
        if len(self.url) > 100:

            self.add_issue(
                "URL is unusually long",
                'medium'
            )

            print(
                f"  {Colors.YELLOW}"
                f"⚠ Long URL: {len(self.url)} chars"
                f"{Colors.RESET}"
            )

        else:

            print(
                f"  {Colors.GREEN}"
                f"✓ Normal URL length"
                f"{Colors.RESET}"
            )


        # Hyphens
        if self.domain.count('-') > 2:

            self.add_issue(
                "Excessive hyphens in domain",
                'medium'
            )

            print(
                f"  {Colors.YELLOW}"
                f"⚠ Multiple hyphens in domain"
                f"{Colors.RESET}"
            )


        # Punycode
        if 'xn--' in self.domain.lower():

            self.add_issue(
                "Domain uses Punycode "
                "(possible homograph indicator)"
            )

            print(
                f"  {Colors.RED}"
                f"✗ Punycode domain detected"
                f"{Colors.RESET}"
            )


        # Suspicious keywords
        suspicious_keywords = [
            'login',
            'verify',
            'verification',
            'password',
            'credential',
            'secure',
            'account',
            'update',
            'confirm'
        ]

        found_keywords = [
            keyword
            for keyword in suspicious_keywords
            if keyword in self.url.lower()
        ]

        if found_keywords:

            self.add_issue(
                "Suspicious keywords: "
                + ", ".join(found_keywords),
                'medium'
            )

            print(
                f"  {Colors.YELLOW}"
                f"⚠ Suspicious keywords: "
                f"{', '.join(found_keywords)}"
                f"{Colors.RESET}"
            )

        else:

            print(
                f"  {Colors.GREEN}"
                f"✓ No obvious phishing keywords"
                f"{Colors.RESET}"
            )


    # ========================================================
    # SSL / TLS
    # ========================================================

    def check_ssl(self):

        print(
            f"\n{Colors.BOLD}"
            f"[2] SSL/TLS Certificate Check"
            f"{Colors.RESET}"
        )

        if self.parsed.scheme != 'https':

            self.add_issue(
                "Site does not use HTTPS"
            )

            print(
                f"  {Colors.RED}"
                f"✗ No HTTPS - connection is not encrypted"
                f"{Colors.RESET}"
            )

            return


        try:

            context = ssl.create_default_context()

            port = self.parsed.port or 443

            with socket.create_connection(
                (self.domain, port),
                timeout=5
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=self.domain
                ) as ssock:

                    cert = ssock.getpeercert()

                    issuer = dict(
                        x[0]
                        for x in cert.get('issuer', [])
                    )

                    issued_to = dict(
                        x[0]
                        for x in cert.get('subject', [])
                    )

                    expiry_date = datetime.strptime(
                        cert['notAfter'],
                        '%b %d %H:%M:%S %Y %Z'
                    )

                    days_left = (
                        expiry_date - datetime.now()
                    ).days


                    print(
                        f"  {Colors.GREEN}"
                        f"✓ Valid SSL certificate"
                        f"{Colors.RESET}"
                    )

                    print(
                        f"    Issued to: "
                        f"{issued_to.get('commonName', 'N/A')}"
                    )

                    print(
                        f"    Issued by: "
                        f"{issuer.get('organizationName', 'N/A')}"
                    )

                    print(
                        f"    Expires in: "
                        f"{days_left} days"
                    )


                    if days_left < 0:

                        self.add_issue(
                            "SSL certificate has expired"
                        )

                        print(
                            f"  {Colors.RED}"
                            f"✗ Certificate expired"
                            f"{Colors.RESET}"
                        )

                    elif days_left < 15:

                        self.add_issue(
                            f"SSL expiring soon "
                            f"({days_left} days)",
                            'medium'
                        )

                        print(
                            f"  {Colors.YELLOW}"
                            f"⚠ Certificate expiring soon"
                            f"{Colors.RESET}"
                        )


        except ssl.SSLCertVerificationError:

            self.add_issue(
                "SSL certificate verification failed"
            )

            print(
                f"  {Colors.RED}"
                f"✗ Invalid/untrusted certificate"
                f"{Colors.RESET}"
            )


        except Exception as e:

            self.add_issue(
                "Could not verify SSL certificate",
                'medium'
            )

            print(
                f"  {Colors.YELLOW}"
                f"⚠ Could not verify SSL"
                f"{Colors.RESET}"
            )


    # ========================================================
    # Domain Age
    # ========================================================

    def check_domain_age(self):

        print(
            f"\n{Colors.BOLD}"
            f"[3] Domain Age Check"
            f"{Colors.RESET}"
        )


        if not WHOIS_AVAILABLE:

            print(
                f"  {Colors.YELLOW}"
                f"⚠ WHOIS library not installed"
                f"{Colors.RESET}"
            )

            return


        try:

            w = whois.whois(self.domain)

            creation_date = w.creation_date


            if isinstance(
                creation_date,
                list
            ):

                creation_date = creation_date[0]


            if creation_date:

                if creation_date.tzinfo is not None:

                    creation_date = (
                        creation_date.replace(
                            tzinfo=None
                        )
                    )


                age_days = (
                    datetime.now() -
                    creation_date
                ).days


                print(
                    f"  Domain created: "
                    f"{creation_date.strftime('%Y-%m-%d')}"
                )

                print(
                    f"  Age: "
                    f"{age_days / 365:.1f} years"
                )


                if age_days < 90:

                    self.add_issue(
                        f"Domain very new "
                        f"({age_days} days)",
                        'medium'
                    )

                    print(
                        f"  {Colors.RED}"
                        f"✗ Less than 90 days old"
                        f"{Colors.RESET}"
                    )


                elif age_days < 365:

                    self.add_issue(
                        f"Domain relatively new "
                        f"({age_days} days)",
                        'medium'
                    )

                    print(
                        f"  {Colors.YELLOW}"
                        f"⚠ Less than 1 year old"
                        f"{Colors.RESET}"
                    )


                else:

                    print(
                        f"  {Colors.GREEN}"
                        f"✓ Established domain history"
                        f"{Colors.RESET}"
                    )


            else:

                print(
                    f"  {Colors.YELLOW}"
                    f"⚠ Creation date not found"
                    f"{Colors.RESET}"
                )


        except Exception:

            print(
                f"  {Colors.YELLOW}"
                f"⚠ Creation date not found"
                f"{Colors.RESET}"
            )


    # ========================================================
    # HTTP Response
    # ========================================================

    def check_http_response(self):

        print(
            f"\n{Colors.BOLD}"
            f"[4] HTTP Response & Security Headers"
            f"{Colors.RESET}"
        )


        try:

            response = requests.get(
                self.url,
                timeout=10,
                allow_redirects=True,
                headers={
                    "User-Agent":
                    "SentryURL/1.0 "
                    "(Defensive Security Scanner)"
                }
            )


            # Redirects
            if response.history:

                print(
                    f"  {Colors.YELLOW}"
                    f"⚠ {len(response.history)} "
                    f"redirect(s):"
                    f"{Colors.RESET}"
                )

                for i, resp in enumerate(
                    response.history
                ):

                    print(
                        f"    {i + 1}. "
                        f"{resp.url} "
                        f"-> {resp.status_code}"
                    )


                print(
                    f"    Final: "
                    f"{response.url}"
                )


                if len(response.history) > 2:

                    self.add_issue(
                        f"Multiple redirects "
                        f"({len(response.history)})",
                        'medium'
                    )

            else:

                print(
                    f"  {Colors.GREEN}"
                    f"✓ No redirects"
                    f"{Colors.RESET}"
                )


            # HTTP status
            print(
                f"  {Colors.GREEN}"
                f"✓ HTTP Status: "
                f"{response.status_code}"
                f"{Colors.RESET}"
            )


            # Security headers
            headers = response.headers

            security_headers = {

                'Strict-Transport-Security':
                    'HSTS',

                'X-Content-Type-Options':
                    'X-Content-Type-Options',

                'X-Frame-Options':
                    'X-Frame-Options',

                'Content-Security-Policy':
                    'Content-Security-Policy',

                'Referrer-Policy':
                    'Referrer-Policy'
            }


            missing = [
                name
                for header, name
                in security_headers.items()
                if header not in headers
            ]


            if missing:

                print(
                    f"  {Colors.YELLOW}"
                    f"⚠ Missing headers: "
                    f"{', '.join(missing)}"
                    f"{Colors.RESET}"
                )

                self.add_issue(
                    "Missing security headers: "
                    + ", ".join(missing),
                    'medium'
                )

            else:

                print(
                    f"  {Colors.GREEN}"
                    f"✓ All key security headers present"
                    f"{Colors.RESET}"
                )


        except requests.exceptions.SSLError:

            self.add_issue(
                "SSL error during HTTP connection"
            )

            print(
                f"  {Colors.RED}"
                f"✗ SSL Error"
                f"{Colors.RESET}"
            )


        except requests.exceptions.ConnectionError:

            self.add_issue(
                "Could not connect to site"
            )

            print(
                f"  {Colors.RED}"
                f"✗ Connection failed"
                f"{Colors.RESET}"
            )


        except requests.exceptions.Timeout:

            self.add_issue(
                "Connection timed out"
            )

            print(
                f"  {Colors.RED}"
                f"✗ Connection timed out"
                f"{Colors.RESET}"
            )


        except Exception:

            print(
                f"  {Colors.YELLOW}"
                f"⚠ HTTP check failed"
                f"{Colors.RESET}"
            )


    # ========================================================
    # Final Report
    # ========================================================

    def generate_report(self):

        print(
            f"\n{Colors.BOLD}"
            f"{'=' * 60}"
            f"{Colors.RESET}"
        )

        print(
            f"{Colors.BOLD}"
            f"FINAL REPORT: {self.domain}"
            f"{Colors.RESET}"
        )

        print(
            f"{Colors.BOLD}"
            f"{'=' * 60}"
            f"{Colors.RESET}"
        )


        self.score = max(
            0,
            min(100, self.score)
        )


        if self.score >= 80:

            verdict = (
                f"{Colors.GREEN}"
                f"LOW RISK"
                f"{Colors.RESET}"
            )

        elif self.score >= 50:

            verdict = (
                f"{Colors.YELLOW}"
                f"SUSPICIOUS - Review Needed"
                f"{Colors.RESET}"
            )

        else:

            verdict = (
                f"{Colors.RED}"
                f"HIGH RISK"
                f"{Colors.RESET}"
            )


        print(
            f"\n{Colors.BOLD}"
            f"Safety Score: "
            f"{self.score}/100"
            f"{Colors.RESET}"
        )

        print(
            f"{Colors.BOLD}"
            f"Verdict: "
            f"{verdict}"
            f"{Colors.RESET}"
        )


        if self.issues:

            print(
                f"\n{Colors.RED}"
                f"Critical Issues:"
                f"{Colors.RESET}"
            )

            for issue in self.issues:

                print(
                    f"  {Colors.RED}"
                    f"• {issue}"
                    f"{Colors.RESET}"
                )


        if self.warnings:

            print(
                f"\n{Colors.YELLOW}"
                f"Warnings:"
                f"{Colors.RESET}"
            )

            for warning in self.warnings:

                print(
                    f"  {Colors.YELLOW}"
                    f"• {warning}"
                    f"{Colors.RESET}"
                )


        if not self.issues and not self.warnings:

            print(
                f"\n{Colors.GREEN}"
                f"No major issues detected."
                f"{Colors.RESET}"
            )


        print()


    # ========================================================
    # Run All Checks
    # ========================================================

    def run_all_checks(self):

        print(
            f"\n{Colors.BOLD}"
            f"{Colors.BLUE}"
            f"Scanning: {self.url}"
            f"{Colors.RESET}"
        )

        self.check_url_structure()
        self.check_ssl()
        self.check_domain_age()
        self.check_http_response()
        self.generate_report()


# ============================================================
# Main
# ============================================================

def main():

    print(BANNER)

    print(
        f"{Colors.BOLD}"
        f"{Colors.CYAN}"
        f"{'=' * 60}"
        f"{Colors.RESET}"
    )


    parser = argparse.ArgumentParser(
        description=(
            "SentryURL - URL Safety & "
            "Phishing Indicator Scanner"
        )
    )


    parser.add_argument(
        'url',
        nargs='?',
        help='URL to check'
    )


    parser.add_argument(
        '-f',
        '--file',
        help='File containing URLs'
    )


    args = parser.parse_args()


    # File mode
    if args.file:

        try:

            with open(
                args.file,
                'r',
                encoding='utf-8'
            ) as f:

                urls = [
                    line.strip()
                    for line in f
                    if line.strip()
                ]


            for url in urls:

                URLSafetyChecker(
                    url
                ).run_all_checks()

                print(
                    "\n"
                    + "-" * 60
                    + "\n"
                )


        except FileNotFoundError:

            print(
                f"{Colors.RED}"
                f"File not found: {args.file}"
                f"{Colors.RESET}"
            )


        return


    # Direct URL
    if args.url:

        URLSafetyChecker(
            args.url
        ).run_all_checks()

        return


    # Interactive mode
    while True:

        try:

            url = input(
                f"\n{Colors.BOLD}"
                f"{Colors.CYAN}"
                f"URL (or 'quit'): "
                f"{Colors.RESET}"
            ).strip()


            if url.lower() in (
                'quit',
                'exit',
                'q'
            ):

                print(
                    f"\n{Colors.GREEN}"
                    f"SentryURL terminated."
                    f"{Colors.RESET}"
                )

                break


            if not url:
                continue


            URLSafetyChecker(
                url
            ).run_all_checks()


        except KeyboardInterrupt:

            print(
                f"\n\n{Colors.YELLOW}"
                f"Interrupted by user."
                f"{Colors.RESET}"
            )

            break


        except EOFError:

            break


# ============================================================
# Entry Point
# ============================================================

if __name__ == '__main__':
    main()
