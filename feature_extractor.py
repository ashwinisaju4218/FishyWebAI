import re
import ssl
import socket
import whois
import requests

from urllib.parse import urlparse
from datetime import datetime


def extract_features(url):

    features = []
    live_checks = []

    parsed = urlparse(url)
    domain = parsed.netloc

    # =========================
    # 1. IP Address Detection
    # =========================

    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'

    if re.search(ip_pattern, url):
        features.append(-1)
        live_checks.append("⚠️ URL contains IP address")
    else:
        features.append(1)

    # =========================
    # 2. URL Length
    # =========================

    if len(url) < 54:
        features.append(1)

    elif 54 <= len(url) <= 75:
        features.append(0)
        live_checks.append("⚠️ URL length is suspicious")

    else:
        features.append(-1)
        live_checks.append("⚠️ URL is extremely long")

    # =========================
    # 3. URL Shortener
    # =========================

    shortening_services = r"bit\.ly|goo\.gl|tinyurl|t\.co"

    if re.search(shortening_services, url):
        features.append(-1)
        live_checks.append("⚠️ URL uses shortening service")
    else:
        features.append(1)

    # =========================
    # 4. @ Symbol
    # =========================

    if "@" in url:
        features.append(-1)
        live_checks.append("⚠️ URL contains @ symbol")
    else:
        features.append(1)

    # =========================
    # 5. Double Slash Redirect
    # =========================

    if url.rfind('//') > 6:
        features.append(-1)
        live_checks.append("⚠️ URL contains redirecting //")
    else:
        features.append(1)

    # =========================
    # 6. Hyphen in Domain
    # =========================

    if '-' in domain:
        features.append(-1)
        live_checks.append("⚠️ Suspicious '-' in domain")
    else:
        features.append(1)

    # =========================
    # 7. Subdomains
    # =========================

    dots = domain.count('.')

    if dots == 1:
        features.append(1)

    elif dots == 2:
        features.append(0)
        live_checks.append("⚠️ Multiple subdomains detected")

    else:
        features.append(-1)
        live_checks.append("⚠️ Too many subdomains")

    # =========================
    # LIVE WEBSITE CHECK
    # =========================

    try:
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            live_checks.append("✅ Website is reachable")
        else:
            live_checks.append("⚠️ Website returned unusual status code")

    except:
        live_checks.append("❌ Website appears offline")

    # =========================
    # SSL CERTIFICATE CHECK
    # =========================

    try:

        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain):

                live_checks.append("✅ SSL Certificate is valid")

    except:
        live_checks.append("⚠️ SSL Certificate invalid or missing")

    # =========================
    # DOMAIN AGE CHECK
    # =========================

    try:

        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.now() - creation_date).days

        if age_days < 30:
            live_checks.append("⚠️ Domain is VERY new")

        elif age_days < 180:
            live_checks.append("⚠️ Domain is relatively new")

        else:
            live_checks.append("✅ Domain age looks safe")

    except:
        live_checks.append("⚠️ Could not determine domain age")

    return features, live_checks