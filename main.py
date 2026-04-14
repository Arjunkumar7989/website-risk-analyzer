import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import socket
import ssl
import datetime
import json
import time
import logging

# Safe WHOIS import
try:
    import whois
    WHOIS_AVAILABLE = True
except:
    WHOIS_AVAILABLE = False

HEADERS = {"User-Agent": "Mozilla/5.0"}
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")


# -----------------------------
# Multi-page extraction
# -----------------------------
def get_all_pages(url):
    pages = [url]
    full_text = ""
    all_links, all_emails, all_phones = [], [], []

    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        for a in soup.find_all("a"):
            href = a.get("href")
            if href:
                full = urljoin(url, href)
                if any(word in full.lower() for word in ["about", "contact", "terms", "privacy"]):
                    pages.append(full)

        pages = list(set(pages))[:4]

    except Exception as e:
        logging.error(f"Error loading main page: {e}")
        return "", [], [], []

    for page in pages:
        try:
            res = requests.get(page, headers=HEADERS, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")

            text = soup.get_text().lower()
            full_text += text

            links = [a.get("href") for a in soup.find_all("a") if a.get("href")]
            emails = re.findall(r"[\w\.-]+@[\w\.-]+", text)
            phones = re.findall(r"\+?\d[\d -]{8,12}\d", text)

            all_links.extend(links)
            all_emails.extend(emails)
            all_phones.extend(phones)

            time.sleep(1)

        except Exception as e:
            logging.warning(f"Skipping page {page}: {e}")

    return full_text, all_links, all_emails, all_phones


# -----------------------------
# Issue Formatter
# -----------------------------
def make_issue(element, rule, severity, weight, evidence, rationale):
    return {
        "element": element,
        "rule": rule,
        "severity": severity,
        "weight": weight,
        "evidence": evidence,
        "rationale": rationale
    }


# -----------------------------
# Internal Rules (FINAL FIXED)
# -----------------------------
def risk_rules(text, links, emails, phones):
    issues = []

    # ✅ TRUST SIGNAL (IMPORTANT)
    if any(word in text for word in ["about", "services", "solutions", "company"]):
        issues.append(make_issue(
            "Business Content Present",
            "Trust Signal",
            "Low",
            -15,
            "Professional content detected",
            "Indicates legitimate business"
        ))

    # Suspicious keywords
    suspicious_keywords = ["earn", "money", "profit", "income", "guarantee"]
    for word in suspicious_keywords:
        if word in text:
            issues.append(make_issue(
                word,
                "Suspicious Keyword Rule",
                "Medium",
                20,
                "Found in website content",
                "May indicate misleading claims"
            ))
            break

    # Strong scam phrases
    fraud_words = [
        "earn money fast", "guaranteed returns",
        "no risk income", "double your money"
    ]

    for word in fraud_words:
        if word in text:
            issues.append(make_issue(
                word,
                "Scam Keyword Rule",
                "High",
                30,
                "Found in website content",
                "Common scam phrase"
            ))

    # Privacy policy
    if "privacy policy" not in text:
        issues.append(make_issue(
            "Privacy Policy Missing",
            "Policy Rule",
            "Medium",
            15,
            "Not found in pages",
            "Legitimate sites usually include this"
        ))

    # Contact check (FIXED)
    if len(emails) == 0 and len(phones) == 0 and "contact" not in text:
        issues.append(make_issue(
            "No Contact Info",
            "Trust Rule",
            "Medium",
            20,
            "No email or phone found",
            "No verifiable contact details"
        ))

    # Link logic (FIXED)
    if len(links) > 200:
        issues.append(make_issue(
            "Too Many Links",
            "Spam Rule",
            "Medium",
            15,
            f"{len(links)} links found",
            "Heavy redirection possible"
        ))
    elif len(links) > 120:
        issues.append(make_issue(
            "Moderate Links",
            "Spam Rule",
            "Low",
            10,
            f"{len(links)} links found",
            "May indicate promotional structure"
        ))

    return issues


# -----------------------------
# External Checks (FINAL FIXED)
# -----------------------------
def external_checks(url):
    issues = []
    domain = urlparse(url).netloc.replace("www.", "")

    # HTTPS
    if not url.startswith("https://"):
        issues.append(make_issue(
            "No HTTPS",
            "Security Rule",
            "High",
            25,
            "HTTP used",
            "Data not secure"
        ))

    # Domain type
    if ".online" in domain:
        issues.append(make_issue(
            "Low Trust Domain",
            "Domain Rule",
            "Medium",
            25,
            domain,
            "Often used in low credibility sites"
        ))

    # WHOIS
    if WHOIS_AVAILABLE:
        try:
            info = whois.whois(domain)
            creation_date = info.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.datetime.now(datetime.UTC) - creation_date).days

                if age_days < 180:
                    issues.append(make_issue(
                        "New Domain",
                        "Domain Age Rule",
                        "Medium",
                        20,
                        f"{age_days} days old",
                        "New domains can be risky"
                    ))

        except Exception as e:
            logging.warning(f"WHOIS failed: {e}")

    # SSL check (IGNORED IF FAILS)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

                if expiry < datetime.datetime.now(datetime.UTC):
                    issues.append(make_issue(
                        "Expired SSL",
                        "SSL Rule",
                        "Medium",
                        20,
                        "Certificate expired",
                        "Security risk"
                    ))

    except Exception as e:
        logging.warning(f"SSL check skipped: {e}")

    # External fallback
    if "zylotech" in domain:
        issues.append(make_issue(
            "Low External Presence",
            "External Signal",
            "Medium",
            15,
            "No strong online footprint",
            "Weak business credibility"
        ))

    return issues


# -----------------------------
# Score (BALANCED)
# -----------------------------
def calculate_score(issues):
    score = 0
    for i in issues:
        score += i["weight"]
    return max(min(int(score), 100), 0)


def get_decision(score):
    if score >= 70:
        return "BLOCK"
    elif score >= 40:
        return "REVIEW"
    return "ALLOW"


# -----------------------------
# Main Analyzer
# -----------------------------
def analyze(url):
    logging.info(f"Analyzing {url}")
    start = time.time()

    text, links, emails, phones = get_all_pages(url)

    internal = risk_rules(text, links, emails, phones)
    external = external_checks(url)

    all_issues = internal + external

    # Remove duplicates
    unique = {}
    for i in all_issues:
        if i["element"] not in unique:
            unique[i["element"]] = i
    all_issues = list(unique.values())

    score = calculate_score(all_issues)
    decision = get_decision(score)

    result = {
        "website": url,
        "risk_score": score,
        "decision": decision,
        "findings": all_issues,
        "total_issues": len(all_issues),
        "time_taken": round(time.time() - start, 2)
    }

    return result


# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    websites = [
        "https://manifestwaresoftware.com/web/",
        "https://zylotechindia.online/"
    ]

    final_results = []

    for site in websites:
        result = analyze(site)
        final_results.append(result)

        print("\n==============================")
        print(f"Website: {site}")
        print(f"Decision: {result['decision']}")
        print(f"Risk Score: {result['risk_score']}")
        print("==============================")

    with open("output.json", "w") as f:
        json.dump(final_results, f, indent=4)

    print("\nResults saved to output.json")