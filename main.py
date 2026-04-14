import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin



suspicious_words = [
    "earn", "income", "profit", "investment", "money",
    "double", "guaranteed", "instant", "no risk",
    "work from home", "bonus", "free", "win"
]

severity_weights = {
    "High": 3,
    "Medium": 2,
    "Low": 1
}



def extract_data(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        text = soup.get_text().lower()

        links = []
        for tag in soup.find_all("a", href=True):
            links.append(urljoin(url, tag["href"]))

        emails = re.findall(r"[\w\.-]+@[\w\.-]+", text)

        return text, links, emails

    except:
        return "", [], []



def check_internal(url, text, links, emails):
    risks = []

    
    for word in suspicious_words:
        if word in text:
            risks.append({
                "element": "Suspicious Claims",
                "category": "Fraud",
                "severity": "High",
                "reason": f"keyword found: {word}",
                "rule": "keyword check"
            })
            break

    
    if len(emails) == 0:
        risks.append({
            "element": "No Contact Info",
            "category": "Trust",
            "severity": "Medium",
            "reason": "no email found",
            "rule": "contact check"
        })

    
    if len(links) > 150:
        risks.append({
            "element": "Too Many Links",
            "category": "Spam",
            "severity": "High",
            "reason": f"{len(links)} links",
            "rule": "link count"
        })
    elif len(links) > 80:
        risks.append({
            "element": "Too Many Links",
            "category": "Spam",
            "severity": "Medium",
            "reason": f"{len(links)} links",
            "rule": "link count"
        })

    
    domain = urlparse(url).netloc
    ext_count = 0

    for link in links:
        if urlparse(link).netloc != domain:
            ext_count += 1

    if ext_count > 20:
        risks.append({
            "element": "External Links High",
            "category": "Spam",
            "severity": "High",
            "reason": f"{ext_count} external links",
            "rule": "external links"
        })

    
    if "login" in text and "password" in text and len(emails) == 0:
        risks.append({
            "element": "Possible Phishing",
            "category": "Security",
            "severity": "High",
            "reason": "login without contact info",
            "rule": "login pattern"
        })

    return risks



def check_external(url):
    risks = []
    domain = urlparse(url).netloc

    if domain.endswith(".online") or domain.endswith(".xyz"):
        risks.append({
            "element": "Low Trust Domain",
            "category": "Domain",
            "severity": "High",
            "reason": "suspicious domain extension",
            "rule": "domain check"
        })

    if not url.startswith("https"):
        risks.append({
            "element": "No HTTPS",
            "category": "Security",
            "severity": "High",
            "reason": "website not secure",
            "rule": "https check"
        })

    return risks



def external_check(url, text):
    risks = []
    domain = urlparse(url).netloc

    keywords = ["scam", "fraud", "review"]
    matched = []

    for k in keywords:
        if k in text or k in domain:
            matched.append(k)

    
    if matched:
        risks.append({
            "element": "Negative Signals",
            "category": "Reputation",
            "severity": "High",
            "reason": f"found words: {matched}",
            "rule": "external match",
            "external_evidence": f"matched keywords: {matched}"
        })
    else:
        risks.append({
            "element": "No Negative Signals",
            "category": "Reputation",
            "severity": "Low",
            "reason": "no negative keywords found",
            "rule": "external match",
            "external_evidence": "no negative signals observed"
        })

    return risks



def final_score(risks):
    score = 0

    for r in risks:
        score += severity_weights[r["severity"]]

    if score >= 4:
        return "HIGH RISK"
    elif score >= 2:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"



def analyze(url):
    print("\n" + "=" * 50)
    print("Checking:", url)

    text, links, emails = extract_data(url)

    r1 = check_internal(url, text, links, emails)
    r2 = check_external(url)
    r3 = external_check(url, text)

    all_risks = r1 + r2 + r3

    if len(all_risks) == 0:
        print("No risks found")
    else:
        for r in all_risks:
            print("\nRisk:", r["element"])
            print("Category:", r["category"])
            print("Severity:", r["severity"])
            print("Rule:", r["rule"])
            print("Reason:", r["reason"])
            print("External Evidence:", r.get("external_evidence", "N/A"))

    print("\nFinal:", final_score(all_risks))



if __name__ == "__main__":
    urls = [
        "https://manifestwaresoftware.com/web/",
        "https://zylotechindia.online/"
    ]

    for u in urls:
        analyze(u)