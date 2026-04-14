# Website Risk Analyzer

## Overview
This project is a rule-based system designed to analyze websites and identify potential risk factors. It simulates how a fintech platform performs an initial risk assessment on merchant websites before onboarding.

The focus is on building a simple, explainable, and practical system using rule-based logic and basic external checks, instead of complex machine learning models.

---

## Approach

The system works in three main steps:

### 1. Data Extraction
The website is fetched using requests and parsed using BeautifulSoup.

From the page, the following data is extracted:
- Visible text content
- All hyperlinks
- Email addresses and phone numbers using regular expressions

---

### 2. Risk Detection (Internal Signals)
Based on extracted data, multiple checks are applied:

- Detects suspicious keywords related to earning or money
- Uses context filtering to reduce false positives
- Detects repeated keyword usage (keyword stuffing)
- Checks if contact details (email) are missing
- Identifies excessive number of links
- Detects high number of external links (possible redirection)
- Verifies if company/about information is present
- Flags login-related patterns without trust signals (possible phishing)
- Detects very low content websites

---

### 3. External Checks

Additional checks are performed using URL-level signals:

- Domain extension analysis (e.g., .online, .xyz)
- HTTPS verification (secure vs non-secure)
- Domain structure validation (unusually long domains)

---

## Scoring Logic

Each detected issue contributes to a risk score:

- High → 3 points  
- Medium → 2 points  
- Low → 1 point  

Final classification:

- Score ≥ 5 → HIGH RISK  
- Score ≥ 3 → MEDIUM RISK  
- Score < 3 → LOW RISK  

This ensures that multiple moderate issues can still indicate higher overall risk.

---

## Output Format

For each website, the system provides:

- Risk element detected  
- Source (Internal / External)  
- Category  
- Severity level  
- Reason for detection  
- Final risk classification  

The output is designed to be clear and explainable.

---

## Results

### 1. https://manifestwaresoftware.com/web/
- Detected multiple internal signals such as high link count
- Classified as MEDIUM RISK based on combined signals

### 2. https://zylotechindia.online/
- Suspicious domain extension detected
- Multiple internal risk indicators found
- Classified as HIGH RISK based on combined signals

---

## Limitations

- The system is rule-based and may produce false positives in some cases
- It does not verify domain age or ownership details
- It cannot detect highly sophisticated or well-designed scam websites
- It relies only on visible content and basic signals

---

## Future Improvements

- Integrate WHOIS API for domain age verification
- Add SSL certificate validation checks
- Use machine learning models for improved classification
- Enhance keyword detection using NLP techniques
- Build a user interface for easier interaction

---

## How to Run

Install dependencies:

pip install requests beautifulsoup4

Run the script:

python main.py

---

## Author
Arjun Kumar