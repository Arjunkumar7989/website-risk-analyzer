# Website Risk Analyzer

## Overview

This project is a rule-based system built to evaluate merchant websites and identify potential risk signals before onboarding. It is designed to simulate how fintech platforms perform early-stage risk screening using both on-site signals and external intelligence.

Instead of relying on complex machine learning models, the focus here is on building a **simple, explainable, and practical risk engine** where every decision can be clearly justified.

---

## Why this project?

In real-world onboarding systems, blindly trusting a website can lead to fraud risk. At the same time, being too strict can block legitimate businesses.

This project tries to balance both by answering one key question:

> *“Does the website’s content and external presence actually support its claims?”*

---

## How the System Works

The system evaluates each website in three stages:

### 1. Data Extraction

The website is fetched using `requests` and parsed using `BeautifulSoup`.

Instead of just scanning one page, the system also looks at important sections like:

* About
* Contact
* Privacy Policy

From these pages, it extracts:

* Visible text content
* Hyperlinks
* Emails and phone numbers

This helps in getting a more complete picture of the business.

---

### 2. Risk Detection (Internal Signals)

Once data is extracted, the system checks for inconsistencies and suspicious patterns:

* Presence of misleading keywords (earn, profit, guarantee, etc.)
* Detection of strong scam phrases (e.g., “earn money fast”)
* Missing trust signals (no company/about content)
* Missing privacy policy
* Lack of contact information
* Excessive number of links (possible spam or redirection behavior)

At the same time, **positive signals** like structured business content reduce the risk score.

---

### 3. External Intelligence

To avoid relying only on website content, the system validates signals externally:

* Domain type analysis (e.g., `.online`, `.xyz`)
* HTTPS verification
* Domain age using WHOIS (if available)
* SSL certificate validation
* Search-based reputation (checking for scam/fraud mentions)
* Email validation (generic vs domain-specific emails)

This step ensures that:

> *The website is not just well-designed, but also credible outside its own environment.*

---

## Scoring Logic

Each detected signal contributes to a weighted risk score:

* High severity → strong impact (25–30)
* Medium severity → moderate impact (15–20)
* Low severity → small impact
* Trust signals → reduce overall risk

Final decision:

* **Score ≥ 70 → BLOCK** (High risk)
* **Score ≥ 40 → REVIEW** (Needs manual verification)
* **Score < 40 → ALLOW** (Low risk)

This approach ensures that multiple moderate issues can still lead to a cautious decision.

---

## Output Format

For every website, the system produces a structured and explainable output:

* What was detected
* Which rule was triggered
* Severity level
* Supporting evidence
* Reasoning behind the flag
* Final risk score
* Final decision (ALLOW / REVIEW / BLOCK)

This makes the system easy to audit and understand.

---

## Results

### 1. https://manifestwaresoftware.com/web/

* Strong business-oriented content and structure
* Presence of contact and service-related information
* Some moderate signals like keyword usage and high link count
* WHOIS validation was unavailable

**Final Output:**

* Risk Score: ~60–65
* Decision: REVIEW

👉 The system takes a **conservative approach**, since not all external signals could be verified.

---

### 2. https://zylotechindia.online/

* Weak content structure and unclear business identity
* Suspicious keyword usage in promotional context
* Low-trust domain (.online)
* Limited external credibility

**Final Output:**

* Risk Score: ~75–85
* Decision: BLOCK

👉 Multiple risk signals combine to indicate a high-risk merchant.

---

## Limitations

* External checks like WHOIS may fail due to network/API issues
* Rule-based systems may produce false positives in edge cases
* Cannot detect highly sophisticated fraud websites
* External intelligence is based on basic heuristics

---

## Future Improvements

* Integrate real APIs for stronger external validation
* Improve keyword detection using NLP
* Add domain reputation scoring and blacklist checks
* Introduce confidence scoring
* Build a simple UI/dashboard for visualization

---

## How to Run

Install dependencies:

```
pip install requests beautifulsoup4
```

Run the script:

```
python main.py
```

---

## Author

Arjun Kumar
