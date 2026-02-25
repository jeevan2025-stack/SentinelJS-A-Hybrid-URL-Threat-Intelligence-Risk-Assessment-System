# 🛡️ SentinelJS: Hybrid URL Threat Intelligence System

**SentinelJS** is a full-stack cybersecurity Proof of Concept (PoC) designed to detect malicious URLs in real-time. By moving beyond static blacklists, this project implements a **Multi-Layered Defense** strategy that combines statistical analysis, heuristic patterns, and algorithmic risk scoring.

---

## 🚀 Key Features

- **Statistical Layer:** Calculates **Shannon Entropy** to detect high-randomness domains often used in Domain Generation Algorithms (DGA).
- **Heuristic Engine:** Uses Regex pattern matching to identify **Punycode (Homograph) attacks**, raw IP-address hosting, and URL obfuscation.
- **Weighted Risk Scoring:** Aggregates findings into a probabilistic risk index (Low, Medium, or High Risk).
- **Actionable Forensics:** Generates downloadable **Security Audit Reports (.txt)** for incident response documentation.
- **Modern UI:** Responsive dark-themed dashboard built for security analysts.

---

## 🛠️ Tech Stack

- **Backend:** Python 3.x, Flask (Micro-service Architecture)
- **Frontend:** HTML5, CSS3, JavaScript (ES6+)
- **Logic:** Regular Expressions (Regex), Shannon Entropy Statistics

---

