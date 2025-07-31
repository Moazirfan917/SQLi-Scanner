# 🧨 SQL Injection Scanner

A custom-built **SQLi (SQL Injection) vulnerability scanner** designed for web application security assessments. This tool helps detect **classic SQL injection flaws** using automated payload injection, response analysis, and customizable scanning options.

Ideal for **bug bounty hunters**, **penetration testers**, and **ethical hackers** who want a lightweight, fast, and scriptable tool.

---

## 🚀 Features

- ✅ Supports **GET** and **POST** requests
- 🔎 Tests for common SQL injection payloads
- 📌 Detects changes in HTTP responses (status, content length, errors)
- 🔐 Supports cookies for **authenticated scans**
- 💬 Verbose and color-coded output for better visibility
- 📄 Optional result saving to file

---

## 🧰 Requirements

- Python 3.6+
- `requests`
- `argparse`
- `colorama`

Install the required libraries:

```bash
bash run.sh
