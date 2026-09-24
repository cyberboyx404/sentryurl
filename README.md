# 🛡️ SentryURL

**A Python CLI tool to detect phishing indicators and URL security misconfigurations before you trust a link.**

SentryURL analyzes URLs across multiple security dimensions — URL structure, SSL/TLS certificates, domain age, redirect chains, and HTTP security headers — then generates a 0–100 safety score.

> **Important:** A high score does not guarantee that a URL is safe. This is a heuristic analysis tool, not a definitive malware/phishing verdict.

## ✨ Features

- 🔍 URL structure analysis
- 🔒 SSL/TLS certificate validation
- 📅 Domain age check via WHOIS
- 🔀 HTTP redirect-chain analysis
- 🛡️ Security-header checks
- 📊 0–100 heuristic safety score
- 📁 Batch scanning from a text file
- 💻 Interactive mode

## 📦 Requirements

- Python 3.7+
- Internet connection for remote URL/WHOIS checks
- `requests`
- `python-whois`

## 🚀 Installation

```bash
git clone https://github.com/cyberboyx404/sentryurl.git
cd sentryurl

python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

## 🖥️ Usage

Single URL:

```bash
python url_checker.py example.com
```

Batch scan:

```bash
python url_checker.py -f urls.txt
```

Interactive mode:

```bash
python url_checker.py
```

## 📊 Score

| Score | Verdict |
|---|---|
| 80–100 | 🟢 Safe-looking / low indicators |
| 50–79 | 🟡 Suspicious / review needed |
| 0–49 | 🔴 High-risk indicators |

The score is based only on the checks implemented in the tool. It should not be treated as a security guarantee.

## 📁 Project Structure

```text
sentryurl/
├── url_checker.py
├── requirements.txt
├── urls.txt
├── README.md
├── LICENSE
└── .gitignore
```

## ⚠️ Disclaimer

This project is intended for educational purposes and personal/authorized security testing. Only scan URLs and domains that you own or are explicitly authorized to assess. The authors are not responsible for misuse.

## 🗺️ Roadmap

- [ ] VirusTotal API integration
- [ ] Google Safe Browsing API support
- [ ] Screenshot capture / visual analysis
- [ ] JSON/CSV report export
- [ ] Web dashboard
- [ ] More robust URL normalization and scoring

## 👤 Author

**cyberboyx404**

GitHub: https://github.com/cyberboyx404

## 📄 License

MIT License.
