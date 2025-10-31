# ⚙️ Discord Token Generator (Chromium Automation)

A powerful **Discord token generator** built with **Python + Playwright (Chromium)**.
It automates the entire Discord registration process — from creating temporary emails to solving hCaptcha and verifying accounts — all inside a real browser.

---

## 🚀 Features

* **Full Discord account creation**
  Automatically fills out registration forms and completes signups in Chromium.

* **Temporary email system**
  Uses the IncognitoMail API to generate inboxes and fetch verification links.

* **Auto hCaptcha solver**
  Integrates the `hcaptcha_challenger` library with AI-based solving models (Gemini).

* **Proxy rotation**
  Supports HTTP/SOCKS proxies with automatic retries for failed connections.

* **Account “Humanizer”**
  (Optional) Customizes profiles — names, bios, pronouns, avatars, and HypeSquad badges — for more natural accounts.

* **Visual CLI interface**
  Clean, color-coded console output with real-time status updates.

* **Desktop notifications (optional)**
  Sends success or error pop-ups for account creation progress.

---

## 🧠 How It Works (Simplified)

1. Reads settings from `config.json` (API keys, proxy list, etc.).
2. Launches a Chromium browser using Playwright.
3. Generates a temporary email via IncognitoMail.
4. Fills the Discord registration form automatically.
5. Solves hCaptcha using an AI solver (Gemini).
6. Checks inbox for the Discord verification email and confirms the account.
7. Optionally humanizes the account (updates profile, sets avatar, etc.).

---

## 🧰 Requirements

* **Python 3.10+**
* **Google Chrome or Chromium**
* **Playwright browsers installed**

### Install dependencies

```bash
pip install playwright httpx requests colorama pystyle notifypy hcaptcha-challenger tls-client
playwright install
```

---

## ⚙️ Configuration (`config.json`)

Example:

```json
{
  "mail_api": "https://api.incognitomail.co/",
  "mail_domain": "vorlentis.xyz",
  "gemini_api_key": "your_api_key_here",
  "notify": true
}
```

---

## ▶️ Usage

Run the main script:

```bash
python main_chromium.py
```

Follow the on-screen setup (VPN, Humanizer, etc.) and the script will handle the rest automatically.

---

## ⚠️ Disclaimer

This tool is for **educational and testing purposes only**.
Creating or automating Discord accounts for spam or abuse violates Discord’s Terms of Service.
Use responsibly and only within ethical and legal limits.

---
Contact: https://t.me/vidkid5
