# REALSAFE — Laptop Host Server & Cloudflare Tunnel Guide

This guide explains how to turn your laptop into the **host server** for the REALSAFE platform and share an **HTTPS public link** with friends, team members, or evaluators on their mobile phones and laptops without requiring them to install Python, Flask, or any code.

---

## 💡 How Your Laptop Acts as the Host Server

When you run REALSAFE with the tunnel:
```
[Friend's Phone / Laptop]
          │
          ▼ (Opens HTTPS link in browser)
[Cloudflare Edge Network (SSL / HTTPS)]
          │
          ▼ (Secure encrypted tunnel)
[cloudflared.exe on your laptop]
          │
          ▼ (Forwards traffic internally)
[Flask Application listening on 0.0.0.0:5000]
          │
          ▼
[SQLite Database + ML Engine (Random Forest & SHAP) on your laptop]
```

1. **Your laptop is the server:** Your laptop runs the Flask backend, processes queries, executes the rule-based risk scoring, runs Random Forest + SHAP explanations, and reads/writes the SQLite database.
2. **Cloudflare Tunnel provides the secure bridge:** Instead of exposing your home IP address or configuring complex router port-forwarding, Cloudflare creates an outbound secure tunnel from your laptop to Cloudflare's global edge network.
3. **Your friends don't install anything:** They simply click the generated `https://xxxx.trycloudflare.com` link on their phone, iPad, Mac, or Windows laptop. The full web application loads directly in their mobile or desktop browser!

---

## 🚀 Step-by-Step Instructions

### Step 1: Start the Host Server & Cloudflare Tunnel

Open PowerShell or Command Prompt in the `realsafe` folder and run:

```powershell
cd C:\Users\harih\.gemini\antigravity\scratch\realsafe
python host_server.py
```

*Or simply double-click the included Windows starter file:*
📁 **`start_host.bat`**

---

### Step 2: Obtain the Generated Public HTTPS Link

Within 5 to 10 seconds of starting `host_server.py`, you will see a prominent banner in your terminal:

```text
========================================================================
  🚀 REALSAFE SECURE HOST IS LIVE!
========================================================================
  🌐 PUBLIC HTTPS SHARE LINK:
     >>> https://random-words-here.trycloudflare.com <<<

  💻 LOCAL ACCESS (On this laptop):
     http://localhost:5000  or  http://127.0.0.1:5000

  📱 HOW TO SHARE:
     1. Copy the link: https://random-words-here.trycloudflare.com
     2. Send it to your friends via WhatsApp, Discord, or Email.
     3. Friends can open the link in any mobile or desktop browser.
     4. NO Python, Flask, or files needed for your friends!
========================================================================
```

---

### Step 3: Share the Link with Your Friends

1. **Copy the HTTPS URL** (e.g. `https://xxxx.trycloudflare.com`).
2. **Send it to your friends** over WhatsApp, Telegram, Email, Slack, or SMS.
3. **Your friends open the link** in Chrome, Safari, Firefox, or Edge on their phone or computer.
4. They will see the full REALSAFE dashboard, can view Property Passports (`RS-PROP-0001`, `0007`, `0031`, `0058`), test the **Tamper Lab**, run pre-transaction safety checks, and submit transfer requests!

---

### Step 4: How to Stop the Public Link

Whenever you want to stop hosting:
1. Return to the terminal window running `host_server.py`.
2. Press **`Ctrl + C`**.
3. The tunnel will close immediately, and the public HTTPS URL will become inactive. No one will be able to access your server anymore.

---

## ❓ Frequently Asked Questions & Critical Behavior

### What happens when I close the terminal or shut down my laptop?
Because your laptop is the physical server:
- **If you close the terminal:** Both the Flask server and the Cloudflare tunnel stop immediately. The public link will show a Cloudflare 502/504 error page.
- **If your laptop goes to sleep / hibernates:** The internet connection suspends, so the link will stop responding until you wake up your laptop.
- **If you shut down your laptop:** The server turns off completely.
> [!IMPORTANT]
> Keep your laptop powered on, awake, and connected to Wi-Fi while friends are testing your project.

### Do I get a new link each time I start the server?
Yes. With the free quick tunnel, a fresh unique HTTPS URL (e.g. `https://xxx-xxx.trycloudflare.com`) is generated each time you start `host_server.py`. Simply copy the new link and share it.

---

## 🛠️ Troubleshooting Guide

| Problem | Cause | Solution |
| :--- | :--- | :--- |
| **`[ERROR] Port 5000 is already in use`** | Another application or previous Flask process is running on port 5000. | Run in PowerShell: `Get-Process python \| Stop-Process -Force` or run `set PORT=5050` before starting. |
| **`Could not locate cloudflared.exe`** | The binary is missing from the folder. | Ensure `cloudflared.exe` is inside `C:\Users\harih\.gemini\antigravity\scratch\realsafe\` (bundled automatically). You can also download it from Cloudflare's official releases. |
| **Friends see `Error 502 Bad Gateway`** | Flask server took too long to start or crashed. | Check your terminal window for any Python error logs. Verify local access works first at `http://localhost:5000`. |
| **Friends cannot connect / page hangs** | Your laptop lost internet connection or went into Sleep mode. | Ensure Wi-Fi is connected and Windows Sleep mode is set to "Never" while plugged in during presentations. |
| **Windows Firewall Popup** | Windows Defender asks whether to allow `cloudflared.exe` or `python.exe`. | Click **"Allow Access"** on Private networks. |

---

## 🔒 Security Architecture & Prototype Limitations

This setup includes critical development security measures:
1. **`debug=False` Enforced:** Prevents public users from executing arbitrary Python code via the Werkzeug debugger.
2. **Concealed Stack Traces:** Custom `404.html` and `500.html` error pages are rendered to prevent revealing internal database paths or Python tracebacks.
3. **Strict Upload Whitelist:** Uploads are restricted to document formats (`.pdf`, `.txt`, `.doc`, `.png`, `.jpg`). Executable scripts (`.exe`, `.bat`, `.py`, `.sh`, `.php`) are strictly blocked.
4. **No Direct Database Exposure:** SQLite files and `.env` files are stored outside the public `static/` directory and cannot be downloaded directly via HTTP.
5. **No Real Personal Data:** All data uses synthetic identities (`USR-xxxx`) and Tamil Nadu open-data references.

> [!WARNING]
> **Prototype Hosting vs. Production Deployment:**  
> Cloudflare quick tunnels with your laptop as host are designed for **development demonstrations, hackathons, client previews, and pair-testing**.  
> If you deploy REALSAFE for actual commercial production with real citizens, it should be deployed on hardened cloud infrastructure (such as AWS, GCP, or Azure) with managed databases, production WSGI servers (Gunicorn/Uvicorn), enterprise WAF, and identity provider integrations.
