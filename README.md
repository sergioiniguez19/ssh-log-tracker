# 🛡️ SSH Log Tracker & Auto-Banner

**SSH Log Tracker** is an active security tool written in Python designed to protect Linux servers against SSH brute-force attacks. It monitors system logs in real-time and dynamically blocks attacking IP addresses using `iptables` rules.

---

## ✨ Main Features
- **Real-Time Monitoring:** Leverages `journalctl` to capture failed login attempts the millisecond they happen.
- **Smart Blocking Logic:** Implements a configurable time window (default: 5 min) to distinguish between human error and automated brute-force attacks.
- **Data Persistence:** Integrated SQLite3 database to manage Whitelists (safe IPs) and keep a historical log of blocked attackers.
- **Duplicate Prevention:** Advanced logic checks the Linux kernel's existing rules before applying a ban to avoid firewall clutter.
- **System Notifications:** Sends desktop alerts using `notify-send` for immediate administrator awareness.


---

## 🛠️ Requirements
- **Python 3.x**
- **Root Privileges** (Required to interact with `iptables`)
- **Systemd-based Linux** (Debian, Ubuntu, Kali, Arch, etc.)
---

## 📦 Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/sergioiniguez19/ssh-log-tracker.git
   cd ssh-log-tracker
## ⚙️ Usage
2. **Run the script:**
    ```bash
    sudo python3 main.py
### ⚪ Whitelisting

Upon startup, the script will prompt you to add IP addresses to the **Whitelist**. It is highly recommended to add your local/admin IP to prevent accidental self-lockouts. The whitelist is stored in the iplist.sqlite database and cached during execution for maximum performance.
    

## 🛠️ Technical Details

*   **Language:** Python 3.x
    
*   **Database:** SQLite3 for persistent storage of whitelists and logs.
    
*   **Concurrency:** threading module used for asynchronous log tailing.
    
*   **Network Security:** Direct interaction with netfilter via the iptables binary.
    

## ⚠️ Disclaimer

This tool modifies system firewall rules. Use it with caution. Ensure you have out-of-band access to your server (like a serial console or provider dashboard) in case you accidentally block your own access. The developers are not responsible for any accidental lockouts.
