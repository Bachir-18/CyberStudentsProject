# 🛡️ Cyber Deception Infrastructure for Web Security  

## 📌 Project Overview  
This project aims to **protect a real website** from malicious automated attacks while **analyzing the behavior of bots**. To achieve this, we implement a **cyber deception infrastructure** using a **proxy-based redirection system** that detects and filters incoming requests.  

- **Legitimate requests** are forwarded to the real web server.  
- **Suspicious requests** are redirected to a **honeypot** — a controlled environment designed to attract and study attackers.  

## 🏗️ Infrastructure Components  

### 1️⃣ **Proxy Server (HAProxy + Fail2Ban)**  
- **Filters incoming traffic** to distinguish legitimate users from potential attackers.  
- Redirects **suspicious activity** to the honeypot for analysis.  
- Uses **Fail2Ban** to block repeated malicious attempts.  

### 2️⃣ **Real Web Server (Apache + MySQL + WordPress)**  
- Hosts the **genuine website**, protected by the proxy.  
- Logs are collected for **security analysis**.  

### 3️⃣ **Honeypot Server (WordPress 6.5.5 + Fake Vulnerabilities)**  
- A **realistic yet controlled** environment to **simulate vulnerabilities** (SQL Injection, Brute Force, etc.).  
- Collects data on attacker **behavior and methods**.  

### 4️⃣ **Log Server (ELK Stack: Elasticsearch, Logstash, Kibana)**  
- Aggregates logs from **proxy, web server, and honeypot**.  
- Provides **real-time attack monitoring** with dashboards.  
---

# 📊 Monitoring and Analysis  

- **Kibana Dashboards** provide real-time insights into **attacker activity**.  
- **HAProxy logs** track suspicious requests and blocked IPs.  
- **Honeypot logs** reveal attack techniques and bot behavior.  

---

# 🛠️ Technologies Used  

- **Proxy:** HAProxy, Fail2Ban  
- **Web Server:** Apache, MySQL, WordPress  
- **Honeypot:** WordPress 6.5.5 (with simulated vulnerabilities)  
- **Logging & Analysis:** Elasticsearch, Logstash, Kibana (ELK Stack)  

---

# 🔒 Disclaimer  

🚨 **This project is for research and educational purposes only.** 🚨  
Deploying a honeypot **with real vulnerabilities** requires careful control to **prevent unintended exploitation**. Use at your own risk.  
