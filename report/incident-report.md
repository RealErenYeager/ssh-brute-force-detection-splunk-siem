# 🚨 Incident Report: SSH Brute Force Attack

## 📅 Date

04-05-2026

## 🖥️ Affected System

Ubuntu Server (SSH Service)

---

## 🔍 Incident Summary

A brute-force attack was detected targeting the SSH service on the Ubuntu server. The attacker performed multiple failed login attempts and eventually gained unauthorized access through successful authentication.

---

## 📊 Findings

* **Total Failed Attempts:** 193
* **Successful Login Attempts:** 1
* **Attacker IP Address:** 192.168.29.55

---

## ⚔️ Attack Details

* Attack Type: SSH Brute Force
* Attack Method: Password guessing using automated tool (Hydra)
* Target Account: `joker`

---

## 🧾 Evidence

* Multiple “Failed password” entries observed in authentication logs
* A successful login (“Accepted password”) from the same attacker IP
* Logs analyzed using Splunk SIEM

---

## ⚠️ Impact

* Unauthorized access to the system
* Potential compromise of user account
* Risk of further lateral movement or privilege escalation

---

## 🛡️ Actions Taken

* Attack identified through Splunk detection queries
* Attacker IP (192.168.29.55) flagged as malicious
* Recommended blocking IP via firewall

---

## 🔐 Recommendations

* Enforce strong password policies
* Implement account lockout after multiple failed attempts
* Enable multi-factor authentication (MFA)
* Restrict SSH access (e.g., IP allowlisting)
* Monitor logs continuously using SIEM

---

## 🧠 Conclusion

This incident highlights how weak authentication mechanisms can be exploited through brute-force attacks. Effective log monitoring and detection rules in SIEM systems like Splunk are critical for identifying and responding to such threats in real time.
