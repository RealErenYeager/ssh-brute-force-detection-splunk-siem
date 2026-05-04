# 🚨 Splunk Alert Configuration

## 🔔 Alert Name

SSH Brute Force Attack Leading to Account Compromise

---

## 📌 Description

This alert detects a potential SSH brute-force attack where multiple failed login attempts are followed by a successful login from the same source IP, indicating possible unauthorized access.

---

## 🧠 Detection Logic

* Identify repeated failed login attempts
* Correlate with successful authentication from same IP
* Flag as high severity incident

---

## 💻 Search Query

```spl id="alertq1"
index=main ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count(eval(searchmatch("Failed password"))) as failed,
        count(eval(searchmatch("Accepted password"))) as success
        by src_ip
| where failed > 10 AND success > 0
| eval severity="High"
```

---

## ⏱️ Trigger Conditions

* Run: Every 5 minutes
* Time Range: Last 5 minutes
* Trigger: When results > 0

---

## 🚨 Severity Level

High

---

## ⚠️ Alert Conditions

| Condition                 | Value          |
| ------------------------- | -------------- |
| Failed Attempts Threshold | > 10           |
| Successful Login          | ≥ 1            |
| Correlation               | Same Source IP |

---

## 📢 Alert Actions

* Generate alert in Splunk
* Flag source IP as suspicious
* Recommend blocking IP via firewall
* Notify security team (email / SOC dashboard)

---

## 🛡️ Recommended Response

* Block attacker IP (e.g., firewall/iptables)
* Investigate affected user account
* Enforce password reset
* Review system for further compromise

---

## 🧠 Notes

* Detection based on `/var/log/auth.log` ingestion
* Designed for SSH authentication monitoring
* Can be extended with geolocation or threat intelligence feeds
