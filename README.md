# 🔐 Detection and Analysis of SSH Brute Force Attacks using Splunk SIEM

## 📌 Overview

This project demonstrates a simulated SOC (Security Operations Center) workflow where an SSH brute-force attack was performed and detected using Splunk SIEM.

The lab includes attack simulation, log collection, detection, and incident analysis.

---

## 🧱 Lab Architecture

Kali Linux (Attacker) → Ubuntu (Victim) → Splunk (SIEM)

---

## 🛠️ Tools Used

* Kali Linux (Attack simulation)
* Ubuntu (Log generation)
* Splunk Enterprise (Log analysis and detection)

---

## ⚔️ Attack Simulation

A brute-force attack was performed on SSH service using Hydra from Kali Linux targeting the Ubuntu machine.

---

## 📥 Log Collection

Authentication logs were collected from:
`/var/log/auth.log`

Logs were imported into Splunk for analysis.

---

## 🔍 Detection Logic

### Brute Force Detection

```spl
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
```

### Failed → Success Detection

```spl
index=main ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count(eval(searchmatch("Failed password"))) as failed,
        count(eval(searchmatch("Accepted password"))) as success
        by src_ip
```

---

## 🚨 Key Findings

* Multiple failed login attempts detected
* Successful login after brute force
* Attacker IP identified: 192.168.29.55

---

## 📊 Outcome

Successfully simulated and detected a brute-force attack using Splunk, demonstrating real-world SOC detection and analysis workflow.

---

## 📸 Screenshots

(See /screenshots folder)

---

## 📝 Incident Report

(See /report/incident-report.md)
