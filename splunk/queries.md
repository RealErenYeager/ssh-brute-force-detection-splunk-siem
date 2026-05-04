# 🔍 Splunk Detection Queries

This section contains detection logic used to identify SSH brute-force attacks and successful compromises from authentication logs.

---

## 1️⃣ Brute Force Detection (Multiple Failed Logins)

### 📌 Description

Detects IP addresses generating a high number of failed SSH login attempts.

### 🧠 Detection Logic

* Extract source IP from logs
* Count failed login attempts
* Flag IPs exceeding threshold

### 💻 Query

```spl
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| where failed_attempts > 10
| sort - failed_attempts
```

---

## 2️⃣ Brute Force Leading to Successful Compromise

### 📌 Description

Identifies attackers who performed multiple failed login attempts followed by a successful login.

### 🧠 Detection Logic

* Detect repeated failed attempts
* Check for successful login from same IP
* Confirm possible account compromise

### 💻 Query

```spl
index=main ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count(eval(searchmatch("Failed password"))) as failed,
        count(eval(searchmatch("Accepted password"))) as success
        by src_ip
| where failed > 5 AND success > 0
| sort - failed
```

---

## 3️⃣ Suspicious Successful Login (Optional Advanced Detection)

### 📌 Description

Detects successful SSH logins after a high number of failed attempts.

### 💻 Query

```spl
index=main "Accepted password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
```

---

## 🚨 Detection Summary

| Detection Type       | Condition                  |
| -------------------- | -------------------------- |
| Brute Force Attack   | Failed attempts > 10       |
| Compromise Detection | Failed > 5 AND Success > 0 |

---

## 🧠 Notes

* Logs were sourced from `/var/log/auth.log`
* IP extraction performed using regex
* Queries executed in Splunk SIEM for analysis
