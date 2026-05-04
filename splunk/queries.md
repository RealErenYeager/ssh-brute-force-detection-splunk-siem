# Splunk Detection Queries

## 1. Brute Force Detection
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip

## 2. Failed to Successful Login Detection
index=main ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count(eval(searchmatch("Failed password"))) as failed,
        count(eval(searchmatch("Accepted password"))) as success
        by src_ip