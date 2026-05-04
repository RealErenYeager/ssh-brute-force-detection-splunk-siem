# Alert Logic

Alert Name: SSH Brute Force Attack Detected

Condition:
- Failed login attempts > 5
- Successful login detected

Trigger:
When both conditions are met from the same IP

Action:
- Flag IP as attacker
- Recommend blocking IP