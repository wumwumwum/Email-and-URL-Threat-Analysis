# Email and URL Threat Analysis
A simple Python email and url threat analysis tool. 

Navigate to containing directory in terminal and run:

```
python threat_triage.py --url "https://example.com/login"
python threat_triage.py --email suspicious.eml
cat suspicious.eml | python threat_triage.py --email -
```
