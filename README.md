# ufw-abuseipdb
## what is this?
Python script to automatically report port scans intercepted by UFW in the last three minutes to AbuseIPDB
Please run every 3 minutes with cron ;)

## Usage
```
mv main.py /usr/libexec/report.py
ABUSEIPDB_API_KEY=CHANGEME /usr/bin/python3 /usr/libexec/report.py
```

### crontab
```
*/3 * * * * ABUSEIPDB_API_KEY=CHANGEME /usr/bin/python3 /usr/libexec/report.py
```