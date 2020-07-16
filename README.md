# APEX PE Scanner
A small utility that finds users who are capable of privilege escalation using APEX.

The PE abuses the fact that APEX Triggers run in system mode. A full technical explanation can be found [here](https://cloudsecurityalliance.org/blog/2020/07/16/abusing-privilege-escalation-in-salesforce-using-apex/).

## How to run

The utility requires a username, a password and the security token of a Salesforce user.
```bash
python apex_pe_scanner.py -u USERNAME -p PASSWORD -t SECURITY_TOKEN
```

Instead of typing in your password and security token you can import this code and invoke `find_users_with_apex` with a logged-in `simple_salesforce` client.  

Alternatively you can execute the apex code provided in [apex_pe_scanner.apdx](/apex_pe_scanner.apdx) in [Salesforce Developer Console](https://help.salesforce.com/articleView?id=code_dev_console_opening.htm&type=5).

## Requirements
Python 3.7+

Required python packages:
+ simple_salesforce
