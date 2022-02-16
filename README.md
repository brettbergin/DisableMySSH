# DisableMySSH
This application disables ALL EC2 security group ingress rules that define a 0.0.0.0 ingress on port 22. 


Only security groups that are used by an ec2 instance are in scope for this audit. Because the "Security group allowing 0.0.0.0/0 ingress on port 22 to an EC2 instance" vulnerability was chosen for this assigment, the following logic was implemented:

1. Downloads all AWS ec2 instances
2. Iterates over all security groups attached to each instance.
3. Analyzes all corresponding ingress rules, looking for a 0.0.0.0:22 ingress rule definition.
4. Optionally revoke the ingress rule on the corresponding security group, or print the analyzed results to STDOUT.

# Setup Environment & Dependencies
```
$ git clone https://github.com/brettbergin/DisableMySSH.git
$ virtualenv --python=/usr/local/bin/python3 ~/.venv
$ source ~/.venv/bin/activate
(.venv) $ pip install -r DisableMySSH/requirements.txt
```

# Usage
Via a command line argument, the user can specify whether or not to revoke the ingress rule by providing the `-r` or `--remediate` flag. 

- When specifying `true` the application will revoke the ingress rule on the affected security group.
- When specifying `false` the application will output the security group violations found to STDOUT.

>If you would like to revoke the ingress access from any Security Group that has a 0.0.0.0:22 ingress rule, run with `true`.
```
(.venv) $ AWS_PROFILE=YOUR_PROFILE python main.py -r true
```

>If you would like to see the output of what ec2 instances have security groups with a 0.0.0.0:22 ingress rule, run with `false`.
```
(.venv) $ AWS_PROFILE=YOUR_PROFILE python main.py -r false
```

# Testing
>If you would like to run the unit tests for this app, perform the following:
```
(.venv) $ AWS_PROFILE=YOUR_PROFILE python -m unittest
```