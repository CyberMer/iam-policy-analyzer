# 🛡️ IAM Policy Analyzer

A simple Python tool that finds security problems in your AWS IAM policies. Think of it as a security guard that checks if your policies are too permissive or risky.

### 1. Setup (one time)
```bash
# Clone and go to the project
cd iam-policies

# Install everything you need
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Test it out
```bash
# Check a risky policy (should find problems)
python simple_analyzer.py analyze -f examples/dangerous_policy.json

# Check a good policy (should be clean)
python simple_analyzer.py analyze -f examples/good_policy.json
```

## What It Finds

** Critical Issues**
- Policies with `*` permissions (way too broad!)
- Access to all resources with `*`

** High Risk Issues**  
- Dangerous actions like `iam:*`, `s3:*`, `ec2:*`
- Actions that can create new users/roles (privilege escalation)

** Medium Issues**
- Missing security conditions on sensitive actions

** Low Issues**
- Minor improvements and best practices

##  How to Use

### Analyze One Policy
```bash
# From a file
python simple_analyzer.py analyze --policy-file my-policy.json

# From text
python simple_analyzer.py analyze --policy-text '{"Version":"2012-10-17",...}'
```

### Check Multiple Policies
```bash
# Analyze all policies in a folder
python simple_analyzer.py batch --directory my-policies/ --verbose
```

### Get Different Outputs
```bash
# Pretty table (default)
python simple_analyzer.py analyze -f policy.json

# JSON for automation
python simple_analyzer.py analyze -f policy.json --format json

# Save to file
python simple_analyzer.py analyze -f policy.json --output report.json
```

### Filter by Severity
```bash
# Only show the serious stuff
python simple_analyzer.py analyze -f policy.json --severity high
```

## ⚙️ Customize the Rules

Create a `config.yaml` file to adjust what the tool considers risky:

```yaml
dangerous_actions:
  "*": "critical"           # Never allow this!
  "iam:*": "critical"       # Too broad
  "s3:DeleteBucket": "high" # Your custom rule

dangerous_resources:
  - "*"                     # All resources = bad
  - "arn:aws:s3:::*"       # All S3 buckets = risky
```

Then use it:
```bash
python simple_analyzer.py analyze -f policy.json --config config.yaml
```

