#!/usr/bin/env python3
"""
Simple tests for the IAM Policy Analyzer
"""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.analyzer import IAMPolicyAnalyzer, analyze_policy_string


def test_dangerous_policy():
    """Test analysis of a dangerous policy with wildcard permissions."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    
    analyzer = IAMPolicyAnalyzer()
    findings = analyzer.analyze_policy(policy)
    
    print(f"✓ Dangerous policy test: Found {len(findings)} issues")
    assert len(findings) >= 2  # Should find wildcard action and resource issues
    
    # Check for critical severity findings
    critical_findings = [f for f in findings if f.severity == 'critical']
    assert len(critical_findings) >= 1
    print("  - Found critical severity issues as expected")


def test_privilege_escalation():
    """Test detection of privilege escalation risks."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:CreateRole",
                    "iam:AttachRolePolicy"
                ],
                "Resource": "*"
            }
        ]
    }
    
    analyzer = IAMPolicyAnalyzer()
    findings = analyzer.analyze_policy(policy)
    
    print(f"✓ Privilege escalation test: Found {len(findings)} issues")
    
    # Check for privilege escalation finding
    escalation_findings = [f for f in findings if "Privilege Escalation" in f.title]
    assert len(escalation_findings) >= 1
    print("  - Detected privilege escalation risk")


def test_good_policy():
    """Test analysis of a well-configured policy."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject"
                ],
                "Resource": "arn:aws:s3:::my-bucket/*",
                "Condition": {
                    "StringEquals": {
                        "aws:userid": "${aws:userid}"
                    }
                }
            }
        ]
    }
    
    analyzer = IAMPolicyAnalyzer()
    findings = analyzer.analyze_policy(policy)
    
    print(f"✓ Good policy test: Found {len(findings)} issues")
    # Should find minimal or no issues
    assert len(findings) <= 1
    print("  - Good policy has minimal issues as expected")


def test_example_files():
    """Test analysis of example policy files."""
    examples_dir = Path(__file__).parent / "examples"
    
    # Test dangerous policy file
    dangerous_file = examples_dir / "dangerous_policy.json"
    if dangerous_file.exists():
        with open(dangerous_file) as f:
            policy = json.load(f)
        
        analyzer = IAMPolicyAnalyzer()
        findings = analyzer.analyze_policy(policy)
        print(f"✓ Example dangerous policy: Found {len(findings)} issues")
        assert len(findings) >= 2


def main():
    """Run all tests."""
    print("Running IAM Policy Analyzer Tests...")
    print("=" * 40)
    
    try:
        test_dangerous_policy()
        test_privilege_escalation()
        test_good_policy()
        test_example_files()
        
        print("=" * 40)
        print("✅ All tests passed!")
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
