"""
Core IAM Policy Analyzer
Detects common misconfigurations in IAM policies.
"""

import json
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass

try:
    from .config import AnalyzerConfig
except ImportError:
    from config import AnalyzerConfig


@dataclass
class Finding:
    """Represents a security finding in an IAM policy."""
    severity: str  # critical, high, medium, low
    title: str
    description: str
    policy_statement: Dict[str, Any]
    recommendation: str


class IAMPolicyAnalyzer:
    """Analyzes IAM policies for common misconfigurations."""
    
    def __init__(self, config_file: Optional[str] = None):
        # Load configuration
        self.config = AnalyzerConfig(config_file)
        
        # Use configuration values
        self.dangerous_actions = self.config.dangerous_actions
        self.dangerous_resources = self.config.dangerous_resources
    
    def analyze_policy(self, policy: Dict[str, Any]) -> List[Finding]:
        """Analyze an IAM policy and return findings."""
        findings = []
        
        if 'Statement' not in policy:
            return findings
        
        statements = policy['Statement']
        if not isinstance(statements, list):
            statements = [statements]
        
        for stmt in statements:
            findings.extend(self._analyze_statement(stmt))
        
        return findings
    
    def _analyze_statement(self, statement: Dict[str, Any]) -> List[Finding]:
        """Analyze a single policy statement."""
        findings = []
        
        # Check for overly permissive actions
        findings.extend(self._check_dangerous_actions(statement))
        
        # Check for wildcard resources
        findings.extend(self._check_wildcard_resources(statement))
        
        # Check for missing conditions
        findings.extend(self._check_missing_conditions(statement))
        
        # Check for privilege escalation risks
        findings.extend(self._check_privilege_escalation(statement))
        
        return findings
    
    def _check_dangerous_actions(self, statement: Dict[str, Any]) -> List[Finding]:
        """Check for dangerous or overly broad actions."""
        findings = []
        
        if statement.get('Effect') != 'Allow':
            return findings
        
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        for action in actions:
            if action in self.dangerous_actions:
                severity = self.dangerous_actions[action]
                findings.append(Finding(
                    severity=severity,
                    title=f"Dangerous Action: {action}",
                    description=f"The action '{action}' grants broad permissions that could be exploited.",
                    policy_statement=statement,
                    recommendation=f"Replace '{action}' with specific, least-privilege actions."
                ))
        
        return findings
    
    def _check_wildcard_resources(self, statement: Dict[str, Any]) -> List[Finding]:
        """Check for wildcard resource specifications."""
        findings = []
        
        if statement.get('Effect') != 'Allow':
            return findings
        
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        
        for resource in resources:
            if resource == '*':
                findings.append(Finding(
                    severity='critical',
                    title="Wildcard Resource Access",
                    description="The policy grants access to all resources using '*'.",
                    policy_statement=statement,
                    recommendation="Specify exact resource ARNs instead of using wildcards."
                ))
            elif any(dangerous in resource for dangerous in self.dangerous_resources[1:]):
                findings.append(Finding(
                    severity='high',
                    title="Broad Resource Access",
                    description=f"The resource '{resource}' grants very broad access.",
                    policy_statement=statement,
                    recommendation="Limit resource scope to specific resources needed."
                ))
        
        return findings
    
    def _check_missing_conditions(self, statement: Dict[str, Any]) -> List[Finding]:
        """Check for statements that should have conditions but don't."""
        findings = []
        
        if statement.get('Effect') != 'Allow':
            return findings
        
        # Check if sensitive actions lack conditions
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        sensitive_actions = self.config.sensitive_actions_requiring_conditions
        has_sensitive_action = any(
            any(sensitive in action for sensitive in sensitive_actions)
            for action in actions
        )
        
        if has_sensitive_action and 'Condition' not in statement:
            findings.append(Finding(
                severity='medium',
                title="Missing Access Conditions",
                description="Sensitive actions should include conditions to restrict access.",
                policy_statement=statement,
                recommendation="Add conditions like IP restrictions, MFA requirements, or time-based access."
            ))
        
        return findings
    
    def _check_privilege_escalation(self, statement: Dict[str, Any]) -> List[Finding]:
        """Check for potential privilege escalation risks."""
        findings = []
        
        if statement.get('Effect') != 'Allow':
            return findings
        
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        escalation_actions = self.config.privilege_escalation_actions
        
        found_escalation = [action for action in actions if action in escalation_actions]
        
        if found_escalation:
            findings.append(Finding(
                severity='high',
                title="Privilege Escalation Risk",
                description=f"Actions {found_escalation} can be used to escalate privileges.",
                policy_statement=statement,
                recommendation="Ensure these permissions are absolutely necessary and add strict conditions."
            ))
        
        return findings


def analyze_policy_file(file_path: str, config_file: Optional[str] = None) -> List[Finding]:
    """Analyze an IAM policy from a file."""
    with open(file_path, 'r') as f:
        policy = json.load(f)
    
    analyzer = IAMPolicyAnalyzer(config_file)
    return analyzer.analyze_policy(policy)


def analyze_policy_string(policy_json: str, config_file: Optional[str] = None) -> List[Finding]:
    """Analyze an IAM policy from a JSON string."""
    policy = json.loads(policy_json)
    analyzer = IAMPolicyAnalyzer(config_file)
    return analyzer.analyze_policy(policy)
