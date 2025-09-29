"""
Configuration management for IAM Policy Analyzer
"""

import yaml
import json
from typing import Dict, List, Any, Optional
from pathlib import Path


class AnalyzerConfig:
    """Configuration class for the IAM Policy Analyzer."""
    
    def __init__(self, config_file: Optional[str] = None):
        # Default configuration
        self.dangerous_actions = {
            '*': 'critical',
            'iam:*': 'critical',
            's3:*': 'high',
            'ec2:*': 'high',
            'iam:CreateRole': 'high',
            'iam:AttachRolePolicy': 'high',
            'iam:PutRolePolicy': 'high',
            'sts:AssumeRole': 'medium',
            's3:GetBucketAcl': 'medium',
            'ec2:DescribeInstances': 'low'
        }
        
        self.dangerous_resources = [
            '*',
            'arn:aws:s3:::*',
            'arn:aws:iam::*:*'
        ]
        
        self.privilege_escalation_actions = [
            'iam:CreateRole',
            'iam:AttachRolePolicy',
            'iam:PutRolePolicy',
            'iam:CreateUser',
            'iam:AttachUserPolicy',
            'iam:PutUserPolicy'
        ]
        
        self.sensitive_actions_requiring_conditions = [
            'sts:AssumeRole',
            'iam:*',
            's3:*'
        ]
        
        # Load custom configuration if provided
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, config_file: str):
        """Load configuration from a YAML or JSON file."""
        config_path = Path(config_file)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        
        with open(config_path, 'r') as f:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                config_data = yaml.safe_load(f)
            elif config_path.suffix.lower() == '.json':
                config_data = json.load(f)
            else:
                raise ValueError("Configuration file must be YAML or JSON format")
        
        # Update configuration with loaded data
        if 'dangerous_actions' in config_data:
            self.dangerous_actions.update(config_data['dangerous_actions'])
        
        if 'dangerous_resources' in config_data:
            self.dangerous_resources.extend(config_data['dangerous_resources'])
        
        if 'privilege_escalation_actions' in config_data:
            self.privilege_escalation_actions.extend(config_data['privilege_escalation_actions'])
        
        if 'sensitive_actions_requiring_conditions' in config_data:
            self.sensitive_actions_requiring_conditions.extend(config_data['sensitive_actions_requiring_conditions'])
    
    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary."""
        return {
            'dangerous_actions': self.dangerous_actions,
            'dangerous_resources': self.dangerous_resources,
            'privilege_escalation_actions': self.privilege_escalation_actions,
            'sensitive_actions_requiring_conditions': self.sensitive_actions_requiring_conditions
        }
    
    def save_config(self, output_file: str):
        """Save current configuration to a file."""
        output_path = Path(output_file)
        config_data = self.to_dict()
        
        with open(output_path, 'w') as f:
            if output_path.suffix.lower() in ['.yaml', '.yml']:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            elif output_path.suffix.lower() == '.json':
                json.dump(config_data, f, indent=2)
            else:
                raise ValueError("Output file must have .yaml, .yml, or .json extension")