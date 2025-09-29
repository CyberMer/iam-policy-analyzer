#!/usr/bin/env python3
"""
Simple IAM Policy Analyzer
A small, focused tool for detecting IAM policy misconfigurations.
"""

import click
import json
import sys
from pathlib import Path
from typing import Optional

from src.analyzer import analyze_policy_file, analyze_policy_string
from src.reporter import format_findings


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Simple IAM Policy Misconfiguration Detection Tool"""
    pass


@cli.command()
@click.option('--policy-file', '-f', type=click.Path(exists=True), 
              help='Path to IAM policy JSON file')
@click.option('--policy-text', '-t', help='IAM policy as JSON string')
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Configuration file (YAML or JSON)')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'table', 'csv']), 
              default='table', help='Output format')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'critical']), 
              help='Filter results by minimum severity level')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def analyze(policy_file: Optional[str], policy_text: Optional[str], config: Optional[str],
           output: Optional[str], output_format: str, severity: Optional[str], 
           verbose: bool):
    """Analyze a single IAM policy for misconfigurations."""
    
    if not policy_file and not policy_text:
        click.echo("Error: Either --policy-file or --policy-text must be provided", err=True)
        sys.exit(1)
    
    try:
        # Analyze policy
        if policy_file:
            findings = analyze_policy_file(policy_file, config)
            policy_name = Path(policy_file).stem
        else:
            findings = analyze_policy_string(policy_text, config)
            policy_name = "inline-policy"
        
        # Filter by severity if specified
        if severity:
            severity_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
            min_level = severity_levels[severity]
            findings = [f for f in findings if severity_levels[f.severity] >= min_level]
        
        # Generate report
        report = format_findings(findings, output_format)
        
        if verbose:
            click.echo(f"Analyzed policy: {policy_name}")
            click.echo(f"Found {len(findings)} issues")
        
        # Output report
        if output:
            with open(output, 'w') as f:
                f.write(report)
            click.echo(f"Report saved to: {output}")
        else:
            click.echo(report)
            
    except Exception as e:
        click.echo(f"Error analyzing policy: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--directory', '-d', type=click.Path(exists=True), required=True,
              help='Directory containing policy files')
@click.option('--pattern', default='*.json', help='File pattern to match (default: *.json)')
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Configuration file (YAML or JSON)')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'table', 'csv']), 
              default='table', help='Output format')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'critical']), 
              help='Filter results by minimum severity level')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def batch(directory: str, pattern: str, config: Optional[str], output: Optional[str], 
         output_format: str, severity: Optional[str], verbose: bool):
    """Analyze multiple policy files in a directory."""
    
    try:
        directory_path = Path(directory)
        policy_files = list(directory_path.glob(pattern))
        
        if not policy_files:
            click.echo(f"No files matching pattern '{pattern}' found in {directory}")
            return
        
        if verbose:
            click.echo(f"Found {len(policy_files)} policy files to analyze")
        
        # Analyze all policies
        all_findings = []
        for policy_file in policy_files:
            try:
                findings = analyze_policy_file(str(policy_file), config)
                for finding in findings:
                    finding.policy_statement['_source_file'] = str(policy_file)
                all_findings.extend(findings)
            except Exception as e:
                if verbose:
                    click.echo(f"Error analyzing {policy_file}: {str(e)}", err=True)
                continue
        
        # Filter by severity if specified
        if severity:
            severity_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
            min_level = severity_levels[severity]
            all_findings = [f for f in all_findings if severity_levels[f.severity] >= min_level]
        
        if verbose:
            click.echo(f"Analysis complete. Found {len(all_findings)} total issues")
        
        # Generate report
        report = format_findings(all_findings, output_format)
        
        # Output report
        if output:
            with open(output, 'w') as f:
                f.write(report)
            click.echo(f"Report saved to: {output}")
        else:
            click.echo(report)
            
    except Exception as e:
        click.echo(f"Error in batch analysis: {str(e)}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
