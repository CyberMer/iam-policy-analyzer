#!/usr/bin/env python3
"""
IAM Policy Misconfiguration Detection Tool
Main CLI entry point for analyzing IAM policies.
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
    """IAM Policy Misconfiguration Detection Tool"""
    pass


@cli.command()
@click.option('--policy-file', '-f', type=click.Path(exists=True), 
              help='Path to IAM policy JSON file')
@click.option('--policy-text', '-t', help='IAM policy as JSON string')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'table', 'csv']), 
              default='table', help='Output format')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'critical']), 
              help='Filter results by minimum severity level')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def analyze(policy_file: Optional[str], policy_text: Optional[str], 
           output: Optional[str], output_format: str, severity: Optional[str], 
           verbose: bool):
    """Analyze a single IAM policy for misconfigurations."""
    
    if not policy_file and not policy_text:
        click.echo("Error: Either --policy-file or --policy-text must be provided", err=True)
        sys.exit(1)
    
    try:
        # Analyze policy
        if policy_file:
            findings = analyze_policy_file(policy_file)
            policy_name = Path(policy_file).stem
        else:
            findings = analyze_policy_string(policy_text)
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
            policy = json.loads(policy_text)
            policy_name = "inline_policy"
        
        # Initialize analyzer
        analyzer = PolicyAnalyzer(verbose=verbose)
        
        # Analyze policy
        click.echo(f"Analyzing policy: {policy_name}")
        results = analyzer.analyze_policy(policy, policy_name)
        
        # Filter by severity if specified
        if severity:
            results = analyzer.filter_by_severity(results, severity)
        
        # Generate report
        report_gen = ReportGenerator()
        if output:
            report_gen.save_report(results, output, output_format)
            click.echo(f"Report saved to: {output}")
        else:
            report_gen.print_report(results, output_format)
            
    except Exception as e:
        click.echo(f"Error analyzing policy: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option('--profile', help='AWS profile to use')
@click.option('--region', help='AWS region')
@click.option('--policy-types', multiple=True, 
              type=click.Choice(['managed', 'inline', 'customer', 'aws']),
              default=['managed', 'inline', 'customer'],
              help='Types of policies to analyze')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'yaml', 'table', 'csv']), 
              default='table', help='Output format')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'critical']), 
              help='Filter results by minimum severity level')
@click.option('--max-policies', type=int, help='Maximum number of policies to analyze')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def scan_account(profile: Optional[str], region: Optional[str], 
                policy_types: List[str], output: Optional[str], 
                output_format: str, severity: Optional[str], 
                max_policies: Optional[int], verbose: bool):
    """Scan an entire AWS account for IAM policy misconfigurations."""
    
    try:
        # Initialize AWS collector
        collector = AWSPolicyCollector(profile=profile, region=region, verbose=verbose)
        
        # Collect policies
        click.echo("Collecting IAM policies from AWS account...")
        policies = collector.collect_policies(policy_types, max_policies)
        
        if not policies:
            click.echo("No policies found to analyze")
            return
        
        click.echo(f"Found {len(policies)} policies to analyze")
        
        # Initialize analyzer
        analyzer = PolicyAnalyzer(verbose=verbose)
        
        # Analyze all policies
        all_results = []
        with click.progressbar(policies, label='Analyzing policies') as policy_list:
            for policy_info in policy_list:
                results = analyzer.analyze_policy(
                    policy_info['document'], 
                    policy_info['name'],
                    policy_info.get('arn', '')
                )
                all_results.extend(results)
        
        # Filter by severity if specified
        if severity:
            all_results = analyzer.filter_by_severity(all_results, severity)
        
        # Generate summary statistics
        total_issues = len(all_results)
        severity_counts = {}
        for result in all_results:
            sev = result.get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        click.echo(f"\nScan complete. Found {total_issues} total issues:")
        for sev, count in severity_counts.items():
            click.echo(f"  {sev.upper()}: {count}")
        
        # Generate report
        report_gen = ReportGenerator()
        if output:
            report_gen.save_report(all_results, output, output_format)
            click.echo(f"\nDetailed report saved to: {output}")
        else:
            if total_issues > 50 and output_format == 'table':
                click.echo(f"\nToo many issues to display in table format. Showing first 50:")
                report_gen.print_report(all_results[:50], output_format)
                click.echo(f"\n... and {total_issues - 50} more issues. Use --output to save full report.")
            else:
                report_gen.print_report(all_results, output_format)
                
    except Exception as e:
        click.echo(f"Error scanning account: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option('--directory', '-d', type=click.Path(exists=True), required=True,
              help='Directory containing policy files')
@click.option('--pattern', default='*.json', help='File pattern to match (default: *.json)')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'yaml', 'table', 'csv']), 
              default='table', help='Output format')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'critical']), 
              help='Filter results by minimum severity level')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def batch(directory: str, pattern: str, output: Optional[str], 
         output_format: str, severity: Optional[str], verbose: bool):
    """Analyze multiple policy files in a directory."""
    
    try:
        directory_path = Path(directory)
        policy_files = list(directory_path.glob(pattern))
        
        if not policy_files:
            click.echo(f"No files matching pattern '{pattern}' found in {directory}")
            return
        
        click.echo(f"Found {len(policy_files)} policy files to analyze")
        
        # Initialize analyzer
        analyzer = PolicyAnalyzer(verbose=verbose)
        
        # Analyze all policies
        all_results = []
        with click.progressbar(policy_files, label='Analyzing policies') as file_list:
            for policy_file in file_list:
                try:
                    policy = load_policy_file(str(policy_file))
                    results = analyzer.analyze_policy(policy, policy_file.stem)
                    all_results.extend(results)
                except Exception as e:
                    if verbose:
                        click.echo(f"\nError analyzing {policy_file}: {str(e)}", err=True)
                    continue
        
        # Filter by severity if specified
        if severity:
            all_results = analyzer.filter_by_severity(all_results, severity)
        
        click.echo(f"\nAnalysis complete. Found {len(all_results)} total issues")
        
        # Generate report
        report_gen = ReportGenerator()
        if output:
            report_gen.save_report(all_results, output, output_format)
            click.echo(f"Report saved to: {output}")
        else:
            report_gen.print_report(all_results, output_format)
            
    except Exception as e:
        click.echo(f"Error in batch analysis: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', type=click.Path(), help='Output file path for rules documentation')
def list_rules(output: Optional[str]):
    """List all available security rules and their descriptions."""
    
    try:
        from src.analyzer.rule_engine import RuleEngine
        
        rule_engine = RuleEngine()
        rules_info = rule_engine.get_rules_documentation()
        
        if output:
            with open(output, 'w') as f:
                json.dump(rules_info, f, indent=2)
            click.echo(f"Rules documentation saved to: {output}")
        else:
            click.echo("\nAvailable Security Rules:\n" + "="*50)
            for category, rules in rules_info.items():
                click.echo(f"\n{category.upper()}:")
                for rule in rules:
                    click.echo(f"  • {rule['name']}: {rule['description']}")
                    click.echo(f"    Severity: {rule['severity']}")
                    if rule.get('references'):
                        click.echo(f"    References: {', '.join(rule['references'])}")
                    click.echo()
                    
    except Exception as e:
        click.echo(f"Error listing rules: {str(e)}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
