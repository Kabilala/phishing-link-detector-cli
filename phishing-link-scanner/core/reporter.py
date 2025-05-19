#!/usr/bin/env python3
"""
Reporter module for phishing link scanner.

This module handles report generation and formatting for analysis results.
"""

import json
import os
from datetime import datetime
import textwrap

def generate_report(url, results, threshold=70):
    """
    Generate a comprehensive report from analysis results.
    
    Args:
        url (str): The URL that was analyzed
        results (dict): Analysis results from URLAnalyzer
        threshold (int): The threshold for considering a URL suspicious
        
    Returns:
        dict: Formatted report
    """
    score = results['score']
    findings = results['findings']
    
    # Determine risk level
    if score < 30:
        risk_level = "LOW"
        risk_color = "\033[32m"  # Green
    elif score < 60:
        risk_level = "MEDIUM"
        risk_color = "\033[33m"  # Yellow
    elif score < 80:
        risk_level = "HIGH"
        risk_color = "\033[31m"  # Red
    else:
        risk_level = "VERY HIGH"
        risk_color = "\033[1;31m"  # Bold Red
    
    # Generate recommendation based on score
    if score < threshold:
        recommendation = "This URL does not show strong phishing indicators but always exercise caution."
        if 10 <= score < 30:
            recommendation += " While the risk appears low, verify the source if you're uncertain."
    else:
        recommendation = "This URL exhibits characteristics commonly found in phishing attempts."
        recommendation += " Avoid clicking this link or entering any personal information."
        if score >= 80:
            recommendation += " This URL contains multiple high-risk indicators that strongly suggest malicious intent."
    
    # Format findings by impact
    high_impact = [f for f in findings if f['impact'] >= 20]
    medium_impact = [f for f in findings if 10 <= f['impact'] < 20]
    low_impact = [f for f in findings if f['impact'] < 10]
    
    # Determine suspicious characteristics by category
    protocol_issues = [f for f in findings if any(term in f['description'].lower() for term in ['protocol', 'http'])]
    domain_issues = [f for f in findings if any(term in f['description'].lower() for term in ['domain', 'tld', 'subdomain'])]
    content_issues = [f for f in findings if any(term in f['description'].lower() for term in ['path', 'parameter', 'redirect'])]
    special_issues = [f for f in findings if any(term in f['description'].lower() for term in ['character', 'homoglyph', 'shortener', '@'])]
    
    # Compile report
    report = {
        'url': url,
        'score': score,
        'risk_level': risk_level,
        'threshold': threshold,
        'is_suspicious': score >= threshold,
        'timestamp': datetime.now().isoformat(),
        'findings': findings,
        'findings_by_impact': {
            'high': high_impact,
            'medium': medium_impact,
            'low': low_impact
        },
        'findings_by_category': {
            'protocol': protocol_issues,
            'domain': domain_issues,
            'content': content_issues,
            'special': special_issues
        },
        'recommendation': recommendation,
        'analysis': {
            'domain': results['domain'],
            'tld': results['tld'],
            'subdomain': results['subdomain'],
            'protocol': results['protocol'],
            'path': results['path'],
            'query': results['query']
        }
    }
    
    return report

def print_report(report, verbose=False):
    """
    Print formatted analysis report to console.
    
    Args:
        report (dict): The generated report
        verbose (bool): Whether to display detailed information
    """
    if 'error' in report:
        print("\n" + "-" * 70)
        print("⚠️  ERROR")
        print("-" * 70)
        print(report['error'])
        print("-" * 70)
        return
    
    url = report['url']
    score = report['score']
    risk_level = report['risk_level']
    findings = report['findings']
    threshold = report['threshold']
    is_suspicious = report['is_suspicious']
    recommendation = report['recommendation']
    
    # Terminal color codes
    RESET = "\033[0m"
    GREEN = "\033[32m"  # Green for safe
    YELLOW = "\033[33m"  # Yellow for medium risk
    RED = "\033[31m"  # Red for high risk
    BOLD_RED = "\033[1;31m"  # Bold Red for very high risk
    
    # Set color based on risk level
    if risk_level == "LOW":
        color = GREEN
        status = "SAFE"
    elif risk_level == "MEDIUM":
        color = YELLOW
        status = "SUSPICIOUS"
    elif risk_level == "HIGH":
        color = RED
        status = "SUSPICIOUS"
    else:  # VERY HIGH
        color = BOLD_RED
        status = "DANGEROUS"
    
    # Print header
    print("\n" + "-" * 70)
    print("🔍 PHISHING LINK SCANNER RESULTS")
    print("-" * 70)
    print(f"URL: {url}")
    print("-" * 70)
    
    # Print status and score
    if is_suspicious:
        print(f"{color}❌ {status} [{score}/100]{RESET}: This URL contains phishing indicators")
    else:
        print(f"{GREEN}✓ {status} [{score}/100]{RESET}: This URL appears to be legitimate")
    
    print("\nANALYSIS:")
    
    # Print all findings in verbose mode, or just high impact ones in regular mode
    if verbose:
        for finding in sorted(findings, key=lambda x: x['impact'], reverse=True):
            impact = finding['impact']
            description = finding['description']
            evidence = finding.get('evidence', '')
            
            # Choose color based on impact
            if impact >= 20:
                impact_color = RED
            elif impact >= 10:
                impact_color = YELLOW
            else:
                impact_color = RESET
            
            print(f"{impact_color}• {description}{RESET}")
            if evidence:
                for line in textwrap.wrap(evidence, width=66):
                    print(f"  {line}")
    else:
        # Only print high and medium impact findings in regular mode
        relevant_findings = [f for f in findings if f['impact'] >= 10]
        if relevant_findings:
            for finding in sorted(relevant_findings, key=lambda x: x['impact'], reverse=True):
                impact = finding['impact']
                description = finding['description']
                
                # Choose color based on impact
                if impact >= 20:
                    impact_color = RED
                elif impact >= 10:
                    impact_color = YELLOW
                else:
                    impact_color = RESET
                
                print(f"{impact_color}• {description}{RESET}")
        else:
            print("No significant issues detected")
    
    # Print URL components in verbose mode
    if verbose:
        analysis = report['analysis']
        print("\nURL COMPONENTS:")
        print(f"• Protocol: {analysis['protocol'] or 'None'}")
        print(f"• Domain: {analysis['domain']}")
        print(f"• TLD: {analysis['tld']}")
        if analysis['subdomain']:
            print(f"• Subdomain: {analysis['subdomain']}")
        if analysis['path'] and analysis['path'] != '/':
            print(f"• Path: {analysis['path']}")
        if analysis['query']:
            print(f"• Query Parameters: {analysis['query']}")
    
    # Print recommendation
    print("\nRECOMMENDATION:")
    for line in textwrap.wrap(recommendation, width=66):
        print(line)
    
    print("-" * 70)

def export_report(reports, output_file, is_json=False):
    """
    Export report to a file.
    
    Args:
        reports (list): List of report dictionaries
        output_file (str): File path to write to
        is_json (bool): Whether to output in JSON format
    """
    if is_json:
        # Export as JSON
        with open(output_file, 'w') as f:
            json.dump(reports, f, indent=2)
    else:
        # Export as human-readable text
        with open(output_file, 'w') as f:
            f.write("PHISHING LINK SCANNER RESULTS\n")
            f.write("=" * 40 + "\n\n")
            
            for report in reports:
                if 'error' in report:
                    f.write(f"ERROR: {report['url']}\n")
                    f.write("-" * 40 + "\n")
                    f.write(report['error'] + "\n")
                    f.write("-" * 40 + "\n\n")
                    continue
                
                url = report['url']
                score = report['score']
                risk_level = report['risk_level']
                findings = report['findings']
                is_suspicious = report['is_suspicious']
                recommendation = report['recommendation']
                
                f.write(f"URL: {url}\n")
                f.write("-" * 40 + "\n")
                
                if is_suspicious:
                    f.write(f"RESULT: SUSPICIOUS [{score}/100] - {risk_level} RISK\n\n")
                else:
                    f.write(f"RESULT: LEGITIMATE [{score}/100] - {risk_level} RISK\n\n")
                
                f.write("FINDINGS:\n")
                for finding in sorted(findings, key=lambda x: x['impact'], reverse=True):
                    impact = finding['impact']
                    description = finding['description']
                    evidence = finding.get('evidence', '')
                    
                    f.write(f"• {description} (Impact: {impact})\n")
                    if evidence:
                        for line in textwrap.wrap(evidence, width=66):
                            f.write(f"  {line}\n")
                
                f.write("\nRECOMMENDATION:\n")
                for line in textwrap.wrap(recommendation, width=66):
                    f.write(f"{line}\n")
                
                f.write("\n" + "=" * 40 + "\n\n")
            
            f.write(f"\nScanned {len(reports)} URLs on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print(f"Report exported to {output_file}")