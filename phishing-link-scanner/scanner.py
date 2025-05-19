#!/usr/bin/env python3
"""
Phishing Link Scanner - Command Line Tool

This script analyzes URLs for potential phishing indicators
by checking various characteristics commonly found in phishing URLs.

Author: Kaouthar
License: MIT
"""

import argparse
import sys
import json
import os
from datetime import datetime

# Import local modules
from core.analyzer import URLAnalyzer
from core.reporter import generate_report, print_report, export_report
from utils.validators import is_valid_url

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Scan URLs for potential phishing indicators')
    parser.add_argument('--url', '-u', type=str, required=True, help='URL to scan')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed analysis')
    parser.add_argument('--threshold', '-t', type=int, default=70, 
                       help='Suspicion threshold (0-100, default: 70)')
    parser.add_argument('--output', '-o', type=str, help='Output results to file')
    parser.add_argument('--json', '-j', action='store_true', help='Output in JSON format')
    parser.add_argument('--batch', '-b', type=str, help='Batch scan URLs from file')
    return parser.parse_args()

def scan_url(url, threshold=70, verbose=False):
    """
    Scan a single URL for phishing indicators.
    
    Args:
        url (str): The URL to scan
        threshold (int): The threshold for considering a URL suspicious
        verbose (bool): Whether to display verbose analysis
        
    Returns:
        dict: Analysis results
    """
    # Validate URL format
    if not is_valid_url(url):
        return {
            'url': url,
            'error': 'Invalid URL format. Please provide a properly formatted URL.',
            'score': 0,
            'timestamp': datetime.now().isoformat(),
            'status': 'error'
        }
    
    # Analyze the URL
    analyzer = URLAnalyzer(url)
    results = analyzer.analyze()
    
    # Generate report
    report = generate_report(url, results, threshold)
    
    return report

def main():
    """Main function to run the scanner."""
    args = parse_arguments()
    
    # Handle batch processing
    if args.batch:
        if not os.path.isfile(args.batch):
            print(f"Error: File not found: {args.batch}")
            sys.exit(1)
            
        results = []
        with open(args.batch, 'r') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    result = scan_url(url, args.threshold, args.verbose)
                    results.append(result)
                    if not args.json:
                        print_report(result, args.verbose)
                        print("\n" + "-" * 70 + "\n")
        
        if args.output:
            export_report(results, args.output, is_json=args.json)
        sys.exit(0)
    
    # Process single URL
    results = scan_url(args.url, args.threshold, args.verbose)
    
    # Output results
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results, args.verbose)
    
    # Export to file if requested
    if args.output:
        export_report([results], args.output, is_json=args.json)
    
    # Exit with status code based on whether URL is suspicious
    sys.exit(0 if results['score'] < args.threshold else 1)

if __name__ == "__main__":
    main()