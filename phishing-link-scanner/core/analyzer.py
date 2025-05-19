#!/usr/bin/env python3
"""
URL Analyzer module.

This module provides the main functionality for analyzing URLs for
phishing indicators.
"""

import re
import ipaddress
import socket
from urllib.parse import urlparse, parse_qs
import requests
import tldextract
from datetime import datetime

from core.rules import (
    POPULAR_DOMAINS,
    SECURITY_TERMS,
    SUSPICIOUS_TERMS,
    URL_SHORTENERS,
    SUSPICIOUS_TLDS,
    HOMOGLYPHS
)

class URLAnalyzer:
    """Analyzes URLs for potential phishing indicators."""
    
    def __init__(self, url):
        """
        Initialize the URLAnalyzer.
        
        Args:
            url (str): The URL to analyze
        """
        self.url = url.strip()
        self.parsed_url = urlparse(self.url)
        self.domain_info = tldextract.extract(self.url)
        self.findings = []
        self.score = 0
    
    def analyze(self):
        """
        Perform comprehensive analysis on the URL.
        
        Returns:
            dict: Analysis results with findings and score
        """
        # Protocol analysis
        self._check_protocol()
        
        # Domain analysis
        self._check_domain()
        self._check_homoglyphs()
        self._check_subdomains()
        self._check_ip_address()
        
        # Path and parameters analysis
        self._check_path()
        self._check_parameters()
        
        # Special patterns
        self._check_special_chars()
        self._check_url_shortener()
        
        # Additional checks
        self._check_redirection()
        
        # Calculate final score (normalize to 0-100)
        normalized_score = min(100, self.score)
        
        return {
            'score': normalized_score,
            'findings': self.findings,
            'domain': self.domain_info.domain,
            'tld': self.domain_info.suffix,
            'subdomain': self.domain_info.subdomain,
            'protocol': self.parsed_url.scheme,
            'path': self.parsed_url.path,
            'query': self.parsed_url.query
        }
    
    def _add_finding(self, description, impact, evidence=None):
        """
        Add a finding to the analysis results.
        
        Args:
            description (str): Description of the finding
            impact (int): Impact score (0-100)
            evidence (str, optional): Specific evidence
        """
        self.findings.append({
            'description': description,
            'impact': impact,
            'evidence': evidence
        })
        self.score += impact
    
    def _check_protocol(self):
        """Check if the protocol is secure."""
        if not self.parsed_url.scheme:
            self._add_finding(
                "Missing protocol specification",
                10,
                "URL does not specify HTTP or HTTPS"
            )
        elif self.parsed_url.scheme == 'http':
            self._add_finding(
                "Uses insecure HTTP protocol",
                15,
                "HTTP connections do not encrypt data in transit"
            )
        
        # Check for protocol obfuscation
        if 'http' in self.parsed_url.netloc.lower():
            self._add_finding(
                "Possible protocol obfuscation",
                25,
                f"Found 'http' in unusual location: {self.parsed_url.netloc}"
            )
    
    def _check_domain(self):
        """Analyze domain characteristics."""
        domain = self.domain_info.domain
        
        # Check if domain is a close misspelling of popular domains
        for popular_domain in POPULAR_DOMAINS:
            # Simple Levenshtein distance approximation
            if popular_domain != domain and self._similar_text(popular_domain, domain) > 0.8:
                self._add_finding(
                    "Domain name is similar to a popular website",
                    25,
                    f"'{domain}' is similar to '{popular_domain}'"
                )
                break
        
        # Check for suspicious TLDs
        if self.domain_info.suffix in SUSPICIOUS_TLDS:
            self._add_finding(
                "Uses suspicious TLD",
                10,
                f"'.{self.domain_info.suffix}' is commonly used in phishing"
            )
        
        # Check for excessive hyphens
        if domain.count('-') >= 2:
            self._add_finding(
                "Domain contains multiple hyphens",
                10,
                f"Found {domain.count('-')} hyphens in domain"
            )
        
        # Check for suspicious terms in domain
        for term in SUSPICIOUS_TERMS:
            if term in domain.lower():
                self._add_finding(
                    "Domain contains suspicious term",
                    15,
                    f"Found '{term}' in domain name"
                )
    
    def _check_homoglyphs(self):
        """Check for homoglyphs (similar-looking characters)."""
        domain = self.domain_info.domain.lower()
        
        # Check for digit/letter substitutions
        for char, replacement in HOMOGLYPHS.items():
            if char in domain:
                self._add_finding(
                    "Domain contains homoglyphs",
                    20,
                    f"Found '{char}' which may be confused with '{replacement}'"
                )
    
    def _check_subdomains(self):
        """Check for suspicious subdomain patterns."""
        subdomain = self.domain_info.subdomain
        
        if not subdomain:
            return
            
        # Check for excessive subdomain levels
        if subdomain.count('.') >= 2:
            self._add_finding(
                "Excessive subdomain levels",
                10,
                f"Found {subdomain.count('.') + 1} subdomain levels"
            )
        
        # Check for popular brand names in subdomain
        for domain in POPULAR_DOMAINS:
            if domain in subdomain.lower() and domain != self.domain_info.domain.lower():
                self._add_finding(
                    "Subdomain contains popular brand name",
                    30,
                    f"Found '{domain}' in subdomain but domain is '{self.domain_info.domain}'"
                )
                break
        
        # Check for security terms in subdomain
        for term in SECURITY_TERMS:
            if term in subdomain.lower():
                self._add_finding(
                    "Subdomain contains security-baiting term",
                    15,
                    f"Found '{term}' in subdomain"
                )
    
    def _check_ip_address(self):
        """Check if the domain is an IP address."""
        domain = self.parsed_url.netloc.split(':')[0]  # Remove port if present
        
        try:
            ipaddress.ip_address(domain)
            self._add_finding(
                "URL uses IP address instead of domain name",
                25,
                f"Direct IP access: {domain}"
            )
        except ValueError:
            # Not an IP address, which is the expected case
            pass
    
    def _check_path(self):
        """Analyze URL path for suspicious patterns."""
        path = self.parsed_url.path.lower()
        
        if not path or path == '/':
            return
        
        # Check for common phishing URL paths
        for term in SECURITY_TERMS:
            if term in path:
                self._add_finding(
                    "URL path contains security-baiting term",
                    15,
                    f"Found '{term}' in URL path"
                )
        
        # Check for file extensions that may indicate phishing
        if re.search(r'\.(php|html|aspx)$', path):
            file_ext = re.search(r'\.([^./]+)$', path).group(1)
            
            # Check if path contains words like "login", "signin", "account"
            login_terms = ['login', 'signin', 'account', 'secure', 'verify']
            if any(term in path for term in login_terms):
                self._add_finding(
                    f"URL contains {file_ext} script potentially handling credentials",
                    15,
                    f"'{path}' may be collecting sensitive information"
                )
        
        # Check for suspicious directories
        suspicious_dirs = ['wp-includes', 'wp-admin', 'admin', 'cpanel', 'webmail', 'mail']
        for directory in suspicious_dirs:
            if f'/{directory}/' in path:
                self._add_finding(
                    "URL path contains sensitive directory",
                    10,
                    f"Found '/{directory}/' in path which may indicate targeting admin interfaces"
                )
    
    def _check_parameters(self):
        """Analyze URL parameters for suspicious patterns."""
        query = self.parsed_url.query
        
        if not query:
            return
            
        params = parse_qs(query)
        
        # Check for suspicious parameter names
        suspicious_params = ['token', 'auth', 'password', 'login', 'email', 'account', 'verification']
        for param in suspicious_params:
            if param in params:
                self._add_finding(
                    "URL contains suspicious query parameter",
                    10,
                    f"Found '{param}' parameter which may indicate credential harvesting"
                )
        
        # Check for excessively long parameter values (potential obfuscation)
        for param, values in params.items():
            for value in values:
                if len(value) > 100:
                    self._add_finding(
                        "URL contains unusually long parameter value",
                        15,
                        f"Parameter '{param}' has a {len(value)} character value"
                    )
        
        # Check for encoded parameters that might be hiding something
        encoded_pattern = r'%[0-9A-Fa-f]{2}'
        encoded_count = len(re.findall(encoded_pattern, query))
        if encoded_count > 5:
            self._add_finding(
                "URL contains heavily encoded parameters",
                10,
                f"Found {encoded_count} encoded characters which may be hiding malicious content"
            )
    
    def _check_special_chars(self):
        """Check for misuse of special characters in URL."""
        
        # Check for '@' symbol which can be used to obscure destination
        if '@' in self.parsed_url.netloc:
            self._add_finding(
                "URL contains '@' character in domain portion",
                40,
                "The '@' symbol can be used to make the URL appear like it belongs to a different domain"
            )
        
        # Check for double slashes not part of protocol
        if '//' in self.url.replace('://', ''):
            self._add_finding(
                "URL contains unexpected double slashes",
                15,
                "Double slashes not part of the protocol may indicate an obscured destination"
            )
    
    def _check_url_shortener(self):
        """Check if URL is using a URL shortening service."""
        domain = f"{self.domain_info.domain}.{self.domain_info.suffix}"
        
        if domain in URL_SHORTENERS:
            self._add_finding(
                "URL uses a shortening service",
                20,
                f"URL shortener ({domain}) may be hiding the true destination"
            )
    
    def _check_redirection(self):
        """Check if URL contains redirection indicators."""
        redirects = ['redirect', 'redir', 'url', 'link', 'goto', 'return']
        query = self.parsed_url.query.lower()
        
        for term in redirects:
            if term in query:
                pattern = fr'[?&]{term}=([^&]+)'
                match = re.search(pattern, query)
                if match:
                    redirect_url = match.group(1)
                    self._add_finding(
                        "URL contains redirection parameter",
                        25,
                        f"Found '{term}=' parameter which redirects to another location"
                    )
    
    def _similar_text(self, first, second):
        """
        Calculate similarity between two strings.
        
        A simple implementation of similarity comparison.
        Returns a value between 0 (no similarity) and 1 (identical).
        
        Args:
            first (str): First string to compare
            second (str): Second string to compare
            
        Returns:
            float: Similarity score between 0 and 1
        """
        if not first or not second:
            return 0
            
        first = first.lower()
        second = second.lower()
        
        if first == second:
            return 1.0
            
        # Simple check: how many characters appear in both strings
        first_set = set(first)
        second_set = set(second)
        common_chars = len(first_set.intersection(second_set))
        
        # Length-based similarity
        length_similarity = min(len(first), len(second)) / max(len(first), len(second))
        
        # Character-based similarity
        char_similarity = common_chars / len(first_set.union(second_set))
        
        # Look for big chunks of similar text
        chunks_similarity = 0
        for i in range(min(len(first), len(second)), 0, -1):
            for j in range(len(first) - i + 1):
                chunk = first[j:j+i]
                if chunk in second:
                    chunks_similarity = i / max(len(first), len(second))
                    break
            if chunks_similarity > 0:
                break
        
        # Weighted combination
        return (0.4 * length_similarity) + (0.3 * char_similarity) + (0.3 * chunks_similarity)