#!/usr/bin/env python3
"""
URL validation utilities.

This module provides functions for validating and normalizing URLs.
"""

import re
import ipaddress
from urllib.parse import urlparse, urlunparse

def is_valid_url(url):
    """
    Check if a URL has valid format.
    
    Args:
        url (str): The URL to validate
        
    Returns:
        bool: True if the URL is valid, False otherwise
    """
    # Add http:// prefix if no scheme is provided
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def normalize_url(url):
    """
    Normalize a URL to a standard format.
    
    Args:
        url (str): The URL to normalize
        
    Returns:
        str: The normalized URL
    """
    # Add http:// prefix if no scheme is provided
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        
        # Remove default ports
        netloc = parsed.netloc
        if ':' in netloc:
            host, port = netloc.split(':')
            if (parsed.scheme == 'http' and port == '80') or (parsed.scheme == 'https' and port == '443'):
                netloc = host
        
        # Remove redundant www if present
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        
        # Remove trailing slash from path if it's the only character
        path = parsed.path
        if path == '/':
            path = ''
        
        # Rebuild the URL with normalized components
        normalized = urlunparse((
            parsed.scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            ''  # Remove fragment
        ))
        
        return normalized
    except Exception:
        return url

def has_ip_address(url):
    """
    Check if the URL contains an IP address instead of a domain name.
    
    Args:
        url (str): The URL to check
        
    Returns:
        bool: True if the URL contains an IP address, False otherwise
    """
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        
        # Remove port if present
        if ':' in host:
            host = host.split(':')[0]
        
        # Try to parse as IPv4
        try:
            ipaddress.IPv4Address(host)
            return True
        except ValueError:
            pass
        
        # Try to parse as IPv6
        try:
            # IPv6 addresses in URLs are enclosed in brackets
            if host.startswith('[') and host.endswith(']'):
                ipaddress.IPv6Address(host[1:-1])
                return True
        except ValueError:
            pass
        
        return False
    except Exception:
        return False

def extract_domain(url):
    """
    Extract the domain part from a URL.
    
    Args:
        url (str): The URL to process
        
    Returns:
        str: The domain name
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove username/password if present
        if '@' in domain:
            domain = domain.split('@')[1]
        
        return domain
    except Exception:
        return ""

def extract_path(url):
    """
    Extract the path part from a URL.
    
    Args:
        url (str): The URL to process
        
    Returns:
        str: The path
    """
    try:
        parsed = urlparse(url)
        return parsed.path or "/"
    except Exception:
        return "/"

def extract_query_params(url):
    """
    Extract query parameters from a URL.
    
    Args:
        url (str): The URL to process
        
    Returns:
        dict: Dictionary of query parameters
    """
    try:
        parsed = urlparse(url)
        query = parsed.query
        
        params = {}
        for param in query.split('&'):
            if not param:
                continue
                
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
            else:
                params[param] = ''
                
        return params
    except Exception:
        return {}