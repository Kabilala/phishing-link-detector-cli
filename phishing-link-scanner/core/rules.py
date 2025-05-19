#!/usr/bin/env python3
"""
Phishing detection rules and reference data.

This module contains all the pattern definitions, suspicious indicators,
and reference data used by the scanner.
"""

# Popular domain names that might be targets for typosquatting
POPULAR_DOMAINS = [
    'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix', 'paypal',
    'instagram', 'twitter', 'yahoo', 'linkedin', 'ebay', 'spotify', 'gmail',
    'outlook', 'dropbox', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
    'americanexpress', 'coinbase', 'blockchain', 'binance', 'steam', 'twitch',
    'github', 'gitlab', 'stackoverflow', 'reddit', 'wordpress', 'shopify', 
    'adobe', 'office365', 'icloud', 'protonmail', 'zoom', 'tiktok', 'snapchat',
    'discord', 'telegram', 'whatsapp', 'pinterest', 'tumblr', 'vimeo', 'youtube'
]

# Terms that are often used in phishing URLs to create a sense of security
SECURITY_TERMS = [
    'secure', 'security', 'login', 'signin', 'logon', 'account', 'verify',
    'verification', 'confirm', 'authenticate', 'validation', 'wallet', 
    'update', 'service', 'manage', 'authorization', 'password', 'recover',
    'alert', 'limited', 'important', 'warning', 'authenticate', 'access',
    'reactivate', 'protect', 'identity', 'info', 'official', 'support',
    'help', 'team', 'billing', 'payment', 'privacy', 'suspicious', 'unusual',
    'activity', 'unlock', 'restrict', 'blocked', 'customer', 'reset'
]

# Terms often found in suspicious URLs
SUSPICIOUS_TERMS = [
    'covid', 'bonus', 'free', 'limited', 'offer', 'prize', 'win', 'winner',
    'lottery', 'gift', 'deal', 'discount', 'promotion', 'special', 'reward',
    'urgent', 'important', 'attention', 'update', 'account', 'bank', 'credit',
    'debit', 'password', 'credential', 'payment', 'pay', 'verify', 'confirm',
    'secure', 'login', 'signin', 'validate', 'ebay', 'paypal', 'apple', 'id',
    'microsoft', 'amazon', 'google', 'facebook', 'instagram', 'netflix',
    'bitcoin', 'crypto', 'tax', 'irs', 'refund', 'return', 'delivery'
]

# Common URL shortening services
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cli.gs', 'ow.ly',
    'buff.ly', 'adf.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc',
    'shorte.st', 'tr.im', 'snip.ly', 'ln.is', 'po.st', 'go2l.ink', 'surl.li',
    's2r.co', 'v.gd', 'spoo.me', 'x.co', 'tny.im', 'urls.im', 'urlcut.com',
    'loopt.us', 'x.co', 'zipurl.co', 'bom.to', 'daa.pl', 'pixurl.org', 'hiveurl.com'
]

# TLDs that are commonly used in phishing campaigns
SUSPICIOUS_TLDS = [
    'top', 'xyz', 'online', 'club', 'website', 'site', 'tech', 'space',
    'art', 'shop', 'fun', 'app', 'ml', 'ga', 'cf', 'gq', 'tk', 'best',
    'work', 'loan', 'date', 'racing', 'download', 'stream', 'party', 'review',
    'country', 'science', 'bid', 'faith', 'cricket', 'pw', 'christmas',
    'men', 'study', 'link', 'accountant', 'world', 'buzz', 'network', 'agency',
    'icu', 'vip', 'surf', 'bar', 'one', 'monster', 'mom', 'band', 'webcam'
]

# Dictionary of homoglyphs (characters that look similar but are different)
HOMOGLYPHS = {
    '0': 'o',
    'o': '0',
    '1': 'l',
    'l': '1',
    'i': '1',
    '5': 's',
    's': '5',
    'rn': 'm',
    'cl': 'd',
    'vv': 'w',
    'e': 'a',
    'a': 'e',
    'g': 'q',
    'j': 'i',
    'i': 'j'
}

# File extensions that might indicate phishing when combined with login pages
SUSPICIOUS_EXTENSIONS = [
    '.php', '.html', '.aspx', '.asp', '.jsp', '.cgi', '.pl'
]

# Common login/authentication parameter names
AUTH_PARAMETERS = [
    'login', 'username', 'user', 'email', 'password', 'pass', 'pwd', 'passwd',
    'token', 'auth', 'key', 'session', 'account', 'acct', 'verify', 'code',
    'credential', 'cred', 'signin', 'signout', 'login_credentials', 'j_username',
    'j_password', 'authentication', 'otp', 'pin', 'secret'
]

# Redirection parameter names
REDIRECT_PARAMETERS = [
    'redirect', 'redirecturl', 'redirect_uri', 'redirect_url', 'return',
    'returnurl', 'return_uri', 'return_url', 'goto', 'next', 'destination',
    'redir', 'returl', 'returnto', 'return_to', 'go', 'location', 'link',
    'url', 'site', 'forward', 'forward_url', 'target', 'view', 'window'
]

# Common misleading subdomain patterns
MISLEADING_SUBDOMAINS = [
    'signin', 'login', 'secure', 'account', 'banking', 'update', 'security',
    'verification', 'verify', 'authenticate', 'validate', 'confirm', 'secure',
    'customer', 'support', 'help', 'service', 'official', 'online', 'dashboard'
]