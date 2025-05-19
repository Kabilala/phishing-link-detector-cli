#!/usr/bin/env python3
"""
Homoglyph detection utilities.

This module provides functions for detecting homoglyphs (similar-looking
characters) in domain names, which is a common technique in phishing URLs.
"""

# Extended homoglyphs dictionary with unicode lookalikes
HOMOGLYPHS_EXTENDED = {
    # Latin-based homoglyphs
    'a': ['а', 'ɑ', 'ạ', 'ǎ', 'ȧ', 'ą'],
    'b': ['Ƅ', 'ƅ', 'Ь', 'Ꮟ', 'ḅ'],
    'c': ['с', 'ϲ', 'ς', 'ƈ', 'ċ', 'ҫ'],
    'd': ['ⅾ', 'ԁ', 'ḍ', 'ḓ', 'ď'],
    'e': ['е', 'ẹ', 'ė', 'ę', 'ē', 'ě'],
    'f': ['ｆ', 'ḟ', 'ƒ'],
    'g': ['ɡ', 'ǵ', 'ġ', 'ğ', 'ǧ', 'ģ'],
    'h': ['һ', 'ḥ', 'ḫ', 'ẖ', 'ħ'],
    'i': ['і', 'ⅰ', 'ị', 'ī', 'ĭ', 'і'],
    'j': ['ϳ', 'ј', 'ʝ'],
    'k': ['κ', 'ⲕ', 'ḳ', 'ḵ', 'ķ'],
    'l': ['ⅼ', 'ӏ', '1', 'ḷ', 'ḹ', 'ļ'],
    'm': ['ｍ', 'ṃ', 'ṁ', 'ḿ'],
    'n': ['ո', 'ṇ', 'ṅ', 'ṉ', 'ñ'],
    'o': ['о', 'ο', '0', 'ọ', 'ỏ', 'ơ', 'ö'],
    'p': ['р', 'ρ', 'ṗ', 'ṕ', 'ṗ'],
    'q': ['ԛ', 'ɋ', 'ʠ'],
    'r': ['г', 'ｒ', 'ṛ', 'ṟ', 'ŕ'],
    's': ['ѕ', 'ṣ', 'ṡ', 'ṥ', 'ś', '5'],
    't': ['τ', 'ｔ', 'ṭ', 'ṫ', 'ţ'],
    'u': ['υ', 'ս', 'ụ', 'ů', 'ŭ', 'ü'],
    'v': ['ν', 'ѵ', 'ṿ', 'ⱱ'],
    'w': ['ѡ', 'ԝ', 'ẉ', 'ẃ', 'ẁ'],
    'x': ['х', 'ẋ', 'ẍ'],
    'y': ['у', 'ý', 'ÿ', 'ỵ', 'ỳ'],
    'z': ['ᴢ', 'ꮓ', 'ẓ', 'ẕ', 'ż'],
    
    # Digit homoglyphs
    '0': ['o', 'O', 'о', 'О', 'Ο', 'ο'],
    '1': ['l', 'I', 'І', 'ӏ', 'ⅼ'],
    '2': ['ƻ', 'ᒿ'],
    '3': ['З', 'ʒ', 'ӡ', 'з'],
    '4': ['Ꮞ'],
    '5': ['Ƽ', 'ƽ', 'S', 's'],
    '6': ['б', 'ᓐ'],
    '7': ['𐓒', '፨'],
    '8': ['Ց', 'ȣ', '৪'],
    '9': ['g', 'q', 'ⅾ', 'ԁ'],
    
    # Common multi-character homoglyphs
    'cl': ['d'],
    'rn': ['m'],
    'vv': ['w'],
    'vv': ['w'],
    'VV': ['W'],
}

def contains_homoglyphs(domain):
    """
    Check if a domain contains homoglyphs.
    
    Args:
        domain (str): The domain name to check
        
    Returns:
        tuple: (bool, list) - Whether homoglyphs were found and list of detections
    """
    domain = domain.lower()
    detections = []
    
    # Check for simple character substitutions
    for char in domain:
        for original, lookalikes in HOMOGLYPHS_EXTENDED.items():
            if char in lookalikes:
                detections.append({
                    'character': char,
                    'looks_like': original,
                    'position': domain.index(char)
                })
    
    # Check for multi-character substitutions
    for multi_char, replacements in [(k, v) for k, v in HOMOGLYPHS_EXTENDED.items() if len(k) > 1]:
        if multi_char in domain:
            detections.append({
                'sequence': multi_char,
                'looks_like': ', '.join(replacements),
                'position': domain.index(multi_char)
            })
    
    return bool(detections), detections

def homoglyph_score(domain):
    """
    Calculate a score based on homoglyph presence.
    
    Args:
        domain (str): The domain name to check
        
    Returns:
        float: Score from 0.0 (no homoglyphs) to 1.0 (many homoglyphs)
    """
    has_homoglyphs, detections = contains_homoglyphs(domain)
    
    if not has_homoglyphs:
        return 0.0
    
    # Calculate ratio of homoglyphs to domain length
    ratio = len(detections) / len(domain)
    
    # Scale the score based on the ratio
    if ratio < 0.1:
        return 0.3  # One homoglyph in a long domain is less suspicious
    elif ratio < 0.2:
        return 0.6  # A few homoglyphs suggest possible phishing
    else:
        return 0.9  # Many homoglyphs strongly suggest phishing

def homoglyph_normalize(domain):
    """
    Normalize a domain by replacing homoglyphs with standard characters.
    
    Args:
        domain (str): The domain name to normalize
        
    Returns:
        str: Normalized domain name
    """
    domain = domain.lower()
    normalized = list(domain)
    
    for i, char in enumerate(domain):
        for original, lookalikes in HOMOGLYPHS_EXTENDED.items():
            if len(original) == 1 and char in lookalikes:
                normalized[i] = original
                break
    
    # Handle multi-character substitutions
    normalized_str = ''.join(normalized)
    for multi_char, replacements in [(k, v) for k, v in HOMOGLYPHS_EXTENDED.items() if len(k) > 1]:
        if multi_char in normalized_str:
            normalized_str = normalized_str.replace(multi_char, replacements[0])
    
    return normalized_str