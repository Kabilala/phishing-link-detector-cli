# Phishing Link Scanner

This command-line tool detects potential phishing links by analyzing URLs for suspicious patterns and characteristics. It's built for educational purposes as part of a cybersecurity portfolio.

## Features

- Multi-factor analysis of URLs to detect potential phishing attempts
- Detection of non-secure HTTP protocols
- Identification of suspicious domain names and patterns
- Recognition of URL shorteners that may hide malicious destinations
- Detection of homoglyphs and special character manipulation
- Reporting with detailed explanations for each suspicious element
- Customizable sensitivity settings

## Installation

### Prerequisites

- Python 3.6+
- Required packages: `requests`, `argparse`, `tldextract`

### Setup

1. Clone this repository:
   ```
   git clone https://github.com/kabilala/phishing-link-scanner.git
   cd phishing-link-scanner
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```bash
python scanner.py --url "https://example.com"
```

### Available Options

```
usage: scanner.py [-h] --url URL [--verbose] [--threshold THRESHOLD] [--output OUTPUT]

Scan URLs for potential phishing indicators

optional arguments:
  -h, --help            show this help message and exit
  --url URL, -u URL     URL to scan
  --verbose, -v         Show detailed analysis
  --threshold THRESHOLD, -t THRESHOLD
                        Suspicion threshold (0-100, default: 70)
  --output OUTPUT, -o OUTPUT
                        Output results to file
```

### Example Output

```
----------------------------------------------------------------------------
🔍 PHISHING LINK SCANNER RESULTS
----------------------------------------------------------------------------
URL: http://facebo0k.com/login.php?secur1ty=verification-needed
----------------------------------------------------------------------------
❌ SUSPICIOUS [80/100]: This URL contains multiple phishing indicators

ANALYSIS:
✓ Uses non-secure HTTP protocol
✓ Domain contains homoglyphs (0 instead of o)
✓ URL contains security-baiting terms
✓ Unusual characters in domain name
✓ PHP script handling login information
✓ URL parameter suggests urgent action

RECOMMENDATION:
This URL exhibits classic phishing characteristics. Avoid clicking or 
entering any personal information. The domain attempts to mimic Facebook
but contains character substitutions.
----------------------------------------------------------------------------
```

## Technical Details

The scanner evaluates URLs based on several factors:

1. **Protocol Analysis**
   - HTTP instead of HTTPS
   - Protocol obfuscation

2. **Domain Analysis**
   - Similarity to popular domains (typosquatting)
   - Homoglyph detection (similar-looking characters)
   - Excessive subdomains
   - Recently registered domains

3. **Path and Parameter Analysis**
   - Presence of security-baiting terms
   - Suspicious file extensions
   - Unusual URL parameters
   - Redirection indicators

4. **Content Assessment**
   - URL shortener detection
   - IP address instead of domain name
   - Special character misuse (@, //, etc.)

## Security Scoring

Each detected issue contributes to an overall suspicion score:

- 0-30: Low risk
- 31-60: Medium risk
- 61-80: High risk
- 81-100: Very high risk

## Code Structure

- `scanner.py` - Main script with CLI interface
- `core/` - Directory containing core functionality:
  - `analyzer.py` - URL analysis engine
  - `rules.py` - Phishing detection rules
  - `reporter.py` - Reporting functions
- `utils/` - Utility functions and helpers:
  - `validators.py` - URL validation functions
  - `homoglyphs.py` - Homoglyph detection

## Limitations

- This tool provides an indication of risk but is not 100% accurate
- False positives may occur with legitimate but unusual URLs
- False negatives may occur with sophisticated phishing techniques
- No webpage content analysis is performed

## Educational Use

This tool is designed for educational purposes to:

- Understand how phishing URLs are constructed
- Learn about common phishing techniques
- Develop awareness of URL security indicators
- Practice Python programming for cybersecurity

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational purposes only. It should not be used as the sole method for determining if a website is legitimate. Always use multiple verification methods and proper cybersecurity practices.
