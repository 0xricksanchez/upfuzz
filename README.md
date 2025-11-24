<p align="center">
  <img src="img/logo.png" alt="UpFuzz Logo" width="300"/>
</p>

# UpFuzz

**Advanced File Upload Payload Generator**

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

UpFuzz generates sophisticated file upload payloads designed to bypass WAFs and strict filtering mechanisms.
Unlike simple extension lists, UpFuzz creates **full filenames** with advanced evasion techniques like Unicode RTLO spoofing, NTFS Alternate Data Streams, and double-extension injection.

Designed to be piped directly into **Burp Suite Intruder** or **FFUF**.

## Installation

```bash
git clone https://github.com/yourusername/upfuzz.git
cd upfuzz
python upfuzz.py
```

## Usage

1. Standard Scan (PHP)

Generate variations like .php, .phtml, .php.jpg, .php%00.png.

```bash
python3 upfuzz.py --preset php --filename myprofile > payloads.txt
```

2. ISS/Windows Evasion

Target ASP/ASPX with Windows-specific bypasses (::$DATA, trailing dots).

```bash
python3 upfuzz.py --preset asp --filename document
```

3. Visual Spoofing (RTLO)

Create payloads that look like images to human administrators (e.g., holidays‮gpj.php).

```bash
python3 upfuzz.py --preset php --filename holidays --rtlo
```

## Burp Intruder Workflow

1. Generate payloads: `python3 upfuzz.py --preset web --filename test -o wordlist.txt`
2. Load into Burp:

- Send reqeuest to Intruder.
- Highlight the entire filename in the request: `filename="§image.jpg§"`.
- **Payloads tab**: Load `wordlist.txt` as payload set.

3. Bypass Magic Bytes (Optional):

- Run `python3 upfuzz.py --show-magic` to get the hex signatures.
- In Burp: Payload Processing -> Add Prefix -> Paste the hex (e.g., \xFF\xD8\xFF\xE0).

## Presets

| Preset | Included Extensions              |
| ------ | -------------------------------- |
| php    | .php, .phtml, .phar, .inc, etc.  |
| asp    | .asp, .aspx, .cer, .config       |
| jsp    | .jsp, .jspx, .do, .action        |
| xml    | .xml, .svg, .json, .xslt (XXE)   |
| web    | Combination of PHP, ASP, and JSP |
