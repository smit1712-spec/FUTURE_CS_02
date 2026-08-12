import re
import sys
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


def analyze_email(file_path):
    # --------------------------------------------------
    # Read the email
    # --------------------------------------------------
    try:
        with open(file_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except FileNotFoundError:
        print(f"\nError: Email file not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"\nError reading email: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("        PHISHING EMAIL ANALYZER")
    print("=" * 60)

    # --------------------------------------------------
    # 1. EMAIL INFORMATION
    # --------------------------------------------------

    sender = msg.get("From", "Not available")
    recipient = msg.get("To", "Not available")
    subject = msg.get("Subject", "Not available")
    return_path = msg.get("Return-Path", "Not available")

    print("\n[1] EMAIL INFORMATION")
    print("-" * 60)
    print(f"From       : {sender}")
    print(f"To         : {recipient}")
    print(f"Subject    : {subject}")
    print(f"Return-Path: {return_path}")

    # --------------------------------------------------
    # 2. EMAIL AUTHENTICATION
    # --------------------------------------------------

    print("\n[2] EMAIL AUTHENTICATION")
    print("-" * 60)

    authentication_results = msg.get(
        "Authentication-Results", ""
    )

    spf_match = re.search(
        r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        authentication_results,
        re.IGNORECASE
    )

    dkim_match = re.search(
        r"\bdkim=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        authentication_results,
        re.IGNORECASE
    )

    dmarc_match = re.search(
        r"\bdmarc=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        authentication_results,
        re.IGNORECASE
    )

    spf = spf_match.group(1).upper() if spf_match else "NOT FOUND"
    dkim = dkim_match.group(1).upper() if dkim_match else "NOT FOUND"
    dmarc = dmarc_match.group(1).upper() if dmarc_match else "NOT FOUND"

    print(f"SPF  : {spf}")
    print(f"DKIM : {dkim}")
    print(f"DMARC: {dmarc}")

    # --------------------------------------------------
    # 3. RECEIVED HEADERS
    # --------------------------------------------------

    print("\n[3] RECEIVED HEADERS")
    print("-" * 60)

    received_headers = msg.get_all("Received", [])

    if received_headers:
        for i, received in enumerate(received_headers, 1):
            print(f"\nReceived #{i}:")
            print(received)
    else:
        print("No Received headers found.")

    # --------------------------------------------------
    # 4. URL ANALYSIS
    # --------------------------------------------------

    print("\n[4] URL ANALYSIS")
    print("-" * 60)

    email_text = msg.as_string()

    urls = re.findall(
        r'https?://[^\s<>"\']+',
        email_text,
        re.IGNORECASE
    )

    # Remove duplicates
    urls = list(dict.fromkeys(urls))

    if urls:
        print(f"URLs found: {len(urls)}")

        for i, url in enumerate(urls, 1):
            print(f"{i}. {url}")
    else:
        print("No HTTP/HTTPS URLs found.")

    # --------------------------------------------------
    # 5. SUSPICIOUS INDICATORS
    # --------------------------------------------------

    print("\n[5] SUSPICIOUS INDICATORS")
    print("-" * 60)

    score = 0
    indicators = []

    # --------------------------------------------------
    # Authentication failures
    # --------------------------------------------------

    if spf == "FAIL":
        score += 2
        indicators.append("SPF failed")

    if dkim == "FAIL":
        score += 2
        indicators.append("DKIM failed")

    if dmarc == "FAIL":
        score += 3
        indicators.append("DMARC failed")

    # --------------------------------------------------
    # Missing authentication
    # --------------------------------------------------

    missing_auth_count = 0

    if spf == "NOT FOUND":
        missing_auth_count += 1
        indicators.append("SPF result not found")

    if dkim == "NOT FOUND":
        missing_auth_count += 1
        indicators.append("DKIM result not found")

    if dmarc == "NOT FOUND":
        missing_auth_count += 1
        indicators.append("DMARC result not found")

    # Three missing authentication mechanisms are
    # treated as a stronger warning.
    if missing_auth_count == 3:
        score += 3

    # --------------------------------------------------
    # Sender / Return-Path domain analysis
    # --------------------------------------------------

    sender_domain = None
    return_domain = None

    sender_match = re.search(
        r'[\w.+-]+@([\w.-]+)',
        sender
    )

    return_match = re.search(
        r'[\w.+-]+@([\w.-]+)',
        return_path
    )

    if sender_match:
        sender_domain = sender_match.group(1).lower()

    if return_match:
        return_domain = return_match.group(1).lower()

    if sender_domain and return_domain:
        # A Return-Path can legitimately be a subdomain
        # of the sender's domain.
        if not (
            return_domain == sender_domain
            or return_domain.endswith("." + sender_domain)
        ):
            score += 2
            indicators.append(
                f"Sender/Return-Path domain mismatch: "
                f"{sender_domain} vs {return_domain}"
            )

    # --------------------------------------------------
    # URL analysis
    # --------------------------------------------------

    suspicious_url_count = 0

    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()

            # HTTP instead of HTTPS
            if parsed.scheme.lower() == "http":
                suspicious_url_count += 1

            # Account/login/verification related words
            if re.search(
                r'login|verify|verification|account|password|signin|confirm',
                full_url,
                re.IGNORECASE
            ):
                suspicious_url_count += 1

            # IP address used as hostname
            if re.match(
                r'^\d{1,3}(\.\d{1,3}){3}$',
                domain
            ):
                suspicious_url_count += 1

            # URL contains suspicious redirect/query patterns
            if re.search(
                r'click|redirect|url=|token=|upn=',
                full_url,
                re.IGNORECASE
            ):
                suspicious_url_count += 1

            # Invalid or unusual domain
            if domain.endswith(".invalid"):
                suspicious_url_count += 2

        except Exception:
            continue

    # Large number of URLs
    if len(urls) > 5:
        score += 2
        indicators.append("Large number of URLs")

    # Suspicious URL characteristics
    if suspicious_url_count >= 5:
        score += 2
        indicators.append(
            f"Suspicious URL characteristics detected: "
            f"{suspicious_url_count}"
        )

    # --------------------------------------------------
    # Urgency-related subject analysis
    # --------------------------------------------------

    urgent_words = [
        "urgent",
        "verify your account",
        "account suspended",
        "account locked",
        "confirm your account",
        "password expired",
        "click immediately",
        "immediately"
    ]

    subject_lower = subject.lower()

    matched_urgent_words = []

    for word in urgent_words:
        if word in subject_lower:
            matched_urgent_words.append(word)

    if matched_urgent_words:
        score += 3

        for word in matched_urgent_words:
            indicators.append(
                f"Urgency-related subject phrase: '{word}'"
            )

    # --------------------------------------------------
    # No indicators
    # --------------------------------------------------

    if indicators:
        for indicator in indicators:
            print(f"- {indicator}")
    else:
        print("No major suspicious indicators detected.")

    # --------------------------------------------------
    # 6. FINAL ASSESSMENT
    # --------------------------------------------------

    print("\n[6] FINAL ASSESSMENT")
    print("-" * 60)

    print(f"Risk Score: {score}")

    if score >= 6:
        classification = "PHISHING"
    elif score >= 3:
        classification = "SUSPICIOUS"
    else:
        classification = "LIKELY LEGITIMATE"

    print(f"Classification: {classification}")

    print("\n" + "=" * 60)


# ------------------------------------------------------
# PROGRAM ENTRY POINT
# ------------------------------------------------------

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("\nUsage:")
        print("python email_analyzer.py <email_file>")

        print("\nExample:")
        print(
            'python email_analyzer.py '
            '"samples/legitimate/PLIX Email.txt"'
        )

        sys.exit(1)

    analyze_email(sys.argv[1])