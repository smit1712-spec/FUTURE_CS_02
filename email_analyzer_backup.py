import re
import sys
from email import policy
from email.parser import BytesParser


def analyze_email(file_path):
    # Read the email file
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    print("\n" + "=" * 60)
    print("        PHISHING EMAIL ANALYZER")
    print("=" * 60)

    # --------------------------------------------------
    # 1. Basic email information
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
    # 2. Authentication checks
    # --------------------------------------------------

    print("\n[2] EMAIL AUTHENTICATION")
    print("-" * 60)

    authentication_results = msg.get(
        "Authentication-Results", ""
    )

    # SPF
    spf_match = re.search(
        r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        authentication_results,
        re.IGNORECASE
    )

    # DKIM
    dkim_match = re.search(
        r"\bdkim=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        authentication_results,
        re.IGNORECASE
    )

    # DMARC
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
    # 3. Received headers
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
    # 4. URL extraction
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
    # 5. Suspicious indicators
    # --------------------------------------------------

    print("\n[5] SUSPICIOUS INDICATORS")
    print("-" * 60)

    score = 0
    indicators = []

    # Authentication failures
    if spf == "FAIL":
        score += 2
        indicators.append("SPF failed")

    if dkim == "FAIL":
        score += 2
        indicators.append("DKIM failed")

    if dmarc == "FAIL":
        score += 3
        indicators.append("DMARC failed")

    # Missing authentication
    if spf == "NOT FOUND":
        score += 1
        indicators.append("SPF result not found")

    if dkim == "NOT FOUND":
        score += 1
        indicators.append("DKIM result not found")

    if dmarc == "NOT FOUND":
        score += 1
        indicators.append("DMARC result not found")

    # URL indicator
    if len(urls) > 5:
        score += 2
        indicators.append("Large number of URLs")

    # Urgency-related keywords
    urgent_words = [
        "urgent",
        "verify your account",
        "account suspended",
        "account locked",
        "confirm your account",
        "password expired",
        "click immediately"
    ]

    subject_lower = subject.lower()

    for word in urgent_words:
        if word in subject_lower:
            score += 2
            indicators.append(
                f"Urgency-related subject phrase: '{word}'"
            )

    if indicators:
        for indicator in indicators:
            print(f"- {indicator}")
    else:
        print("No major suspicious indicators detected.")

    # --------------------------------------------------
    # 6. Final classification
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
# Program entry point
# ------------------------------------------------------

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("\nUsage:")
        print("python email_analyzer.py <email_file>")
        print("\nExample:")
        print("python email_analyzer.py PLIX_LEGITIMATE_001.txt")
        sys.exit(1)

    analyze_email(sys.argv[1])