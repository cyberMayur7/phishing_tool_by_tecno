#!/usr/bin/env python3
"""
Improved Standalone Phishing Analyzer: Advanced rule-based detection.
Enhanced for brand mimicking, random domains, path anomalies. No ML/CSV needed.
Now detects tricky phishing like fake PayPal paths on random domains.
"""

import argparse
import sys
from datetime import datetime
import random
import re
from urllib.parse import urlparse

# Optional color support
try:
    from colorama import init as colorama_init, Fore, Style
    COLORAMA_AVAILABLE = True
    init = colorama_init
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    BOLD = Style.BRIGHT
    RESET = Style.RESET_ALL
except ImportError:
    COLORAMA_AVAILABLE = False
    GREEN = YELLOW = RED = CYAN = MAGENTA = BOLD = RESET = ""

# Jokes for fun
JOKES = [
    "Why did the computer get cold? Because it left its Windows open! 😅",
    "I told my password a joke — now it cracks up every time. 😂",
    "Why do hackers wear glasses? To improve their web-sight. 😎",
    "Keyboard not found? Press F1 to continue... (just kidding) 🤪",
]

ASCII_ART = r'''
 _______ _______ _______ _     _  ______ 
|__   __|__   __|__   __| |   | |/ _____|
   | |     | |     | |  | |___| | (____  
   | |     | |     | |  |  ___  |\___ \ 
   | |     | |     | |  | |   | |____) |
   |_|     |_|     |_|  |_|   |_|______/
                                           
            Phisher-Analyzer — TECNO
'''

def print_colored(text, color=""):
    if COLORAMA_AVAILABLE:
        print(f"{color}{BOLD}{text}{RESET}")
    else:
        print(f"{text}")

def is_likely_email(s: str) -> bool:
    s = s.strip().lower()
    if '@' in s and '.' in s and len(s) > 5:
        return True
    return False

def analyze_url(url: str) -> tuple[int, float, list[str]]:
    reasons = []
    score = 0.0
    parsed = urlparse(url.lower())
    netloc = parsed.netloc or url
    path_query = (parsed.path or '') + (parsed.query or '')

    # 1. Protocol check
    if not url.startswith('https://'):
        score += 0.15
        reasons.append("- No HTTPS: Insecure — easy for attackers to intercept data.")

    # 2. IP address
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    if re.search(ip_pattern, url):
        score += 0.4
        reasons.append("- IP address: Legit sites rarely use IPs; hides malicious server.")

    # 3. @ symbol
    if '@' in url:
        score += 0.3
        reasons.append("- '@' in URL: Tricks browser to send credentials to fake site.")

    # 4. Length & complexity
    if len(url) > 80:
        score += 0.15
        reasons.append("- Very long URL: Often hides malicious intent with junk params.")
    if len(path_query) > 40:
        score += 0.15
        reasons.append("- Long path/query: May encode payloads or confuse users.")

    # 5. Suspicious keywords in path/query
    suspicious_keywords = ['login', 'verify', 'update', 'account', 'bank', 'paypal', 'secure-', 'free', 'claim', 'password', 'billing', 'customer']
    found_keywords = [kw for kw in suspicious_keywords if kw in path_query.lower()]
    if found_keywords:
        score += 0.25 * min(len(found_keywords), 3) / 3
        reasons.append(f"- Suspicious keywords in path: {', '.join(found_keywords)} (phishing bait).")

    # 6. Subdomain abuse
    subdomains = len(netloc.split('.')) - 2 if '.' in netloc else 0
    if subdomains > 1:
        score += 0.2
        reasons.append(f"- Excessive subdomains ({subdomains}): Mimics legit sites (e.g., secure.paypal.fake.com).")

    # 7. Brand mimicking
    known_brands = ['paypal', 'bank', 'amazon', 'google', 'facebook', 'netflix', 'irs', 'microsoft']
    path_brands = [b for b in known_brands if b in path_query.lower()]
    domain_brands = [b for b in known_brands if b in netloc.lower()]
    if path_brands and not domain_brands:
        score += 0.35
        reasons.append(f"- Brand mismatch: '{path_brands[0]}' in path but domain '{netloc}' doesn't match (fake mimicry).")

    # 8. Random/gibberish domain
    domain_name = netloc.split('.')[0] if '.' in netloc else netloc
    if len(domain_name) < 4 or len(domain_name) > 15:
        score += 0.2
        reasons.append(f"- Suspicious domain length: '{domain_name}' too short/long (random-generated?).")
    vowels = sum(1 for c in domain_name if c in 'aeiou')
    if len(domain_name) > 0 and vowels / len(domain_name) < 0.3:
        score += 0.25
        reasons.append(f"- Gibberish domain: '{domain_name}' has low real-word patterns (likely auto-generated phishing).")
    misspells = {'paypal': ['paypall', 'pay-pal', 'ppal'], 'google': ['g00gle', 'goog1e']}
    for brand, vars in misspells.items():
        if any(var in netloc for var in vars):
            score += 0.3
            reasons.append(f"- Domain misspelling: Mimics '{brand}' with typos (common phishing tactic).")

    # 9. Unusual path structure
    if '/' in path_query and any(tld in path_query for tld in ['.com', '.co.uk', '.net']):
        score += 0.25
        reasons.append("- Domain-like string in path: Hides real destination (e.g., paypal.co.uk inside fake path).")
    if 'cgi-bin' in path_query or '.php' in path_query:
        score += 0.2
        reasons.append("- CGI-bin or .php in path: Often used in malicious loading scripts.")

    # 10. Special characters
    if re.search(r'[\$#@!%]{2,}', url):
        score += 0.15
        reasons.append("- Unusual special chars: Obfuscation to evade detection.")

    # 11. Known legit domains reduce score
    legit_domains = ['google.com', 'amazon.com', 'facebook.com', 'paypal.com', 'youtube.com']
    if any(domain in netloc for domain in legit_domains):
        score -= 0.25
        reasons.append(f"+ Matches legit domain: '{netloc}' appears safe.")

    score = max(0.0, min(1.0, score))
    is_phish = 1 if score > 0.4 else 0
    confidence = score * 100

    return is_phish, confidence, reasons

def analyze_email(email_text: str) -> tuple[int, float, list[str]]:
    reasons = []
    score = 0.0
    text_lower = email_text.lower()

    suspicious_keywords = ['urgent', 'immediate', 'verify account', 'update payment', 'click here', 'win prize', 'free money', 'claim now']
    found_keywords = [kw for kw in suspicious_keywords if kw in text_lower]
    if found_keywords:
        score += 0.3 * min(len(found_keywords), 3) / 3
        reasons.append(f"- Suspicious keywords: {', '.join(found_keywords)} (urgency bait).")

    link_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\$\\$,]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    links = re.findall(link_pattern, email_text)
    if links:
        score += 0.15 * min(len(links), 2)
        reasons.append(f"- Embedded links ({len(links)}): Risky if unsolicited.")

    if '@' in email_text:
        sender_parts = re.findall(r'[\w\.-]+@[\w\.-]+', email_text)
        if sender_parts:
            sender = sender_parts[0].lower()
            if any(susp in sender for susp in ['free', 'win', 'claim', 'update']):
                score += 0.15
                reasons.append(f"- Suspicious sender: {sender} (fake domain).")
            legit_senders = ['@gmail.com', '@company.com']
            if any(ls in sender for ls in legit_senders):
                score -= 0.1
                reasons.append("+ Legit sender: Lower risk.")

    if len(email_text.strip()) < 50:
        score += 0.1
        reasons.append("- Short message: Typical spam/phish style.")

    if re.search(r'[\$#@!]{2,}', email_text):
        score += 0.2
        reasons.append("- Unusual chars: Fake/obfuscated input.")

    score = max(0.0, min(1.0, score))
    is_phish = 1 if score > 0.5 else 0
    confidence = score * 100

    return is_phish, confidence, reasons

def display_result(input_type: str, input_val: str, is_phish: int, confidence: float, reasons: list, use_color=True):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    border = '+' + '-' * 60 + '+'
    print_colored(border, "" if not use_color else "")

    status = "PHISHING DETECTED ⚠️" if is_phish else "Looks Legit ✅"
    status_color = RED if is_phish else GREEN
    print_colored(f'| Time: {now:<48}|', "" if not use_color else "")
    print_colored(f'| Input type: {input_type:<44}|', "" if not use_color else "")
    print_colored(border, "" if not use_color else "")
    print_colored(f'| Result: {status:<52}|', status_color if use_color else "")
    print_colored(f'| Confidence: {confidence:.1f}%{" " * (52 - len(f"{confidence:.1f}%"))}|', YELLOW if use_color else "")
    print_colored(border, "" if not use_color else "")

    print_colored("\nDetailed Analysis:", CYAN if use_color else "")
    for reason in reasons:
        print_colored(f"• {reason}", "" if not use_color else "")

    print_colored(border + "\n", "" if not use_color else "")
    tip = "Tip: Always hover over links to check real URL, and use official apps for verification. 🔎"
    print_colored(tip, MAGENTA if use_color else "")

def interactive_mode(use_color=True, jokes=True, hacker=False, no_ascii=False):
    if hacker and not no_ascii:
        print_colored(ASCII_ART, MAGENTA if use_color else "")
    print_colored("Welcome bhai! Enter a URL or email to analyze. Type 'exit' to quit.\n", CYAN if use_color else "")

    while True:
        try:
            inp = input((YELLOW + "[input] > " + RESET if use_color else "[input] > ")).strip()
        except (EOFError, KeyboardInterrupt):
            print_colored("\nBye bhai 👋", GREEN if use_color else "")
            break
        if not inp or inp.lower() in ('exit', 'quit'):
            print_colored("Bye bhai 👋", GREEN if use_color else "")
            break

        input_type = "EMAIL" if is_likely_email(inp) else "URL"
        if input_type == "URL":
            is_phish, conf, reasons = analyze_url(inp)
        else:
            is_phish, conf, reasons = analyze_email(inp)

        display_result(input_type, inp, is_phish, conf, reasons, use_color)

        if jokes and random.random() < 0.35:
            print_colored(random.choice(JOKES), CYAN if use_color else "")

def demo_mode(use_color=True, hacker=False, no_ascii=False):
    if hacker and not no_ascii:
        print_colored(ASCII_ART, MAGENTA if use_color else "")
    print_colored("Demo mode — analyzing sample inputs...\n", CYAN if use_color else "")

    samples = [
        ("URL", "https://www.google.com"),
        ("URL", "http://192.168.1.1/login"),
        ("EMAIL", "noreply@company.com: Order confirmed."),
        ("EMAIL", "Urgent: Click http://fakebank.com/verify now!"),
        ("URL", "www.dghjdgf.com/paypal.co.uk/cycgi-bin/webscrcmd=_home-customer&nav=1/loading.php")
    ]

    for inp_type, sample in samples:
        if inp_type == "URL":
            is_phish, conf, reasons = analyze_url(sample)
        else:
            is_phish, conf, reasons = analyze_email(sample)
        display_result(inp_type, sample, is_phish, conf, reasons, use_color)

    print_colored("Demo finished. Run without --demo for interactive mode.", GREEN if use_color else "")

def main():
    parser = argparse.ArgumentParser(description="Improved Phishing Analyzer — Advanced detection.")
    parser.add_argument('--url', help='Analyze a single URL')
    parser.add_argument('--email', help='Analyze a single email text')
    parser.add_argument('--hacker', action='store_true', help='Hacker-style UI (ASCII art)')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')
    parser.add_argument('--no-jokes', action='store_true', help='Disable jokes')
    parser.add_argument('--no-ascii', action='store_true', help='Disable ASCII art')
    parser.add_argument('--demo', action='store_true', help='Run quick demo with samples')
    return parser.parse_args()

if __name__ == "__main__":
    args = main()
    use_color = COLORAMA_AVAILABLE and not args.no_color
    jokes = not args.no_jokes
    hacker = args.hacker
    no_ascii = args.no_ascii

    if use_color:
        colorama_init()

    if args.demo:
        demo_mode(use_color, hacker, no_ascii)
    elif args.url:
        is_phish, conf, reasons = analyze_url(args.url)
        if hacker and not no_ascii:
            print_colored(ASCII_ART, MAGENTA)
        display_result("URL", args.url, is_phish, conf, reasons, use_color)
    elif args.email:
        is_phish, conf, reasons = analyze_email(args.email)
        if hacker and not no_ascii:
            print_colored(ASCII_ART, MAGENTA)
        display_result("EMAIL", args.email, is_phish, conf, reasons, use_color)
    else:
        interactive_mode(use_color, jokes, hacker, no_ascii)