# src/features.py
import re
from urllib.parse import urlparse

def extract_url_features(url: str) -> dict:
    """Return simple numeric features for a URL (used by ML)."""
    if not url:
        return {}
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    has_https = int(parsed.scheme == "https")
    length = len(url)
    num_dots = hostname.count(".")
    has_ip = int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname)))
    digit_ratio = sum(c.isdigit() for c in url) / max(1, len(url))
    suspicious_tokens = sum(1 for t in ["login","secure","account","update","verify"] if t in url.lower())
    return {
        "has_https": has_https,
        "length": length,
        "num_dots": num_dots,
        "has_ip": has_ip,
        "digit_ratio": digit_ratio,
        "suspicious_tokens": suspicious_tokens,
        "path_len": len(path),
    }
