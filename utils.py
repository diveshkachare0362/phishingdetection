import re
from urllib.parse import urlparse

import tldextract

FEATURE_COLUMNS = [
    "url_length",
    "digit_to_letter_ratio",
    "count_at",
    "count_qmark",
    "count_hyphen",
    "count_equal",
    "has_ip_address",
    "has_punycode",
    "has_https",
    "subdomain_count",
    "dot_depth",
]

IPV4_PATTERN = re.compile(
    r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
    r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
)


def _normalize_url(url: str) -> str:
    url = str(url).strip()
    if not url:
        return ""
    if "://" not in url:
        # Default to https so legitimate sites aren't penalised for omitting scheme
        return f"https://{url}"
    return url


def validate_url(url: str):
    raw = str(url or "").strip()
    if not raw:
        return False, "No URL provided."
    if raw.startswith("http:/") and not raw.startswith("http://"):
        return False, "Only one slash after http: instead of //."
    if raw.startswith("https:/") and not raw.startswith("https://"):
        return False, "Only one slash after https: instead of //."
    if not raw.startswith(("http://", "https://")):
        return False, "No http:// or https:// at the start."
    if " " in raw:
        return False, "Spaces are not allowed (should be encoded as %20)."
    if any(ch in raw for ch in "<>\"{}|\\^`"):
        return False, "Invalid characters are not allowed in URLs."

    parsed = urlparse(raw)
    if not parsed.netloc:
        return False, "No domain name provided."

    host = parsed.netloc
    if ":" in host:
        port = host.split(":", 1)[1].split("/")[0]
        if port and not port.isdigit():
            return False, "Port must be a number (e.g., :443)."

    if raw.endswith("&") or raw.endswith("?"):
        return False, "Ends with dangling & (incomplete parameter)."

    return True, ""


def extract_features(url: str):
    normalized_url = _normalize_url(url)
    try:
        parsed = urlparse(normalized_url)
    except ValueError:
        # Some poisoned URLs include malformed IPv6 brackets; strip them for parsing.
        cleaned = normalized_url.replace("[", "").replace("]", "")
        parsed = urlparse(cleaned)
        normalized_url = cleaned
    host = parsed.netloc.lower()
    path_query = f"{parsed.path}{parsed.params}{parsed.query}{parsed.fragment}".lower()
    raw = normalized_url.lower()

    digit_count = sum(ch.isdigit() for ch in raw)
    letter_count = sum(ch.isalpha() for ch in raw)
    ratio = digit_count / max(letter_count, 1)

    extracted_domain = tldextract.extract(normalized_url)
    subdomain_count = len([x for x in extracted_domain.subdomain.split(".") if x])
    dot_depth = normalized_url.count(".")

    feature_dict = {
        "url_length": len(normalized_url),
        "digit_to_letter_ratio": float(ratio),
        "count_at": normalized_url.count("@"),
        "count_qmark": normalized_url.count("?"),
        "count_hyphen": normalized_url.count("-"),
        "count_equal": normalized_url.count("="),
        "has_ip_address": int(bool(IPV4_PATTERN.search(host))),
        "has_punycode": int("xn--" in host or "xn--" in path_query),
        "has_https": int(parsed.scheme.lower() == "https"),
        "subdomain_count": subdomain_count,
        "dot_depth": dot_depth,
    }

    feature_list = [feature_dict[col] for col in FEATURE_COLUMNS]
    return feature_list, feature_dict