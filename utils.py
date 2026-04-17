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
        return f"http://{url}"
    return url


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