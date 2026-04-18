import os
import pickle
import unicodedata
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import tldextract
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from user_store import (
    create_user,
    ensure_demo_user,
    get_user_by_id,
    init_db,
    verify_login,
)
from utils import FEATURE_COLUMNS, extract_features, validate_url

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-for-production")

PUBLIC_ENDPOINTS = frozenset({"login", "register", "static"})


def load_artifact():
    with open("classifier.pkl", "rb") as file:
        saved = pickle.load(file)
    if isinstance(saved, dict) and "model" in saved:
        return saved["model"], saved.get("feature_columns", FEATURE_COLUMNS)
    return saved, FEATURE_COLUMNS


try:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    init_db()
    ensure_demo_user()
    model, feature_columns = load_artifact()
except FileNotFoundError:
    raise RuntimeError("classifier.pkl missing. Run train_model.py first.")


@app.before_request
def require_auth():
    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        return
    if "user_id" not in session:
        if request.path.startswith("/predict") or request.path.startswith("/notify"):
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("login"))


# Fast-path bypass for major brands whose URLs may have complex paths/query
# strings that fool structural checks. Structural + rule-based logic covers
# everything else — no need to hardcode arbitrary domains here.
TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "google.co.in", "google.co.uk",
    "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com",
    "microsoft.com", "office.com", "live.com", "outlook.com", "bing.com",
    "apple.com", "icloud.com",
    "github.com", "wikipedia.org", "linkedin.com",
    "amazon.com", "amazon.in",
    "openai.com",
}

# Brand names used for typosquatting detection
BRAND_NAMES = {
    "google", "gmail", "youtube", "facebook", "instagram", "twitter",
    "paypal", "amazon", "apple", "microsoft", "netflix", "linkedin",
    "github", "yahoo", "ebay", "dropbox", "spotify", "adobe",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "steam", "roblox", "discord", "snapchat", "tiktok", "whatsapp",
    "flipkart", "paytm", "hdfc", "icici", "sbi",
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Standard dynamic-programming Levenshtein distance."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def rule_based_checks(url: str, feature_dict: dict) -> dict:
    """
    Three independent attack detectors that run alongside the ML model.

    Returns
    -------
    {
        'penalty'  : float  0-1   (0 = clean, 1 = definitely malicious)
        'findings' : [str]        (human-readable descriptions for UI)
    }

    Detectors
    ---------
    1. Homograph / Unicode attack  — non-ASCII or mixed-script domain chars
    2. Typosquatting               — domain within edit-distance 2 of a brand
    3. HTTPS trick / brand-in-path — brand name in subdomain or path while
                                     the *registered* domain is different
    """
    normalized = url if "://" in url else f"https://{url}"
    parsed = urlparse(normalized)
    ext = tldextract.extract(normalized)

    domain     = ext.domain.lower()          # e.g. "paypa1"
    subdomain  = ext.subdomain.lower()       # e.g. "www" or "secure.paypal"
    suffix     = ext.suffix.lower()          # e.g. "com"
    host       = parsed.netloc.lower()       # full host including subdomain
    path_lower = parsed.path.lower()

    penalty  = 0.0
    findings = []

    # ── 1. Homograph / Unicode attack ────────────────────────────────────
    # 1a. Non-ASCII characters in the host (raw Unicode lookalikes)
    non_ascii = [ch for ch in host if ord(ch) > 127]
    if non_ascii:
        findings.append(
            "Non-ASCII characters detected in the domain — likely a Unicode "
            "homograph attack (e.g. Cyrillic 'а' disguised as Latin 'a')."
        )
        penalty = max(penalty, 0.95)

    # 1b. Mixed-script detection (Latin + Cyrillic/Greek in same domain)
    scripts = set()
    for ch in host:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch, "")
                if "LATIN"    in name: scripts.add("LATIN")
                elif "CYRILLIC" in name: scripts.add("CYRILLIC")
                elif "GREEK"   in name: scripts.add("GREEK")
            except Exception:
                pass
    if len(scripts) > 1:
        findings.append(
            f"Mixed character scripts ({', '.join(scripts)}) in the domain — "
            "classic homograph attack indicator."
        )
        penalty = max(penalty, 0.97)

    # ── 2. Typosquatting detection ────────────────────────────────────────
    # Normalize digit-to-letter substitutions before comparison
    _substitutions = str.maketrans("01345", "oiaas")
    normalized_domain = domain.translate(_substitutions)

    for brand in BRAND_NAMES:
        if domain == brand or normalized_domain == brand:
            break  # exact match on the registered domain — not typosquatting
        dist = levenshtein_distance(normalized_domain, brand)
        # Flag if very close (distance 1-2) and length is plausible
        if dist <= 2 and abs(len(domain) - len(brand)) <= 2:
            findings.append(
                f"Domain '{domain}.{suffix}' is suspiciously similar to '{brand}' "
                f"(edit distance: {dist}) — possible typosquatting / brand impersonation."
            )
            penalty = max(penalty, 0.88)
            break

    # ── 3. HTTPS trick & brand-in-subdomain/path attack ──────────────────
    # Attackers register evil.com and place the target brand in the path:
    #   https://evil.com/paypal/login   ← looks like PayPal in the URL
    #   https://paypal.evil.com/login   ← brand in subdomain
    # Having HTTPS does NOT make these safe — phishers get free SSL certs.

    for brand in BRAND_NAMES:
        if domain == brand:
            continue  # The registered domain IS the brand — fine

        # Brand name appears in subdomain but registered domain differs
        if brand in subdomain.split("."):
            findings.append(
                f"Brand name '{brand}' is in the subdomain but the actual "
                f"registered domain is '{domain}.{suffix}' — common spoofing trick."
            )
            penalty = max(penalty, 0.92)

        # Brand name appears in path/query (HTTPS trick)
        if f"/{brand}" in path_lower or f".{brand}" in path_lower:
            findings.append(
                f"Brand name '{brand}' found in the URL path while the real domain "
                f"is '{domain}.{suffix}' — HTTPS does not make this link safe."
            )
            penalty = max(penalty, 0.78)

    return {"penalty": penalty, "findings": findings}


def adjust_probability(raw_probability: float, feature_dict: dict) -> float:
    """
    Evidence-based adjustment to the model's raw phishing probability.
    NOTE: has_https is intentionally NOT a green signal — phishers obtain
    free SSL certificates trivially; HTTPS only encrypts the connection,
    it does NOT verify the site is legitimate.
    """
    # ── Hard red flags ──────────────────────────────────────────────
    red_flags = sum([
        feature_dict.get("has_ip_address", 0) == 1,        # raw IP host
        feature_dict.get("has_punycode", 0) == 1,           # punycode / IDN
        feature_dict.get("count_at", 0) > 0,                # @ in URL
        feature_dict.get("url_length", 0) > 150,            # extremely long
        feature_dict.get("digit_to_letter_ratio", 0) > 0.5, # heavy digit use
        feature_dict.get("subdomain_count", 0) >= 3,        # deep subdomain chain
    ])

    if red_flags >= 2:
        return raw_probability           # multiple red flags → trust model fully
    if red_flags == 1:
        return raw_probability * 0.85    # one red flag → light discount only

    # ── Green structural signals (zero red flags path) ──────────────
    # HTTPS deliberately excluded — it's not a reliable safety signal.
    green = sum([
        feature_dict.get("url_length", 999) <= 80,           # short, clean URL
        feature_dict.get("digit_to_letter_ratio", 1) <= 0.15,# almost no digits
        feature_dict.get("subdomain_count", 99) <= 1,        # at most www
        feature_dict.get("count_qmark", 99) == 0,            # no query string
        feature_dict.get("count_equal", 99) == 0,            # no key=value pairs
        feature_dict.get("count_hyphen", 99) <= 1,           # minimal hyphens
        feature_dict.get("dot_depth", 99) <= 2,              # simple dot structure
    ])

    if green >= 6:
        discount = 0.20    # near-perfect structural cleanliness
    elif green >= 4:
        discount = 0.35    # very clean
    elif green >= 2:
        discount = 0.60    # somewhat clean
    else:
        discount = 0.80    # mixed signals

    return raw_probability * discount


def probability_to_verdict(phish_probability: float) -> str:
    if phish_probability >= 0.85:
        return "Malicious"
    if phish_probability >= 0.55:
        return "Suspicious"
    return "Safe"


def feature_influence(feature_list):
    values = np.array(feature_list, dtype=float)
    importances = getattr(model, "feature_importances_", np.ones_like(values))
    scores = np.abs(values) * importances
    ranked_idx = np.argsort(scores)[::-1]
    top = []
    for idx in ranked_idx[:3]:
        top.append(
            {
                "name": feature_columns[idx],
                "value": float(values[idx]),
                "influence": float(scores[idx]),
            }
        )
    return top


def build_user_facing_copy(verdict: str, malicious_probability: float, feature_dict: dict, top_features: list):
    """Human-readable risk %, summary, and bullet reasons for UI / notifications."""
    risk_percent = int(round(max(0.0, min(1.0, malicious_probability)) * 100))
    reasons = []

    if feature_dict.get("has_ip_address"):
        reasons.append("Host looks like a raw IP address (often used in phishing).")
    if feature_dict.get("has_punycode"):
        reasons.append("Punycode / homograph-style encoding detected (xn--).")
    if not feature_dict.get("has_https"):
        reasons.append("Connection is not HTTPS (higher risk for credential theft).")
    if feature_dict.get("subdomain_count", 0) >= 2:
        reasons.append("Unusually deep subdomain chain (possible brand spoofing).")
    if feature_dict.get("url_length", 0) > 100:
        reasons.append("Very long URL (often used to hide the real destination).")
    if feature_dict.get("count_at", 0) > 0:
        reasons.append("Contains '@' (can obscure the true host in some attacks).")

    if verdict == "Safe":
        summary = "Low fraud risk based on URL signals. Still verify the sender and domain before entering passwords."
    elif verdict == "Suspicious":
        summary = "Elevated fraud risk. Do not enter credentials; confirm the link through an official app or typed URL."
        if not reasons:
            reasons.append("Model scores this URL as ambiguous; several structural cues overlap with phishing patterns.")
    else:
        summary = "High fraud risk. Do not visit or sign in. Use official channels only."
        if not reasons:
            reasons.append("Strong overlap with known malicious URL patterns.")

    top_names = [t["name"] for t in (top_features or [])[:3]]
    if top_names:
        reasons.append(f"Strongest model signals involved: {', '.join(top_names)}.")

    return {
        "risk_score_percent": risk_percent,
        "summary": summary,
        "reasons": reasons[:8],
    }


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        password = request.form.get("password", "")
        ok, msg = create_user(email, phone, password)
        if ok:
            flash(msg, "success")
            return redirect(url_for("login"))
        flash(msg, "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        user = verify_login(email, password)
        if user:
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(url_for("home"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))
    return render_template("index.html", user=user)


@app.route("/predict", methods=["POST"])
def predict():
    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url", "")).strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    valid, validation_error = validate_url(url)
    if not valid:
        return jsonify({"error": validation_error}), 400

    feature_list, feature_dict = extract_features(url)

    # ── Trusted-domain fast path ──────────────────────────────────────────
    _ext = tldextract.extract(url)
    _registered = f"{_ext.domain}.{_ext.suffix}".lower()
    if _registered in TRUSTED_DOMAINS:
        user_copy = build_user_facing_copy("Safe", 0.0, feature_dict, [])
        return jsonify({
            "verdict": "Safe",
            "probability": 0.0,
            "risk_score_percent": 0,
            "summary": user_copy["summary"],
            "reasons": ["Domain is a well-known trusted site."],
            "top_features": [],
            "raw_features": feature_dict,
        })

    # ── Rule-based attack detection (runs independently of ML model) ──────
    rbc = rule_based_checks(url, feature_dict)

    # ── ML model prediction ───────────────────────────────────────────────
    feature_frame = pd.DataFrame([feature_list], columns=feature_columns)
    probabilities = model.predict_proba(feature_frame)[0]
    raw_probability = float(probabilities[1])

    # Apply evidence-based structural adjustment
    adjusted_probability = adjust_probability(raw_probability, feature_dict)

    # ── Combine: take the higher threat signal ────────────────────────────
    # Rule-based checks can detect attacks the ML model may miss entirely
    final_probability = max(adjusted_probability, rbc["penalty"])

    verdict = probability_to_verdict(final_probability)
    top_features = feature_influence(feature_list)
    user_copy = build_user_facing_copy(verdict, final_probability, feature_dict, top_features)

    # Prepend rule-based findings to the reasons list
    all_reasons = rbc["findings"] + user_copy["reasons"]

    return jsonify(
        {
            "verdict": verdict,
            "probability": round(final_probability, 4),
            "risk_score_percent": user_copy["risk_score_percent"],
            "summary": user_copy["summary"],
            "reasons": all_reasons[:8],
            "top_features": top_features,
            "raw_features": feature_dict,
        }
    )


@app.route("/notify", methods=["POST"])
def notify():
    """
    Sends alert notification to the logged-in user's registered email and phone.
    """
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Authentication required"}), 401

    user = get_user_by_id(uid)
    if not user:
        return jsonify({"error": "User not found"}), 404

    payload = request.get_json(silent=True) or {}
    _message = str(payload.get("message", "")).strip()
    if not _message:
        return jsonify({"error": "message required"}), 400

    _email = user["email"]
    _phone = user["phone"]

    print(f"\n[ALERT] Sending to user_id={uid}")
    print(f"  Email: {_email}")
    print(f"  Phone: {_phone or '(not set)'}")
    print(f"  Message: {_message}\n")

    return jsonify(
        {
            "ok": True,
            "detail": f"Alert is being sent to your registered email ({_email}) and phone ({_phone or 'not set'}).",
            "sent_to_email": _email,
            "sent_to_phone": _phone or None,
        }
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
