import streamlit as st
import re
from urllib.parse import urlparse

BANK_IDENTIFIERS = [
    "hdfc", "icici", "axis", "sbi", "iob", "pnb",
    "canara", "unionbank", "bankofbaroda", "kotak",
    "yesbank", "indusind", "federalbank", "idfc",
    "bandhan", "rbl", "au"
]

INDIAN_BANK_SUFFIXES = [
    ".bank.in",
    ".co.in",
    ".in"
]

ACTION_WORDS = [
    "click", "verify", "login", "update",
    "submit", "share", "confirm", "respond"
]

SENSITIVE_DATA = [
    "otp", "pin", "password", "cvv"
]

LOOKALIKE_WORDS = [
    "login", "secure", "verify", "update"
]

TRANSACTION_KEYWORDS = [
    "debited", "credited", "avl bal",
    "available balance", "rs."
]


def analyze_bank_link(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    has_bank_id = any(bank in domain for bank in BANK_IDENTIFIERS)
    has_valid_suffix = any(domain.endswith(suffix) for suffix in INDIAN_BANK_SUFFIXES)
    has_lookalike = any(word in domain for word in LOOKALIKE_WORDS)

    if has_bank_id and has_valid_suffix and not has_lookalike:
        return "trusted"
    elif has_bank_id:
        return "lookalike"
    else:
        return "unrelated"


def analyze_message(text):
    text = text.lower()
    score = 0
    reasons = []

    # --- Legitimate transaction alert override ---
    if any(k in text for k in TRANSACTION_KEYWORDS) and "http" not in text:
        return "✅ Legitimate", 10, [
            "Standard bank transaction alert",
            "No external link or credential request detected"
        ]

    # --- Link analysis ---
    urls = re.findall(r"(https?://\S+)", text)

    for url in urls:
        link_type = analyze_bank_link(url)

        if link_type == "trusted":
            score += 15
            reasons.append("Link belongs to an official Indian bank domain")
        elif link_type == "lookalike":
            score += 40
            reasons.append("Look-alike banking domain detected")
        else:
            score += 40
            reasons.append("Untrusted external link detected")

    # --- Phone call action ---
    if "call" in text and re.search(r"\d{8,}", text):
        score += 25
        reasons.append("User asked to call a number")

    # --- Action requests ---
    for word in ACTION_WORDS:
        if word in text:
            score += 20
            reasons.append(f"Action request detected: '{word}'")
            break

    # --- Sensitive data request ---
    for word in SENSITIVE_DATA:
        if word in text:
            score += 50
            reasons.append(f"Sensitive data request detected: '{word}'")
            break

    # --- Final classification ---
    if score >= 60:
        status = "🚨 Phishing (High Risk)"
    elif score >= 30:
        status = "⚠️ Suspicious"
    else:
        status = "🔒 Safe (Low Risk)"


    return status, score, reasons


# -----------------------------
#              UI
# -----------------------------

st.set_page_config(page_title="FinTech Phishing Detector", layout="centered")

st.title("🔐 FinTech Phishing Detection System By S4i1M")
st.write(
    "This system detects phishing by analyzing **risky user actions and domain structure**, "
    "not by random keywords. It supports Indian banking domains such as `.bank.in`."
)

message = st.text_area("Paste banking SMS or email here")

if st.button("Analyze"):
    if not message.strip():
        st.warning("Please enter a message.")
    else:
        status, score, reasons = analyze_message(message)

        st.subheader("Result")
        st.write(f"**Status:** {status}")
        if score >= 30:
            st.write(f"**Risk Score:** {score}/100")


        st.subheader("Explanation")
        for r in reasons:
            st.write("- " + r)
