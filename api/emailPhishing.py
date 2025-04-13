from __future__ import annotations
import streamlit as st
from bs4 import BeautifulSoup
import tldextract, re, ssl, socket, requests, email
from email.header import decode_header
from datetime import datetime

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

def analyze_email_headers(email_content: str):
    try:
        msg = email.message_from_string(email_content)
        headers = []

        for header in ["From", "To", "Subject", "Date", "Return-Path", "Received"]:
            if header in msg:
                value = msg[header]
                if isinstance(value, str):
                    value = decode_header(value)[0][0]
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", errors="ignore")

                status, reason = "safe", ""
                if header == "From":
                    if "@" not in value:
                        status, reason = "suspicious", "Invalid email format"
                    elif "noreply" in value.lower():
                        status, reason = "suspicious", "No‑reply address"

                headers.append({"name": header, "value": value, "status": status, "reason": reason})
        return headers
    except Exception as e:
        st.error(f"Header analysis failed: {e}")
        return []


def analyze_links(email_content: str):
    try:
        soup = BeautifulSoup(email_content, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            url, status, reason = a["href"], "safe", ""
            if not url.startswith(("http://", "https://")):
                status, reason = "suspicious", "Non‑HTTP/HTTPS link"
            elif any(s in url for s in ("bit.ly", "tinyurl.com")):
                status, reason = "suspicious", "URL shortener detected"
            elif "@" in url:
                status, reason = "suspicious", "Email address in URL"
            links.append({"url": url, "status": status, "reason": reason})
        return links
    except Exception as e:
        st.error(f"Link analysis failed: {e}")
        return []


def check_ssl(domain: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return "Valid"
    except Exception:
        return "Invalid"


def check_blacklist(domain: str):
    return "Unknown"


def analyze_domain(domain: str):
    try:
        if not WHOIS_AVAILABLE:
            return {"age": "Unknown", "ssl_status": check_ssl(domain), "blacklist_status": check_blacklist(domain)}

        info = whois.whois(domain)
        creation = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date
        age_years = (datetime.now() - creation).days // 365 if creation else "Unknown"
        return {"age": f"{age_years} years", "ssl_status": check_ssl(domain), "blacklist_status": check_blacklist(domain)}
    except Exception:
        return {"age": "Unknown", "ssl_status": check_ssl(domain), "blacklist_status": check_blacklist(domain)}


def analyze_attachments(email_content: str):
    try:
        msg = email.message_from_string(email_content)
        attachments = []
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get("Content-Disposition") is None:
                continue
            filename = part.get_filename()
            if filename:
                status, reason = "safe", ""
                if filename.lower().endswith((".exe", ".bat", ".cmd", ".msi", ".dll")):
                    status, reason = "phishing", "Executable detected"
                elif filename.lower().endswith((".zip", ".rar", ".7z")):
                    status, reason = "suspicious", "Archive detected"
                attachments.append({"name": filename, "type": "file", "status": status, "reason": reason})
        return attachments
    except Exception as e:
        st.error(f"Attachment analysis failed: {e}")
        return []


def analyze_language_patterns(email_content: str):
    risk = []
    urgency = ["urgent", "immediately", "asap", "right away", "hurry"]
    if any(p in email_content.lower() for p in urgency):
        risk.append({"title": "Urgency", "description": "Contains urgent wording", "severity": "medium"})
    threats = ["account suspended", "security alert", "verify your account", "password expired"]
    if any(p in email_content.lower() for p in threats):
        risk.append({"title": "Threat language", "description": "Threatening wording", "severity": "high"})
    if len(re.findall(r"\b[a-z]{2,}\b", email_content.lower())) > 100:
        risk.append({"title": "Poor grammar", "description": "Multiple grammar issues", "severity": "low"})
    return risk


def generate_recommendations(results: dict):
    recs = []
    if any(l["status"] == "suspicious" for l in results["links"]):
        recs.append({"title": "Suspicious links", "description": "Avoid clicking links; verify sender."})
    if any(a["status"] == "phishing" for a in results["attachments"]):
        recs.append({"title": "Dangerous attachment", "description": "Do not open executable attachments."})
    if any(h["status"] == "suspicious" for h in results["headers"]):
        recs.append({"title": "Suspicious headers", "description": "Headers suggest possible spoofing."})
    if results["domain_info"]["age"] == "Unknown":
        recs.append({"title": "Unknown domain", "description": "Sender domain could not be verified."})
    return recs


def run_analysis(email_content: str) -> dict:
    domain = None
    for line in email_content.splitlines():
        if line.lower().startswith("from:"):
            m = re.search(r"[\w\.-]+@[\w\.-]+", line)
            if m:
                domain = tldextract.extract(m.group()).domain
            break

    headers = analyze_email_headers(email_content)
    links = analyze_links(email_content)
    domain_info = analyze_domain(domain) if domain else {"age": "Unknown", "ssl_status": "Unknown", "blacklist_status": "Unknown"}
    attachments = analyze_attachments(email_content)
    risk_factors = analyze_language_patterns(email_content)

    score = 0.0
    if links:
        score += sum(1 for l in links if l["status"] == "safe") / len(links) * 0.3
    if headers:
        score += sum(1 for h in headers if h["status"] == "safe") / len(headers) * 0.3
    if attachments:
        score += sum(1 for a in attachments if a["status"] == "safe") / len(attachments) * 0.2
    if risk_factors:
        score += sum(0.5 for f in risk_factors if f["severity"] == "low") / len(risk_factors) * 0.2

    verdict, threat = ("Safe", "low") if score >= 0.8 else ("Suspicious", "medium") if score >= 0.5 else ("Phishing", "high")

    return {
        "verdict": verdict,
        "threatLevel": threat,
        "score": score,
        "threatScore": 1 - score,
        "domain_info": domain_info,
        "links": links,
        "headers": headers,
        "attachments": attachments,
        "riskFactors": risk_factors,
        "recommendations": generate_recommendations(
            {"links": links, "headers": headers, "attachments": attachments, "domain_info": domain_info}
        ),
    }


def phishing_tab():
    st.subheader("🎣 Email‑Phishing Analyzer")

    uploaded = st.file_uploader("Upload .eml / raw email file", type=["eml", "txt"])
    raw_text = st.text_area("…or paste raw email content", height=200)

    if st.button("Analyze email", type="primary"):
        if uploaded:
            content = uploaded.read().decode("utf-8", errors="ignore")
        else:
            content = raw_text

        if not content.strip():
            st.warning("Please provide email content.")
            st.stop()

        with st.spinner("Running analysis…"):
            result = run_analysis(content)

        col1, col2, col3 = st.columns(3)
        col1.metric("Verdict", result["verdict"])
        col2.metric("Threat level", result["threatLevel"])
        col3.metric("Confidence (0‑1)", f"{result['score']:.2f}")

        st.markdown("---")
        st.markdown("#### 🖹 Email preview")
        st.code(content[:500] + ("…" if len(content) > 500 else ""), language="eml")

        with st.expander("🔗 Links found"):
            for l in result["links"]:
                st.write(f"- **{l['url']}**  →  {l['status']} ({l['reason']})")

        with st.expander("📑 Headers"):
            for h in result["headers"]:
                st.write(f"- **{h['name']}**: {h['value']}  →  {h['status']} ({h['reason']})")

        with st.expander("📎 Attachments"):
            for a in result["attachments"]:
                st.write(f"- **{a['name']}**  →  {a['status']} ({a['reason']})")

        if result["riskFactors"]:
            st.markdown("#### ⚠️ Risk factors")
            for r in result["riskFactors"]:
                st.write(f"- **{r['title']}** ({r['severity']}): {r['description']}")

        if result["recommendations"]:
            st.markdown("#### ✅ Recommendations")
            for r in result["recommendations"]:
                st.write(f"- **{r['title']}**: {r['description']}")
