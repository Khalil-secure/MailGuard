import httpx
import os
import base64
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

HEADERS_VT = {"x-apikey": VIRUSTOTAL_API_KEY}

# ── VirusTotal ────────────────────────────────────────────────────

async def check_url_virustotal(url: str) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(endpoint, headers=HEADERS_VT)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return {
                "source": "virustotal",
                "target": url,
                "malicious": malicious,
                "suspicious": suspicious,
                "verdict": "PHISHING" if malicious > 0 else "SUSPICIOUS" if suspicious > 0 else "SAFE"
            }
    except Exception as e:
        logger.error(f"VirusTotal URL check failed: {e}")
    return {"source": "virustotal", "target": url, "verdict": "UNKNOWN"}

async def check_domain_virustotal(domain: str) -> dict:
    endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(endpoint, headers=HEADERS_VT)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return {
                "source": "virustotal",
                "target": domain,
                "malicious": malicious,
                "suspicious": suspicious,
                "verdict": "PHISHING" if malicious > 0 else "SUSPICIOUS" if suspicious > 0 else "SAFE"
            }
    except Exception as e:
        logger.error(f"VirusTotal domain check failed: {e}")
    return {"source": "virustotal", "target": domain, "verdict": "UNKNOWN"}

# ── AbuseIPDB ─────────────────────────────────────────────────────

async def check_ip_abuseipdb(ip: str) -> dict:
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(endpoint, headers=headers, params=params)
        if r.status_code == 200:
            data = r.json()["data"]
            score = data.get("abuseConfidenceScore", 0)
            return {
                "source": "abuseipdb",
                "target": ip,
                "abuse_score": score,
                "verdict": "PHISHING" if score > 80 else "SUSPICIOUS" if score > 30 else "SAFE"
            }
    except Exception as e:
        logger.error(f"AbuseIPDB check failed: {e}")
    return {"source": "abuseipdb", "target": ip, "verdict": "UNKNOWN"}

# ── Verdict Engine ────────────────────────────────────────────────

def compute_verdict(results: list) -> str:
    verdicts = [r.get("verdict") for r in results]
    if "PHISHING" in verdicts:
        return "PHISHING"
    if verdicts.count("SUSPICIOUS") >= 2:
        return "SUSPICIOUS"
    if "SUSPICIOUS" in verdicts:
        return "SUSPICIOUS"
    return "SAFE"