import asyncio
import re
import dns.resolver
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage
from checks import check_url_virustotal, check_domain_virustotal, check_ip_abuseipdb, compute_verdict
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Extraction helpers ────────────────────────────────────────────

URL_REGEX = re.compile(r'https?://[^\s<>"\']+')
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def extract_urls(text: str) -> list:
    return list(set(URL_REGEX.findall(text)))

def extract_ips(text: str) -> list:
    return list(set(IP_REGEX.findall(text)))

def extract_domains(urls: list) -> list:
    domains = []
    for url in urls:
        match = re.search(r'https?://([^/\s]+)', url)
        if match:
            domains.append(match.group(1))
    return list(set(domains))

def extract_sender_domain(sender: str) -> str:
    match = re.search(r'@([\w\.-]+)', sender)
    return match.group(1) if match else None

def check_spf_dmarc(domain: str) -> dict:
    results = {"spf": False, "dmarc": False}
    try:
        spf = dns.resolver.resolve(domain, 'TXT')
        for r in spf:
            if 'v=spf1' in str(r):
                results["spf"] = True
    except:
        pass
    try:
        dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for r in dmarc:
            if 'v=DMARC1' in str(r):
                results["dmarc"] = True
    except:
        pass
    return results

def get_email_body(message) -> str:
    body = ""
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = message.get_payload(decode=True).decode(errors="ignore")
    return body

def get_attachments(message) -> list:
    attachments = []
    for part in message.walk():
        if part.get_content_disposition() == "attachment":
            attachments.append({
                "filename": part.get_filename(),
                "content_type": part.get_content_type(),
                "data": part.get_payload(decode=True)
            })
    return attachments

# ── SMTP Handler ──────────────────────────────────────────────────
class PhishingHandler(AsyncMessage):
    async def handle_message(self, message):
        logger.info("=== NEW EMAIL RECEIVED ===")
        logger.info(f"From: {message['from']} | Subject: {message['subject']}")

        body = get_email_body(message)
        urls = extract_urls(body)
        ips = extract_ips(body)
        domains = extract_domains(urls)
        sender_domain = extract_sender_domain(message['from'])
        dns_checks = check_spf_dmarc(sender_domain) if sender_domain else {}

        logger.info(f"Extracted — URLs: {urls} | IPs: {ips} | Domains: {domains}")

        # Run all checks
        check_results = []

        for url in urls:
            result = await check_url_virustotal(url)
            check_results.append(result)
            logger.info(f"VT URL check: {result}")

        for domain in domains:
            result = await check_domain_virustotal(domain)
            check_results.append(result)
            logger.info(f"VT Domain check: {result}")

        for ip in ips:
            result = await check_ip_abuseipdb(ip)
            check_results.append(result)
            logger.info(f"AbuseIPDB check: {result}")

        final_verdict = compute_verdict(check_results)
        logger.info(f"=== FINAL VERDICT: {final_verdict} ===")

if __name__ == "__main__":
    handler = PhishingHandler()
    controller = Controller(handler, hostname="0.0.0.0", port=1025)
    controller.start()
    logger.info("SMTP server running on port 1025")
    asyncio.get_event_loop().run_forever()