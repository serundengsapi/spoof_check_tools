#!/usr/bin/python3

import argparse
import logging
import os
import smtplib
import sys
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Tuple

import dns.resolver
import emailprotectionslib.dmarc as dmarc_lib
import emailprotectionslib.spf as spf_lib
import tldextract
from colorama import Fore, Style
from colorama import init as color_init
from dns.exception import DNSException

import re

logging.basicConfig(level=logging.INFO)

# Global file handle for -o/--output logging
_output_file = None

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI color/style escape sequences from a string."""
    return _ANSI_ESCAPE.sub("", text)


def output(message, level="info"):
    colors = {
        "good": Fore.GREEN + Style.BRIGHT + "[+]" + Style.RESET_ALL,
        "indifferent": Fore.BLUE + Style.BRIGHT + "[*]" + Style.RESET_ALL,
        "error": Fore.RED + Style.BRIGHT + "[-] !!! " + Style.NORMAL,
        "bad": Fore.RED + Style.BRIGHT + "[-]" + Style.RESET_ALL,
        "info": Fore.WHITE + Style.BRIGHT + "[*]" + Style.RESET_ALL,
    }
    line = f"{colors[level]} {message}"
    print(line)
    if _output_file:
        # Write a clean (no ANSI) version to the output file
        tags = {"good": "[+]", "indifferent": "[*]", "error": "[-] !!!",
                "bad": "[-]", "info": "[*]"}
        _output_file.write(f"{tags[level]} {message}\n")


def check_spf_redirect_mechanisms(spf_record: spf_lib.SpfRecord) -> bool:
    redirect_domain = spf_record.get_redirect_domain()
    if redirect_domain:
        output(f"Processing an SPF redirect domain: {redirect_domain}", "info")
        return is_spf_record_strong(redirect_domain)
    return False


def check_spf_include_mechanisms(spf_record: spf_lib.SpfRecord) -> bool:
    include_domain_list = spf_record.get_include_domains()
    for include_domain in include_domain_list:
        output(f"Processing an SPF include domain: {include_domain}", "info")
        if is_spf_record_strong(include_domain):
            return True
    return False


def is_spf_redirect_record_strong(spf_record: spf_lib.SpfRecord) -> bool:
    output(f"Checking SPF redirect domain: {spf_record.get_redirect_domain()}", "info")
    redirect_strong = spf_record._is_redirect_mechanism_strong()
    level = "bad" if redirect_strong else "indifferent"
    output(
        (
            "Redirect mechanism is strong"
            if redirect_strong
            else "Redirect mechanism is not strong"
        ),
        level,
    )
    return redirect_strong


def check_spf_include_redirect(spf_record: spf_lib.SpfRecord) -> bool:
    if spf_record.get_redirect_domain():
        if is_spf_redirect_record_strong(spf_record):
            return True
    return spf_record._are_include_mechanisms_strong()


def check_spf_all_string(spf_record: spf_lib.SpfRecord) -> bool:
    """Check if SPF all string is strong"""
    if spf_record.all_string:
        if spf_record.all_string in ["~all", "-all"]:
            output(
                f"SPF record contains an All item: {spf_record.all_string}",
                "indifferent",
            )
            return True
        else:
            output(f"SPF record All item is too weak: {spf_record.all_string}", "good")
    else:
        output("SPF record has no All string", "good")

    return check_spf_include_redirect(spf_record)


def is_spf_record_strong(domain: str) -> bool:
    try:
        spf_record = spf_lib.SpfRecord.from_domain(domain)
        if spf_record and spf_record.record:
            output("Found SPF record:", "info")
            output(str(spf_record.record), "info")
            if not check_spf_all_string(spf_record):
                if not check_spf_redirect_mechanisms(
                    spf_record
                ) and not check_spf_include_mechanisms(spf_record):
                    return False
        else:
            output(f"{domain} has no SPF record!", "good")
            return False
        return True
    except DNSException as e:
        output(f"DNS error while checking SPF: {str(e)}", "error")
        return False


def check_dmarc_extras(dmarc_record: dmarc_lib.DmarcRecord) -> None:
    if dmarc_record.pct and dmarc_record.pct != "100":
        output(
            f"DMARC pct is set to {dmarc_record.pct}% - might be possible",
            "indifferent",
        )
    if dmarc_record.rua:
        output(f"Aggregate reports will be sent: {dmarc_record.rua}", "indifferent")
    if dmarc_record.ruf:
        output(f"Forensics reports will be sent: {dmarc_record.ruf}", "indifferent")


def check_dmarc_policy(dmarc_record: dmarc_lib.DmarcRecord) -> bool:
    if dmarc_record.policy:
        if dmarc_record.policy in ["reject", "quarantine"]:
            output(f"DMARC policy set to {dmarc_record.policy}", "bad")
            return True
        else:
            output(f"DMARC policy set to {dmarc_record.policy}", "good")
    else:
        output("DMARC record has no Policy", "good")
    return False


def check_dmarc_org_policy(base_record: dmarc_lib.DmarcRecord) -> bool:
    try:
        org_record = base_record.get_org_record()
        if org_record and org_record.record:
            output("Found organizational DMARC record:", "info")
            output(str(org_record.record), "info")
            if org_record.subdomain_policy:
                if org_record.subdomain_policy == "none":
                    output(
                        f"Organizational subdomain policy set to {org_record.subdomain_policy}",
                        "good",
                    )
                elif org_record.subdomain_policy in ["quarantine", "reject"]:
                    output(
                        f"Organizational subdomain policy explicitly set to {org_record.subdomain_policy}",
                        "bad",
                    )
                    return True
            else:
                output(
                    "No explicit organizational subdomain policy. Defaulting to organizational policy",
                    "info",
                )
                return check_dmarc_policy(org_record)
        else:
            output("No organizational DMARC record", "good")
    except dmarc_lib.OrgDomainException:
        output("No organizational DMARC record", "good")
    except Exception as e:
        logging.exception(e)
    return False


def is_dmarc_record_strong(domain: str) -> bool:
    try:
        dmarc = dmarc_lib.DmarcRecord.from_domain(domain)
        if dmarc and dmarc.record:
            output("Found DMARC record:", "info")
            output(str(dmarc.record), "info")
            if check_dmarc_policy(dmarc):
                check_dmarc_extras(dmarc)
                return True
        elif dmarc.get_org_domain():
            output("No DMARC record found. Looking for organizational record", "info")
            return check_dmarc_org_policy(dmarc)
        else:
            output(f"{domain} has no DMARC record!", "good")
        return False
    except DNSException as e:
        output(f"DNS error while checking DMARC: {str(e)}", "error")
        return False


def check_domain(domain: str) -> Tuple[bool, bool, bool]:
    spf_strong = is_spf_record_strong(domain)
    dmarc_strong = is_dmarc_record_strong(domain)
    is_spoofable = not dmarc_strong
    return is_spoofable, spf_strong, dmarc_strong


# ---------------------------------------------------------------------------
# Email spoofing test helpers
# ---------------------------------------------------------------------------

TEST_RECIPIENTS: List[str] = [
    "0x25952fa784ffe9574d6be0add07530c21b4a1521@ethermail.io",
    "abnid312@gmail.com",
    "ryujinx@wearehackerone.com",
]


def get_mx_hosts(domain: str) -> List[str]:
    """Resolve MX records for *domain* and return hostnames sorted by priority.
    Compatible with both dnspython <2.0 (query) and >=2.0 (resolve)."""
    try:
        # dnspython >= 2.0
        _dns_query = getattr(dns.resolver, "resolve", None) or dns.resolver.query
        answers = _dns_query(domain, "MX")
        mx_hosts = sorted(answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in mx_hosts]
    except Exception as e:
        output(f"Failed to resolve MX records for {domain}: {e}", "error")
        return []


def build_spoof_email(from_domain: str, recipient: str) -> MIMEMultipart:
    """Build a spoofed MIME email that clearly identifies itself as a
    security test so it won't be mistaken for real phishing."""
    sender = f"security-test@{from_domain}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    msg = MIMEMultipart("alternative")
    msg["From"] = f"Spoof Test <{sender}>"
    msg["To"] = recipient
    msg["Subject"] = f"[SPOOF TEST] Email Spoofing Verification - {from_domain}"
    msg["X-Spoofcheck-Test"] = "true"
    msg["Date"] = timestamp

    text_body = (
        f"=== EMAIL SPOOFING TEST ===\n\n"
        f"This is an automated spoofing verification email.\n"
        f"Spoofed domain : {from_domain}\n"
        f"Sender address : {sender}\n"
        f"Recipient      : {recipient}\n"
        f"Timestamp      : {timestamp}\n\n"
        f"If you received this email in your inbox, the domain "
        f"'{from_domain}' is vulnerable to email spoofing.\n\n"
        f"--- spoofcheck automated test ---\n"
    )

    html_body = (
        f"<html><body style='font-family:monospace;background:#1a1a2e;color:#e0e0e0;"
        f"padding:20px;'>"
        f"<h2 style='color:#00ff88;'>&#128274; Email Spoofing Test</h2>"
        f"<hr style='border-color:#333;'>"
        f"<p>This is an <b>automated spoofing verification</b> email.</p>"
        f"<table style='border-collapse:collapse;'>"
        f"<tr><td style='padding:4px 12px;color:#888;'>Spoofed domain</td>"
        f"<td style='padding:4px 12px;color:#00ff88;'>{from_domain}</td></tr>"
        f"<tr><td style='padding:4px 12px;color:#888;'>From</td>"
        f"<td style='padding:4px 12px;'>{sender}</td></tr>"
        f"<tr><td style='padding:4px 12px;color:#888;'>To</td>"
        f"<td style='padding:4px 12px;'>{recipient}</td></tr>"
        f"<tr><td style='padding:4px 12px;color:#888;'>Time</td>"
        f"<td style='padding:4px 12px;'>{timestamp}</td></tr>"
        f"</table>"
        f"<hr style='border-color:#333;'>"
        f"<p style='color:#ff6b6b;'>If you see this in your inbox, "
        f"<b>{from_domain}</b> is vulnerable to email spoofing.</p>"
        f"<p style='font-size:11px;color:#555;'>— spoofcheck automated test —</p>"
        f"</body></html>"
    )

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))
    return msg


def send_spoof_test(domain: str) -> None:
    """Deliver spoofed emails from *domain* to every TEST_RECIPIENTS address.

    How it works (same approach as emkei.cz):
      1. The From header is forged as  security-test@<spoofed domain>
      2. For each recipient we resolve the MX of the **recipient's** domain
         (e.g. gmail.com, ethermail.io) — NOT the spoofed sender's domain.
      3. We connect directly to the recipient's MX and hand off the message.
    """
    output(
        f"\n{'='*60}\n  SPOOFING TEST — Sending test emails as {domain}\n{'='*60}",
        "info",
    )

    sender = f"security-test@{domain}"
    mx_cache: dict = {}  # cache MX lookups per recipient domain

    for recipient in TEST_RECIPIENTS:
        output(f"\nSending spoofed email to: {recipient}", "info")

        # Resolve MX for the recipient's domain, not the spoofed domain
        rcpt_domain = recipient.split("@", 1)[1]
        if rcpt_domain not in mx_cache:
            mx_cache[rcpt_domain] = get_mx_hosts(rcpt_domain)
        mx_hosts = mx_cache[rcpt_domain]

        if not mx_hosts:
            output(f"  No MX records for recipient domain {rcpt_domain} — skipping", "error")
            continue

        output(f"  Recipient MX hosts ({rcpt_domain}): {', '.join(mx_hosts)}", "info")
        msg = build_spoof_email(domain, recipient)
        delivered = False

        # Try each MX host in priority order until one accepts
        for mx_host in mx_hosts:
            try:
                output(f"  Trying MX host: {mx_host}:25", "info")
                with smtplib.SMTP(mx_host, 25, timeout=15) as smtp:
                    smtp.ehlo(domain)
                    # Attempt STARTTLS if the server supports it
                    try:
                        smtp.starttls()
                        smtp.ehlo(domain)
                    except smtplib.SMTPNotSupportedError:
                        pass
                    smtp.sendmail(sender, recipient, msg.as_string())
                output(
                    f"  ✓ Email accepted by {mx_host} for {recipient}",
                    "good",
                )
                delivered = True
                break  # no need to try remaining MX hosts
            except smtplib.SMTPRecipientsRefused as e:
                output(f"  Recipient refused by {mx_host}: {e}", "bad")
            except smtplib.SMTPSenderRefused as e:
                output(f"  Sender refused by {mx_host}: {e}", "bad")
            except smtplib.SMTPException as e:
                output(f"  SMTP error with {mx_host}: {e}", "bad")
            except OSError as e:
                output(f"  Connection error with {mx_host}: {e}", "bad")

        if not delivered:
            output(
                f"  ✗ Failed to deliver to {recipient} via any MX host",
                "error",
            )

    output(f"\n{'='*60}\n  Spoofing test complete\n{'='*60}\n", "info")


def extract_root_domain(entry: str) -> str | None:
    """Extract the registered root domain from a URL, subdomain, or plain domain.
    Examples:
        https://00000-vedi.sushi.com  →  sushi.com
        000000k.t.me                 →  t.me
        sub.example.co.uk            →  example.co.uk
    Returns None if extraction fails."""
    entry = entry.strip()
    # Strip protocol + path so tldextract gets a clean hostname
    if "://" in entry:
        entry = entry.split("://", 1)[1]
    entry = entry.split("/", 1)[0]    # drop path
    entry = entry.split("?", 1)[0]    # drop query string
    entry = entry.split("#", 1)[0]    # drop fragment
    entry = entry.split(":", 1)[0]    # drop port

    ext = tldextract.extract(entry)
    if ext.domain and ext.suffix:
        return ext.registered_domain
    return None


def load_domains_from_file(filepath: str) -> List[str]:
    """Read entries from a text file, extract root domains, and deduplicate.
    Accepts raw URLs, subdomains, or plain domains — one per line.
    Blank lines and lines starting with # are ignored."""
    if not os.path.isfile(filepath):
        output(f"File not found: {filepath}", "error")
        sys.exit(1)

    raw_entries: List[str] = []
    with open(filepath, "r") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                raw_entries.append(line)

    if not raw_entries:
        output(f"No entries found in {filepath}", "error")
        sys.exit(1)

    # Extract root domains and deduplicate while preserving order
    seen: set = set()
    unique_domains: List[str] = []
    skipped = 0

    for entry in raw_entries:
        root = extract_root_domain(entry)
        if root:
            if root not in seen:
                seen.add(root)
                unique_domains.append(root)
        else:
            skipped += 1
            output(f"Could not extract root domain from: {entry}", "bad")

    if not unique_domains:
        output("No valid domains extracted from file", "error")
        sys.exit(1)

    output(f"Raw entries: {len(raw_entries)}  →  Unique root domains: {len(unique_domains)}", "info")
    if skipped:
        output(f"Skipped {skipped} unrecognized entries", "bad")

    return unique_domains


def process_domain(domain: str) -> bool:
    """Run spoofcheck + spoof test on a single domain. Returns True if spoofable."""
    output(f"\n{'─'*60}", "info")
    output(f"Checking domain: {domain}", "info")
    output(f"{'─'*60}", "info")

    is_spoofable, spf_strong, dmarc_strong = check_domain(domain)

    if is_spoofable:
        output(f"Spoofing possible for {domain}!", "good")
        output("\nInitiating email spoofing test...", "info")
        send_spoof_test(domain)
        return True
    else:
        output(f"Spoofing not possible for {domain}", "bad")
        return False


def print_summary(results: List[Tuple[str, bool]]) -> None:
    """Print a final summary table after a bulk run."""
    spoofable = [d for d, s in results if s]
    safe = [d for d, s in results if not s]

    output(f"\n{'='*60}", "info")
    output(f"  BULK SCAN SUMMARY  ({len(results)} domains)", "info")
    output(f"{'='*60}", "info")
    output(f"  Spoofable   : {len(spoofable)}", "good")
    output(f"  Protected   : {len(safe)}", "bad")
    output(f"{'─'*60}", "info")

    if spoofable:
        output("  Vulnerable domains (test emails sent):", "good")
        for d in spoofable:
            output(f"    ✓ {d}", "good")
    if safe:
        output("  Protected domains:", "bad")
        for d in safe:
            output(f"    ✗ {d}", "bad")

    output(f"{'='*60}\n", "info")


if __name__ == "__main__":
    color_init()

    parser = argparse.ArgumentParser(
        description=(
            "Check if a domain can be spoofed based on SPF and DMARC records.\n"
            "Accepts raw URLs, subdomains, or plain domains — root domains are\n"
            "extracted automatically and duplicates are removed."
        ),
        epilog=(
            "Examples:\n"
            "  %(prog)s -d example.com                Check a single domain\n"
            "  %(prog)s -d https://sub.example.com     Also works (extracts root)\n"
            "  %(prog)s -f subdomains.txt              Bulk check from file\n"
            "  %(prog)s -f subdomains.txt --no-test    Check only, skip sending emails\n"
            "  %(prog)s -f subdomains.txt -o result.txt  Save output to file\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single domain / URL / subdomain to check")
    group.add_argument(
        "-f", "--file",
        help="File containing domains/URLs/subdomains (one per line). "
             "Root domains are extracted and deduplicated automatically.",
    )
    parser.add_argument(
        "--no-test",
        action="store_true",
        help="Skip sending test emails even if spoofing is possible",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Save all output to a file (plain text, no colors)",
    )

    args = parser.parse_args()

    # ── Open output file if requested ──
    if args.output:
        try:
            _output_file = open(args.output, "w")
            _output_file.write(f"spoofcheck results — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            _output_file.write(f"{'='*60}\n\n")
        except OSError as e:
            output(f"Cannot open output file: {e}", "error")
            sys.exit(1)

    try:
        if args.domain:
            # ── Single domain mode ──
            root = extract_root_domain(args.domain)
            if not root:
                output(f"Could not extract a valid root domain from: {args.domain}", "error")
                sys.exit(1)
            if root != args.domain:
                output(f"Extracted root domain: {root}  (from {args.domain})", "info")
            domains = [root]
        else:
            # ── Bulk file mode ──
            domains = load_domains_from_file(args.file)
            output(f"Loaded {len(domains)} unique root domain(s) from {args.file}", "info")

        results: List[Tuple[str, bool]] = []

        for domain in domains:
            if args.no_test:
                # Check only, no email sending
                output(f"\n{'─'*60}", "info")
                output(f"Checking domain: {domain}", "info")
                output(f"{'─'*60}", "info")
                is_spoofable, _, _ = check_domain(domain)
                if is_spoofable:
                    output(f"Spoofing possible for {domain}!", "good")
                else:
                    output(f"Spoofing not possible for {domain}", "bad")
                results.append((domain, is_spoofable))
            else:
                spoofable = process_domain(domain)
                results.append((domain, spoofable))

        # Print summary when checking multiple domains
        if len(results) > 1:
            print_summary(results)

        # ── Write structured summary to output file ──
        if _output_file:
            spoofable = [d for d, s in results if s]
            safe = [d for d, s in results if not s]
            _output_file.write(f"\n{'='*60}\n")
            _output_file.write(f"SUMMARY — {len(results)} domain(s) checked\n")
            _output_file.write(f"{'='*60}\n")
            _output_file.write(f"Spoofable : {len(spoofable)}\n")
            _output_file.write(f"Protected : {len(safe)}\n")
            _output_file.write(f"{'─'*60}\n")
            if spoofable:
                _output_file.write("\nVulnerable domains (test emails sent):\n")
                for d in spoofable:
                    _output_file.write(f"  ✓ {d}\n")
            if safe:
                _output_file.write("\nProtected domains:\n")
                for d in safe:
                    _output_file.write(f"  ✗ {d}\n")
            _output_file.write(f"{'='*60}\n")
            output(f"\nResults saved to: {args.output}", "info")

    except KeyboardInterrupt:
        output("\nAborted by user.", "error")
        sys.exit(130)
    except Exception as e:
        logging.exception("An unexpected error occurred")
        output(f"Error: {str(e)}", "error")
        sys.exit(1)
    finally:
        if _output_file:
            _output_file.close()
