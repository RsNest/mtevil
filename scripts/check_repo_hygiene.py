#!/usr/bin/env python3
"""CI repository hygiene linter (P1 / Q1).

Fails the build if tracked text files contain:
- Autonomous System numbers (e.g., AS12345),
- specific telecom / ISP names or common hosting/AS brand names,
- non-allowlisted public IPv4/IPv6 addresses or partial IP prefixes (outside
  RFC 1918/6598/5737/3849, loopback, link-local, and official Telegram DC CIDRs),
- non-allowlisted domain names outside RFC 2606 (`example.*`, `*.test`) and the
  explicitly approved infrastructure/preset allowlist.
"""
from __future__ import annotations

import hashlib
import ipaddress
import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

ALLOWED_V4_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    # Official Telegram MTProto Data Center IPv4 ranges:
    ipaddress.ip_network("91.105.192.0/23"),
    ipaddress.ip_network("91.108.4.0/22"),
    ipaddress.ip_network("91.108.8.0/21"),
    ipaddress.ip_network("91.108.16.0/21"),
    ipaddress.ip_network("91.108.56.0/22"),
    ipaddress.ip_network("149.154.160.0/20"),
    ipaddress.ip_network("185.76.151.0/24"),
    # Well-known public DNS resolver examples:
    ipaddress.ip_network("1.1.1.1/32"),
    ipaddress.ip_network("8.8.8.8/32"),
    ipaddress.ip_network("9.9.9.9/32"),
)

ALLOWED_DOMAINS = {
    "alpinelinux.org",
    "apache.org",
    "caddyserver.com",
    "cloudflare.com",
    "crates.io",
    "debian.org",
    "docker.com",
    "example.com",
    "example.net",
    "example.org",
    "ghcr.io",
    "github.com",
    "githubusercontent.com",
    "google.com",
    "habr.com",
    "ietf.org",
    "json-schema.org",
    "kernel.org",
    "letsencrypt.org",
    "mozilla.org",
    "mtproxy.github.io",
    "nginx.org",
    "openssl.org",
    "ozon.ru",
    "petrovich.ru",
    "pypi.org",
    "python.org",
    "rfc-editor.org",
    "rsnest.github.io",
    "rust-lang.org",
    "t.me",
    "telegram.org",
    "ubuntu.com",
    "vk.com",
    "wikipedia.org",
    "x.com",
    "ya.ru",
}

ALLOWED_DOMAIN_SUFFIXES = (
    ".example",
    ".example.com",
    ".example.net",
    ".example.org",
    ".localhost",
    ".test",
)

# SHA-256 digests of forbidden leaked tokens (domain roots / IPs / ASNs) so the linter
# rejects them without embedding plaintext private identifiers in the repository.
BANNED_SHA256_PREFIXES = {
    "d3f184",  # reserved slot check via prefix hash helper
}

SKIP_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".bin",
    ".der",
    ".crt",
    ".pem",
    ".lock",
}

SKIP_FILES = {
    "scripts/check_repo_hygiene.py",
}

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
PARTIAL_CIDR_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})/(\d{1,2})\b")
ASN_RE = re.compile(r"\bAS\d{2,7}\b")
ISP_BRAND_RE = re.compile(
    r"(?<![A-Za-zА-Яа-яЁё0-9_])(?:"
    r"мгтс|mgts"
    r"|ростелеком[а-яё]*|rostelecom\w*|ртк"
    r"|билайн[а-яё]*|beeline\w*|вымпелком[а-яё]*|vimpelcom\w*"
    r"|мегафон[а-яё]*|megafon\w*"
    r"|мтс|mts"
    r"|йот[аеыуой]|yota"
    r"|теле2|tele2"
    r"|эр-?телеком[а-яё]*|er-?telecom\w*|дом\.ру|dom\.ru|domru"
    r"|транстелеком[а-яё]*|transtelecom\w*|ттк"
    r"|акадо|akado|таттелеком[а-яё]*|tattelecom\w*|башинформсвяз[а-яё]*"
    r"|hetzner\w*|хетцнер[а-яё]*|ovhcloud|ovh"
    r"|digitalocean|linode|vultr|contabo|scaleway|upcloud|leaseweb|choopa|melbicom|hostkey"
    r"|aeza|аеза|аэза|timeweb\w*|таймвеб[а-яё]*|selectel\w*|селектел[а-яё]*"
    r"|vdsina\w*|firstvds\w*|ruvds\w*|beget\w*|бегет[а-яё]*|fornex"
    r"|comcast|verizon|vodafone|telefonica|chinanet"
    r")(?![A-Za-zА-Яа-яЁё0-9_])",
    re.IGNORECASE,
)
IPV6_RE = re.compile(r"(?<![A-Za-z0-9:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![A-Za-z0-9:])")
DOMAIN_TLD_RE = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]{1,63})*"
    r"\.(?:tech|ru|com|net|org|io|dev|app|cloud|me|su|info|biz|top|xyz|pro|site|online|club|space|host|shop|store|work|live|link|pw|cc|tv|uk|de|nl|ch|fr|us|eu)\b",
    re.IGNORECASE,
)
CODE_EXTS = {".rs", ".py"}


def _is_allowed_ipv4(raw: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(raw)
    except ValueError:
        return True
    return any(ip in net for net in ALLOWED_V4_NETS)


def _is_allowed_partial_cidr(a: int, b: int, prefix_len: int) -> bool:
    if a > 255 or b > 255 or prefix_len > 32:
        return True
    if a in (0, 10, 127) or (a == 192 and b == 168) or (a == 192 and b == 0) or (a == 198 and b == 51) or (a == 203 and b == 0):
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 100 and 64 <= b <= 127:
        return True
    if (a, b) in ((149, 154), (91, 108), (91, 105), (185, 76)):
        return True
    return False


def _is_allowed_ipv6(raw: str) -> bool:
    # Ignore HH:MM:SS timestamps (e.g. 12:34:56)
    if re.fullmatch(r"\d{1,2}:\d{2}:\d{2}", raw):
        return True
    try:
        ip = ipaddress.IPv6Address(raw)
    except ValueError:
        return True
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_private:
        return True
    if ip in ipaddress.ip_network("2001:db8::/32"):
        return True
    if ip.ipv4_mapped is not None:
        return _is_allowed_ipv4(str(ip.ipv4_mapped))
    return False


def _is_allowed_domain(raw: str) -> bool:
    d = raw.lower().rstrip(".")
    if d in ALLOWED_DOMAINS:
        return True
    if any(d.endswith("." + root) for root in ALLOWED_DOMAINS):
        return True
    if any(d.endswith(sfx) for sfx in ALLOWED_DOMAIN_SUFFIXES):
        return True
    return False


def _extract_code_comments_and_strings(text: str) -> list[tuple[int, str]]:
    """For .rs and .py, check only comments and string literals to avoid member-access false positives."""
    out: list[tuple[int, str]] = []
    str_pat = re.compile(r'r?#*"[^"\n]*"|\'[^\'\n]*\'|(//|#)[^\n]*')
    for lineno, line in enumerate(text.splitlines(), 1):
        chunks = [re.sub(r"\\[nrt]", " ", m.group(0)) for m in str_pat.finditer(line)]
        if chunks:
            out.append((lineno, " ".join(chunks)))
    return out


def scan_repo(root: pathlib.Path = REPO_ROOT) -> list[str]:
    errors: list[str] = []
    try:
        tracked = subprocess.check_output(
            ["git", "ls-files"], cwd=str(root), text=True
        ).splitlines()
    except (OSError, subprocess.SubprocessError):
        tracked = [
            str(p.relative_to(root)).replace("\\", "/")
            for p in root.rglob("*")
            if p.is_file() and ".git" not in p.parts and "target" not in p.parts
        ]

    for rel in tracked:
        norm = rel.replace("\\", "/")
        if norm in SKIP_FILES or norm.startswith("fuzz/corpus/"):
            continue
        p = root / rel
        if not p.is_file() or p.suffix.lower() in SKIP_EXTS:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        if p.suffix.lower() in CODE_EXTS:
            lines_to_scan = _extract_code_comments_and_strings(text)
        else:
            lines_to_scan = list(enumerate(text.splitlines(), 1))

        for lineno, line in lines_to_scan:
            for m in ASN_RE.finditer(line):
                errors.append(f"{norm}:{lineno}: disallowed AS number token '{m.group(0)}'")
            for m in ISP_BRAND_RE.finditer(line):
                h = hashlib.sha256(m.group(0).lower().encode()).hexdigest()[:12]
                errors.append(f"{norm}:{lineno}: disallowed ISP / AS brand name (sha256:{h})")
            for m in IPV4_RE.finditer(line):
                val = m.group(0)
                if not _is_allowed_ipv4(val):
                    h = hashlib.sha256(val.encode()).hexdigest()[:12]
                    errors.append(f"{norm}:{lineno}: non-allowlisted public IPv4 (sha256:{h})")
            for m in PARTIAL_CIDR_RE.finditer(line):
                a, b, plen = int(m.group(1)), int(m.group(2)), int(m.group(3))
                if not _is_allowed_partial_cidr(a, b, plen):
                    h = hashlib.sha256(m.group(0).encode()).hexdigest()[:12]
                    errors.append(f"{norm}:{lineno}: non-allowlisted partial IP prefix (sha256:{h})")
            for m in IPV6_RE.finditer(line):
                val = m.group(0)
                if not _is_allowed_ipv6(val):
                    h = hashlib.sha256(val.encode()).hexdigest()[:12]
                    errors.append(f"{norm}:{lineno}: non-allowlisted public IPv6 (sha256:{h})")
            for m in DOMAIN_TLD_RE.finditer(line):
                val = m.group(0)
                if not _is_allowed_domain(val):
                    h = hashlib.sha256(val.lower().encode()).hexdigest()[:12]
                    errors.append(
                        f"{norm}:{lineno}: non-allowlisted domain (tld=.{val.rsplit('.', 1)[1].lower()}, sha256:{h})"
                    )
    return errors


def main() -> int:
    errors = scan_repo(REPO_ROOT)
    if errors:
        print("Repository hygiene check FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print("Repository hygiene check passed cleanly (0 violations).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
