#!/usr/bin/env python3
"""
scrub.py — quet secret / test-IP / data nhay cam truoc khi push repo public.

Dung:
  python scrub.py            # chi BAO CAO (khong sua file) — chay cai nay truoc
  python scrub.py --redact   # thay cac match bang [REDACTED] (ghi de file, can than)

Khong co dependency ngoai stdlib. Chay o thu muc goc repo.
Exit code != 0 neu con phat hien -> tien cho CI chan push.
"""
import os, re, sys, argparse

# (ten rule, regex, co redact khong). Redact=False => chi canh bao, khong tu sua
#   (vd IP private co the la mo ta hop le, de nguoi doc tu quyet).
RULES = [
    ("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), True),
    ("ZeroTier network id", re.compile(r"\b(?:network[_\s-]?id|nwid)\s*[:=]\s*[0-9a-f]{16}\b", re.I), True),
    ("ZeroTier 16-hex id",  re.compile(r"\b[0-9a-f]{16}\b"), False),  # canh bao, de tu xet
    ("Private key block",   re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"), True),
    ("AWS-like key",        re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("Space-delimited secret", re.compile(r"(?i)\b(auth_pass|password|passwd|secret|api[_-]?key)\s+[^\s#]{3,}"), True),
    ("ZeroTier NWID", re.compile(r"(?i)\bn?wid[:\s`]+[0-9a-f]{16}\b"), True),
    ("Generic secret kv",   re.compile(r"(?i)\b(pass(word)?|passwd|secret|api[_-]?key|token|auth[_-]?pass)\b\s*[:=]\s*['\"]?[^\s'\"]{4,}"), True),
    ("Wazuh creds",         re.compile(r"(?i)\bwazuh(-wui)?\s*[:/]\s*\S+"), True),
    ("Synthetic test IP",   re.compile(r"\b[5-9]\.[5-9]\.[5-9]\.[5-9]\b"), True),  # 5.5.5.5 .. 9.9.9.9
    ("Private IPv4",        re.compile(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"), False),
    ("onrender / live URL", re.compile(r"\bhttps?://[A-Za-z0-9.-]*onrender\.com\S*", re.I), False),
]

TEXT_EXT = {".md",".txt",".py",".sh",".yml",".yaml",".json",".csv",".conf",".cfg",
            ".xml",".ini",".env",".js",".ts",".html",".rules",".cff",".toml",""}
SKIP_PATHS = ("payloads/raw", "payloads/manifest.csv", "missed_payloads")  # corpus tấn công public, bỏ qua
SKIP_DIRS = {".git","__pycache__",".ipynb_checkpoints","node_modules"}

def is_text(path):
    return os.path.splitext(path)[1].lower() in TEXT_EXT

def scan_file(path, redact):
    try:
        data = open(path, encoding="utf-8", errors="replace").read()
    except Exception as e:
        return [], False
    hits, new = [], data
    for name, rx, can_redact in RULES:
        for m in rx.finditer(data):
            ln = data.count("\n", 0, m.start()) + 1
            sev = "REDACT" if (redact and can_redact) else ("WARN " if not can_redact else "FOUND")
            hits.append((sev, name, ln, m.group()[:80]))
        if redact and can_redact:
            new = rx.sub("[REDACTED]", new)
    changed = False
    if redact and new != data:
        open(path, "w", encoding="utf-8").write(new); changed = True
    return hits, changed

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--redact", action="store_true", help="thay match redactable bang [REDACTED] (ghi de file)")
    ap.add_argument("root", nargs="?", default=".")
    a = ap.parse_args()

    total, redacted_files = 0, 0
    for dp, dns, fns in os.walk(a.root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in sorted(fns):
            if fn == os.path.basename(__file__):   # bo qua chinh no
                continue
            p = os.path.join(dp, fn)
            if not is_text(p):
                continue
            if any(sp in p.replace("\\","/") for sp in SKIP_PATHS):
                continue
            hits, changed = scan_file(p, a.redact)
            if changed: redacted_files += 1
            for sev, name, ln, snip in hits:
                total += 1
                print(f"[{sev}] {p}:{ln}  {name}: {snip}")

    print("-"*60)
    if a.redact:
        print(f"Da redact {redacted_files} file. Van kiem tra WARN (khong tu sua) bang tay.")
    print(f"Tong phat hien: {total}")
    if total:
        print(">> CON SECRET/NHAY CAM. KHONG push cho toi khi sach (WARN tu xet, FOUND/REDACT phai xu).")
    else:
        print(">> Sach. An toan push.")
    # exit != 0 neu con FOUND/REDACT chua xu (WARN khong chan)
    sys.exit(1 if total and not a.redact else 0)

if __name__ == "__main__":
    main()
