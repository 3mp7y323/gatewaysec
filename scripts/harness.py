#!/usr/bin/env python3
"""
harness.py — ban payload qua GatewaySec, ghi ket qua 403-based blocking.

Khop methodology trong paper:
  - encoding (§2.3): soi moi chuoi tim percent-octet %XX co san;
    chi URL-encode chuoi RAW, giu nguyen chuoi da pre-encoded (tranh double-encode).
  - metric (§4): HTTP 403 = blocked; moi outcome khac (gom timeout) = miss.
  - 95% Wilson interval cho moi lop (ra dung Table 2).

Input: thu muc payload, moi lop 1 file .txt (1 payload / dong). Vi du:
  payloads/raw/sqli.txt  xss.txt  path_traversal.txt  command_injection.txt  benign.txt

Output (ghi vao --out, mac dinh ./payloads/):
  manifest.csv              id,class,source_list,sha256,url_encoded
  per_payload_results.csv   id,class,http_status,blocked

Chay:
  python harness.py --target https://192.0.2.10:8080 --raw-dir payloads/raw
  python harness.py --emit-results   # alias tien dung, dung mac dinh

LUU Y QUAN TRONG (methodology):
  * Active Response co the chan IP cua chinh may ban payload giua chung (rule
    correlation 100301-304 / 100201). Khi do payload sau se timeout = miss va
    lam lech ket qua. Chay tu IP duoc allowlist, hoac de y canh bao "nhieu
    timeout lien tiep" ben duoi roi tam dung / go block tr-oc khi chay tiep.
  * L1 iptables gioi han SYN moi 25/s — dat --delay du de khong tu trip.
"""
import argparse, csv, hashlib, math, os, re, sys, time
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("Can: pip install requests")
from urllib.parse import quote

PRE_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")   # §2.3: dau hieu da percent-encoded
CLASS_FILES = {   # ten file -> (class label, source_list mac dinh)
    "sqli":               ("sqli",              "SecLists/PayloadBox"),
    "xss":                ("xss",               "PayloadBox/html5sec"),
    "path_traversal":     ("path_traversal",    "SecLists"),
    "command_injection":  ("command_injection", "PayloadBox"),
    "benign":             ("benign",            "authored"),
}
PREFIX = {"sqli":"SQLI","xss":"XSS","path_traversal":"PT","command_injection":"CMD","benign":"BEN"}

def encode_payload(s):
    """Tra ve (chuoi_gui, da_url_encode?). Raw -> quote; pre-encoded -> giu nguyen."""
    if PRE_ENCODED.search(s):
        return s, False
    return quote(s, safe=""), True

def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = k / n; d = 1 + z*z/n
    c = (p + z*z/(2*n)) / d
    h = (z * math.sqrt(p*(1-p)/n + z*z/(4*n*n))) / d
    return (max(0, c-h), min(1, c+h))

def send(session, target, payload_sent, method, where, timeout):
    """Gui 1 payload. Tra ve http_status (int) hoac None neu timeout/loi mang."""
    try:
        if where == "query":
            r = session.request(method, target, params={"q": payload_sent},
                                 timeout=timeout, verify=False, allow_redirects=False)
        elif where == "body":
            r = session.request(method, target, data={"q": payload_sent},
                                 timeout=timeout, verify=False, allow_redirects=False)
        else:  # path
            r = session.request(method, target.rstrip("/") + "/" + payload_sent,
                                 timeout=timeout, verify=False, allow_redirects=False)
        return r.status_code
    except requests.exceptions.RequestException:
        return None   # timeout / connection reset -> dem la miss

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="https://192.0.2.10:8080",
                    help="VIP gateway, vd https://192.0.2.10:8080")
    ap.add_argument("--raw-dir", default="payloads/raw", help="thu muc chua <class>.txt")
    ap.add_argument("--out", default="payloads", help="thu muc ghi manifest + results")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--where", default="query", choices=["query","body","path"])
    ap.add_argument("--delay", type=float, default=0.05, help="giay giua 2 request (tranh rate-limit)")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--emit-results", action="store_true", help="alias: dung mac dinh")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    session = requests.Session()
    man_path = os.path.join(a.out, "manifest.csv")
    res_path = os.path.join(a.out, "per_payload_results.csv")
    man = csv.writer(open(man_path, "w", newline="", encoding="utf-8"))
    res = csv.writer(open(res_path, "w", newline="", encoding="utf-8"))
    man.writerow(["id","class","source_list","sha256","url_encoded"])
    res.writerow(["id","class","http_status","blocked"])

    per_class = {}   # class -> [n, blocked]
    consec_timeout = 0
    total = 0

    for fname, (klass, src) in CLASS_FILES.items():
        fpath = os.path.join(a.raw_dir, fname + ".txt")
        if not os.path.exists(fpath):
            print(f"[skip] khong thay {fpath}")
            continue
        payloads = [ln.rstrip("\n") for ln in open(fpath, encoding="utf-8", errors="replace") if ln.strip()]
        per_class.setdefault(klass, [0, 0])
        for i, raw in enumerate(payloads, 1):
            pid = f"{PREFIX[klass]}-{i:04d}"
            sha = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
            sent, encoded = encode_payload(raw)
            man.writerow([pid, klass, src, sha, str(encoded).lower()])

            status = send(session, a.target, sent, a.method, a.where, a.timeout)
            blocked = (status == 403)
            res.writerow([pid, klass, status if status is not None else "timeout",
                          str(blocked).lower()])
            per_class[klass][0] += 1
            if blocked: per_class[klass][1] += 1
            total += 1

            # canh bao AR chan may minh
            consec_timeout = consec_timeout + 1 if status is None else 0
            if consec_timeout == 15:
                print(f"\n[!] 15 timeout lien tiep — co the IP cua may dang bi Active Response "
                      f"chan. Kiem tra: sudo iptables -L INPUT -n | grep <IP>. Tam dung...\n")
            time.sleep(a.delay)

    # ---- summary (Table 2 style) ----
    print("\n=== 403-based blocking rate (Wilson 95% CI) ===")
    print(f"{'class':<20}{'n':>7}{'blocked':>9}{'BR%':>8}   95% CI")
    prim_n = prim_b = 0
    all_n = all_b = 0
    for klass, (n, b) in per_class.items():
        lo, hi = wilson(b, n)
        print(f"{klass:<20}{n:>7}{b:>9}{100*b/n if n else 0:>8.1f}   [{100*lo:.1f}, {100*hi:.1f}]")
        if klass in ("sqli","xss"): prim_n += n; prim_b += b
        if klass != "benign":       all_n += n; all_b += b
    if prim_n:
        lo, hi = wilson(prim_b, prim_n)
        print(f"{'PRIMARY (sqli+xss)':<20}{prim_n:>7}{prim_b:>9}{100*prim_b/prim_n:>8.1f}   [{100*lo:.1f}, {100*hi:.1f}]")
    if all_n:
        lo, hi = wilson(all_b, all_n)
        print(f"{'ALL attack classes':<20}{all_n:>7}{all_b:>9}{100*all_b/all_n:>8.1f}   [{100*lo:.1f}, {100*hi:.1f}]")
    # FPR tu benign
    if "benign" in per_class and per_class["benign"][0]:
        n, b = per_class["benign"]
        print(f"\nFPR (benign blocked): {b}/{n} = {100*b/n:.1f}%  (n nho -> xem §6 limits)")
    print(f"\nDa ghi: {man_path} , {res_path}  ({total} payload)")
    print("Nho chay scrub.py truoc khi push neu log/ket qua co IP noi bo.")

if __name__ == "__main__":
    main()
