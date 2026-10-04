# Payloads (9,406 — corpus thật của §5.1)

`raw/` — payload gốc 1 dòng/payload, 4 lớp:
  sqli.txt 945 · xss.txt 6613 · path_traversal.txt 1608 · command_injection.txt 240  (= 9,406)
Nguồn: SecLists, PayloadBox, html5sec (public, giấy phép gốc giữ nguyên — xem LICENSE).

`manifest.csv` — id, class, source_list, **sha256 từng payload**, url_encoded (payload đã pre-encoded hay raw).
`per_payload_results.csv` — TEMPLATE. Để có bản thật: chạy harness `--full`, nó ghi `missed_payloads/missed_<class>.txt`
  (các payload KHÔNG bị 403). Blocked = tổng − miss. Số paper Table 2: SQLi 878/945, XSS 6543/6613,
  Trav 1458/1608, CMDi 176/240 (chạy --full).

## Harness
`../scripts/gwsec_dr_test.sh` — harness THẬT đã tạo ra số Table 2 (đã genericize IP).
  Gửi GET `/?q=<payload>`; smart-encode (giữ %XX pre-encoded, URL-encode raw); 403=blocked, khác=miss.
  Chạy toàn corpus:  ./gwsec_dr_test.sh --full --target=http://<VIP>:8080
  Benign/FPR = 20 query hardcoded; latency = median 20 request.
`../scripts/harness.py` — bản Python tương đương (emit per_payload_results.csv + Wilson CI Table 2).

> Lưu ý: scrub.py cố ý BỎ QUA payloads/raw + manifest (chuỗi tấn công public, không phải secret).
