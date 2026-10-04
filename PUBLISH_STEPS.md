# PUBLISH_STEPS — đưa artifact lên GitHub + Zenodo (lấy DOI)

Thứ tự: dọn → scrub sạch → GitHub private → rà → public → Zenodo DOI → dán DOI vào paper.

## 0. (tùy chọn) genericize IP nội bộ trong config
75 cảnh báo WARN còn lại đều là IP RFC1918 trong `config/GatewaySec_config_sanitized.md` (low-risk, lab đã bỏ).
Muốn gọn tuyệt đối thì đổi về dải tài liệu:
```
sed -i 's/192\.168\.150\.128/203.0.113.10/g; s/192\.168\.0\.210/192.0.2.10/g;
        s/192\.168\.140\./198.51.100./g; s/192\.168\.0\./192.0.2./g' config/GatewaySec_config_sanitized.md
```
(Không bắt buộc — IP nội bộ không phải secret. Khoá bí mật như password/NWID đã redact.)

## 1. SCRUB — bắt buộc, phải 0 FOUND
```
python3 scrub.py .
```
- `>> Sach` hoặc chỉ còn WARN (IP) → OK.
- Còn `[FOUND]` → xử hết rồi mới push. (scrub cố ý bỏ qua payloads/raw — corpus tấn công public.)

## 2. (tùy chọn) bổ sung data thật nếu lab còn sống
- `per_payload_results.csv` thật: `cd scripts && ./gwsec_dr_test.sh --full --target=http://<VIP>:8080`
  → sinh `missed_payloads/` → blocked = tổng − miss. Đưa kết quả vào `payloads/`.
- 3 PNG: `cd scripts && python3 verify_models.py` (cần cicids2017_combined.csv) → copy PNG vào `results/`.
- Không có cũng push được — manifest + harness đã đủ mạnh.

## 3. Rà ranh giới (đừng vượt)
- [ ] KHÔNG có source 5 app người khác (chỉ payload + manifest).
- [ ] KHÔNG có hình/record data hospital.
- [ ] `.gitignore` đã chặn `*.log`, `verdict.json`, `app-sources/`, dataset CSV, venv.

## 4. GitHub — PRIVATE trước
```
cd gatewaysec-artifact
git init && git add . && git commit -m "GatewaySec reproducibility artifact v1.0"
git branch -M main
git remote add origin https://github.com/<user>/gatewaysec-iap491.git
git push -u origin main
```
Để **Private**. Mở trên web rà lại 1 lượt (nhất là config + có file lạ không).

## 5. Public
Settings → Danger Zone → Change visibility → Public. (Chỉ khi mục 1–4 xong.)

## 6. Zenodo — lấy DOI
1. zenodo.org → đăng nhập bằng GitHub → Settings → GitHub → bật switch repo `gatewaysec-iap491`.
2. Về GitHub repo → Releases → **Create a new release** → tag `v1.0` → Publish.
3. Zenodo tự nhận, mint **DOI** (dạng `10.5281/zenodo.XXXXXXX`). Lấy số đó.

## 7. Dán DOI vào 3 chỗ
- `README.md`: thay `10.5281/zenodo.XXXXXXX`.
- `CITATION.cff`: field `doi:`.
- **Paper** — Data & code availability:
  > All models, scripts, the gateway configuration, the 9,406-payload manifest, and the test harness
  > are archived at https://doi.org/10.5281/zenodo.XXXXXXX. Payloads come from public lists
  > (SecLists, PayloadBox, html5sec); third-party application sources are not redistributed.
  > The VM testbed was decommissioned; the archive supports offline reproduction of the model
  > results and configuration review, not live end-to-end replay.

## 8. Checklist cuối
- [ ] scrub 0 FOUND
- [ ] private → rà → public
- [ ] Zenodo DOI mint xong
- [ ] DOI dán vào README + CITATION + paper
- [ ] (paper) điền [CONFIRM harness] + sửa latency "mean"→"median"
- [ ] (paper) verify/bỏ citation [23]; chọn câu Authorization & ethics (bản self-host)
