"""
serve_ai_engine.py — AI Engine (out-of-band) cho GatewaySec.

VAI TRÒ: đứng giữa CICFlowMeter và model. Nhận feature 1 flow -> khớp đúng
hợp đồng train -> XGBoost + Isolation Forest -> fusion -> verdict. Nếu ĐỦ tin
cậy (XGB >= 0.9) thì ghi verdict cho Wazuh Active Response chặn IP.

KHÔNG tự chặn gói. KHÔNG nằm trên packet path. Chỉ đọc feature, phán, rồi
đẩy verdict cho Wazuh AR thực thi (gwsec-drop). Đây là điểm defense.

ARTIFACT cần (copy vào để cùng thư mục):
  xgboost_model.json   iforest_model.pkl   scaler.pkl   feature_list.json

CHẠY:
  # chế độ batch (đọc CSV do CICFlowMeter xuất từ pcap) — dùng để test/demo tái lập
  python3 serve_ai_engine.py --csv /tmp/flows.csv
  # chế độ watch (poll file CSV live CICFlowMeter đang ghi)
  python3 serve_ai_engine.py --watch /tmp/flows_live.csv
"""
import pandas as pd
import numpy as np
import json, joblib, re, os, time, argparse
import xgboost as xgb

# ============================================================
# CẤU HÌNH — chốt theo kiến trúc đã thống nhất
# ============================================================
ART_DIR      = "."                                   # thư mục chứa 4 artifact
VERDICT_OUT  = "/var/log/ai-engine/verdict.json"     # Wazuh <localfile> đọc file này
W_XGB, W_IF  = 0.6, 0.4                               # trọng số late fusion
BLOCK_GATE   = 0.90   # CHỈ XGBoost >= ngưỡng này mới cho Active Response chặn
SUSPECT_GATE = 0.50   # fused >= ngưỡng này -> alert "suspicious" (KHÔNG chặn)
# IF chỉ đóng góp vào score cảnh báo, TỰ NÓ không bao giờ kích block (FPR cao).

# ============================================================
# norm() — GIỐNG HỆT align_datasets.py để map tên cột CICFlowMeter -> tên train
# (CICFlowMeter nhả "Tot Fwd Pkts", train lưu "Total Fwd Packets" -> cùng key)
# ============================================================
ABBREV = {
    "tot": "total", "pkts": "packets", "pkt": "packet", "len": "length",
    "fwd": "fwd", "bwd": "bwd", "byts": "bytes", "cnt": "count",
    "seg": "segment", "init": "init", "win": "window", "flg": "flag",
    "hdr": "header", "iat": "iat", "std": "std", "avg": "average",
    "max": "max", "min": "min", "mean": "mean", "var": "variance",
    "act": "active", "subflow": "subflow", "blk": "bulk", "dst": "destination",
    "src": "source", "ts": "timestamp", "prot": "protocol", "dur": "duration",
    # TODO: nếu checkpoint khớp cột báo THIẾU feature length/totlen, bổ sung ở đây:
    # "totlen": "totallength", "pktlen": "packetlength",
}

def norm(col: str) -> str:
    c = str(col).strip().lower()
    c = c.replace("/", " ").replace("_", " ").replace("-", " ").replace(".", " ")
    c = re.sub(r"[^a-z0-9 ]", "", c)
    return "".join(ABBREV.get(w, w) for w in c.split())

# ============================================================
# BẢNG RENAME: CICFlowMeter Java V4 (serve) -> CICIDS2017 V3 (train)
# V4 đổi tên 13 cột so với V3 (số ít/nhiều, đảo thứ tự từ, CWR/CWE...).
# Feature TÍNH GIỐNG HỆT, chỉ khác tên -> map tay tất định.
# ĐÃ VERIFY: sau rename, norm() khớp 78/78 feature CICIDS2017, RỚT 0.
# ============================================================
RENAME_V4_TO_2017 = {
    "Dst Port": "Destination Port",
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Backward Packets",
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
    "Packet Length Min": "Min Packet Length",
    "Packet Length Max": "Max Packet Length",
    "CWR Flag Count": "CWE Flag Count",
    "Fwd Segment Size Avg": "Avg Fwd Segment Size",
    "Bwd Segment Size Avg": "Avg Bwd Segment Size",
    "FWD Init Win Bytes": "Init_Win_bytes_forward",
    "Bwd Init Win Bytes": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
}


class AIEngine:
    def __init__(self, art_dir=ART_DIR):
        # --- feature contract (SOURCE OF TRUTH = file train xuất) ---
        self.feature_list = json.load(open(os.path.join(art_dir, "feature_list.json")))
        self.feat_key2name = {norm(f): f for f in self.feature_list}  # key -> tên train
        self.feat_keys_ordered = [norm(f) for f in self.feature_list]  # ĐÚNG thứ tự train

        # --- scaler + models ---
        self.scaler = joblib.load(os.path.join(art_dir, "scaler.pkl"))
        self.xgb = xgb.XGBClassifier()
        self.xgb.load_model(os.path.join(art_dir, "xgboost_model.json"))
        self.iforest = joblib.load(os.path.join(art_dir, "iforest_model.pkl"))

        # --- calibrate IF về [0,1] KHÔNG cần min-max theo batch ---
        # score_samples: cao = bình thường, thấp = bất thường. offset_ = ngưỡng.
        # anomaly = offset_ - score  (>0 = bất thường). Bọc sigmoid -> [0,1].
        self._if_offset = float(getattr(self.iforest, "offset_", -0.5))
        # TODO: scale này nên hiệu chỉnh bằng phân bố score trên tập train benign.
        # Tạm để 20 (đủ tách). Muốn khớp CHÍNH XÁC eval (min-max) thì train phải
        # lưu (raw.min, raw.max) ra if_norm.json rồi load ở đây.
        self._if_scale = 20.0

        print(f"[AIEngine] {len(self.feature_list)} feature | "
              f"IF offset={self._if_offset:.4f} | gate XGB>={BLOCK_GATE}")

    # ---------- 1) map + xếp cột incoming -> ma trận đúng thứ tự train ----------
    def _align_features(self, df: pd.DataFrame):
        # B0: rename cột V4 -> tên 2017 (tất định) TRƯỚC khi norm-match
        df = df.rename(columns=RENAME_V4_TO_2017)
        incoming = {norm(c): c for c in df.columns}          # key -> tên incoming
        missing = [k for k in self.feat_keys_ordered if k not in incoming]
        if missing:
            # feature train có mà CICFlowMeter KHÔNG nhả -> điền 0 + cảnh báo.
            # Nếu missing NHIỀU -> sai bản CICFlowMeter, verdict sẽ rác.
            miss_names = [self.feat_key2name[k] for k in missing]
            print(f"[WARN] thiếu {len(missing)}/{len(self.feature_list)} feature "
                  f"(điền 0): {miss_names[:8]}{'...' if len(miss_names)>8 else ''}")

        cols = []
        for k in self.feat_keys_ordered:
            if k in incoming:
                cols.append(pd.to_numeric(df[incoming[k]], errors="coerce"))
            else:
                cols.append(pd.Series(np.zeros(len(df)), index=df.index))
        X = pd.concat(cols, axis=1)
        X.columns = self.feature_list                        # đúng tên + thứ tự train
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)  # serve KHÔNG drop dòng
        return X, missing

    # ---------- 2) lấy IP nguồn (metadata, KHÔNG phải feature) để chặn ----------
    @staticmethod
    def _extract_src_ip(df: pd.DataFrame):
        for c in df.columns:
            if norm(c) in ("sourceip", "srcip"):
                return df[c].astype(str).values
        return np.array(["0.0.0.0"] * len(df))               # không có -> không chặn

    # ---------- 3) chấm điểm 1 batch flow ----------
    def score(self, df: pd.DataFrame):
        src_ips = self._extract_src_ip(df)
        X, _ = self._align_features(df)
        Xs = self.scaler.transform(X)

        p_xgb = self.xgb.predict_proba(Xs)[:, 1]             # xác suất attack
        raw = self.iforest.score_samples(Xs)                 # cao=normal, thấp=bất thường
        anomaly = self._if_offset - raw                      # >0 = bất thường
        p_if = 1.0 / (1.0 + np.exp(-self._if_scale * anomaly))  # sigmoid -> [0,1]

        fused = W_XGB * p_xgb + W_IF * p_if

        results = []
        for i in range(len(df)):
            block = bool(p_xgb[i] >= BLOCK_GATE)             # CHỈ XGB gate mới chặn
            if block:
                verdict = "malicious"
            elif fused[i] >= SUSPECT_GATE:
                verdict = "suspicious"                       # alert-only, KHÔNG chặn
            else:
                verdict = "benign"
            results.append({
                "src_ip": src_ips[i],                        # gwsec-drop regex đọc field này
                "verdict": verdict,
                "block": block,
                "xgb_conf": round(float(p_xgb[i]), 4),
                "if_score": round(float(p_if[i]), 4),
                "fused": round(float(fused[i]), 4),
            })
        return results

    # ---------- 4) ghi verdict cho Wazuh AR (chỉ ghi cái đáng ghi) ----------
    def emit(self, results):
        os.makedirs(os.path.dirname(VERDICT_OUT), exist_ok=True)
        n = 0
        with open(VERDICT_OUT, "a") as f:
            for r in results:
                if r["verdict"] == "benign":
                    continue                                 # đừng spam benign vào SIEM
                r["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                # compact (không cách) để khớp regex gwsec-drop: "src_ip":"..."
                f.write(json.dumps(r, separators=(",", ":")) + "\n")
                n += 1
                tag = "BLOCK" if r["block"] else "alert"
                print(f"  [{tag}] {r['src_ip']} xgb={r['xgb_conf']} "
                      f"fused={r['fused']} -> {r['verdict']}")
        return n


def run_csv(engine, path):
    df = pd.read_csv(path, low_memory=False)
    print(f"[+] {len(df)} flow từ {path}")
    engine.emit(engine.score(df))


def run_watch(engine, path, poll=2.0):
    """Poll file CSV live: chi DOC va xu dong MOI theo byte offset."""
    print(f"[+] watch {path} (Ctrl-C de dung)")
    from io import StringIO
    header = None
    offset = 0
    while True:
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    if header is None:
                        header = f.readline()
                        offset = f.tell()
                    f.seek(0, os.SEEK_END)
                    if f.tell() < offset:
                        offset = len(header.encode())
                    f.seek(offset)
                    new_lines = f.readlines()
                    offset = f.tell()
                if new_lines and header:
                    df = pd.read_csv(StringIO(header + "".join(new_lines)), low_memory=False)
                    if len(df):
                        engine.emit(engine.score(df))
            time.sleep(poll)
        except KeyboardInterrupt:
            print("[+] dung."); break
        except Exception as e:
            print(f"[!] {e}"); time.sleep(poll)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="đọc 1 file CSV CICFlowMeter rồi thoát (batch/demo)")
    ap.add_argument("--watch", help="poll file CSV live, xử dòng mới")
    ap.add_argument("--art", default=ART_DIR, help="thư mục chứa 4 artifact")
    args = ap.parse_args()

    engine = AIEngine(args.art)
    if args.csv:
        run_csv(engine, args.csv)
    elif args.watch:
        run_watch(engine, args.watch)
    else:
        print("Cần --csv <file> hoặc --watch <file>")
