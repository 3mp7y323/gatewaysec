"""
verify_models.py — Đánh giá 4 artifact đã train (khớp CHÍNH XÁC train_ids_models.py)
Chạy trên máy có sẵn: cicids2017_combined.csv + 4 file artifact.
Tái tạo đúng X_test (random_state=42) -> chấm điểm -> xuất metrics.json + chart PNG cho báo cáo.

  python verify_models.py
"""
import pandas as pd
import numpy as np
import xgboost as xgb
import joblib, json, gc
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, roc_auc_score, roc_curve)

DATA_PATH = "./cicids2017_combined.csv"   # SỬA nếu khác
BLOCK_TH  = 0.9    # ngưỡng XGBoost auto-block (gating)
W_XGB, W_IF = 0.6, 0.4   # trọng số late-fusion

# ---- copy y hệt 2 hàm trong script train để tái tạo đúng tập test ----
def reduce_mem_usage(df):
    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            c_min, c_max = df[col].min(), df[col].max()
            if str(df[col].dtype)[:3] == 'int':
                if c_min > np.iinfo(np.int32).min and c_max < np.iinfo(np.int32).max:
                    df[col] = df[col].astype(np.int32)
            else:
                if c_min > np.finfo(np.float32).min and c_max < np.finfo(np.float32).max:
                    df[col] = df[col].astype(np.float32)
    return df

def clean_data(df):
    df.columns = df.columns.str.strip()
    df = df[df['Destination Port'] != 'Destination Port']
    label_col = df['Label']
    features = df.drop(columns=['Label']).apply(pd.to_numeric, errors='coerce')
    features['Label'] = label_col
    df = features
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    return df

def main():
    print("[+] Load + clean dataset (tái tạo đúng tập test)...")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    df = clean_data(df); df = reduce_mem_usage(df)
    df['Label_Binary'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    X = df.drop(columns=['Label', 'Label_Binary'])
    y = df['Label_Binary']

    # PHẢI giống train: test_size=0.2, random_state=42, stratify=y
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2,
                                            random_state=42, stratify=y)
    del df, X, y; gc.collect()
    print(f"[+] Tập test: {len(X_test):,} dòng | attack={int(y_test.sum()):,} benign={int((y_test==0).sum()):,}")

    # ---- nạp artifact + kiểm tra feature khớp ----
    feat = json.load(open('feature_list.json'))
    assert list(X_test.columns) == feat, "Feature order KHÔNG khớp feature_list.json!"
    scaler = joblib.load('scaler.pkl')
    X_test_scaled = scaler.transform(X_test)       # CHỈ transform, không fit

    xgb_model = xgb.XGBClassifier()
    xgb_model.load_model('xgboost_model.json')
    try: xgb_model.set_params(device='cpu')        # verify chạy được cả máy không GPU
    except Exception: pass
    iforest = joblib.load('iforest_model.pkl')

    # ================= XGBoost =================
    xgb_proba = xgb_model.predict_proba(X_test_scaled)[:, 1]
    xgb_pred  = (xgb_proba >= 0.5).astype(int)
    def metrics(y_true, y_pred):
        return dict(accuracy=round(accuracy_score(y_true,y_pred),4),
                    precision=round(precision_score(y_true,y_pred,zero_division=0),4),
                    recall=round(recall_score(y_true,y_pred,zero_division=0),4),
                    f1=round(f1_score(y_true,y_pred,zero_division=0),4))
    m_xgb = metrics(y_test, xgb_pred)
    m_xgb['roc_auc'] = round(roc_auc_score(y_test, xgb_proba), 4)
    cm_xgb = confusion_matrix(y_test, xgb_pred)
    blocked = int((xgb_proba >= BLOCK_TH).sum())
    print(f"\n[XGBoost] {m_xgb}")
    print(f"[XGBoost] số mẫu sẽ auto-block (>= {BLOCK_TH}): {blocked:,}")

    # ============ Isolation Forest (alert-only) ============
    # predict: 1=normal, -1=anomaly -> map sang attack(1)/normal(0)
    if_pred = (iforest.predict(X_test_scaled) == -1).astype(int)
    if_anom = -iforest.decision_function(X_test_scaled)   # cao = bất thường
    m_if = metrics(y_test, if_pred)
    print(f"[IForest] {m_if}  (alert-only, không auto-block)")

    # ================= Late-fusion ensemble =================
    if_norm = (if_anom - if_anom.min()) / (if_anom.max() - if_anom.min() + 1e-9)
    fusion = W_XGB * xgb_proba + W_IF * if_norm
    fus_pred = (fusion >= 0.5).astype(int)
    m_fus = metrics(y_test, fus_pred)
    m_fus['roc_auc'] = round(roc_auc_score(y_test, fusion), 4)
    print(f"[Ensemble 0.6/0.4] {m_fus}")

    # ---- lưu metrics.json ----
    out = dict(test_size=len(X_test), xgboost=m_xgb, iforest=m_if,
               ensemble=m_fus, confusion_matrix_xgb=cm_xgb.tolist(),
               auto_block_count=blocked, block_threshold=BLOCK_TH)
    json.dump(out, open('metrics.json','w'), indent=2)
    print("\n[+] Đã lưu metrics.json")

    # ================= CHARTS cho báo cáo =================
    # 1) Confusion matrix
    plt.figure(figsize=(5,4))
    plt.imshow(cm_xgb, cmap='Blues')
    for i in range(2):
        for j in range(2):
            plt.text(j,i,f"{cm_xgb[i,j]:,}",ha='center',va='center',
                     color='white' if cm_xgb[i,j]>cm_xgb.max()/2 else 'black',fontsize=12)
    plt.xticks([0,1],['Benign','Attack']); plt.yticks([0,1],['Benign','Attack'])
    plt.xlabel('Dự đoán'); plt.ylabel('Thực tế'); plt.title('Confusion Matrix — XGBoost')
    plt.colorbar(); plt.tight_layout(); plt.savefig('confusion_matrix_xgb.png',dpi=150); plt.close()

    # 2) ROC curve
    fpr,tpr,_ = roc_curve(y_test, xgb_proba)
    plt.figure(figsize=(5,4))
    plt.plot(fpr,tpr,label=f"XGBoost AUC={m_xgb['roc_auc']}")
    fpr2,tpr2,_ = roc_curve(y_test, fusion)
    plt.plot(fpr2,tpr2,label=f"Ensemble AUC={m_fus['roc_auc']}")
    plt.plot([0,1],[0,1],'k--',alpha=0.4)
    plt.xlabel('False Positive Rate'); plt.ylabel('True Positive Rate')
    plt.title('ROC Curve'); plt.legend(); plt.tight_layout()
    plt.savefig('roc_curve.png',dpi=150); plt.close()

    # 3) Feature importance (top 15)
    imp = xgb_model.feature_importances_
    idx = np.argsort(imp)[-15:]
    plt.figure(figsize=(6,5))
    plt.barh(range(len(idx)), imp[idx])
    plt.yticks(range(len(idx)), [feat[i] for i in idx], fontsize=8)
    plt.xlabel('Importance'); plt.title('Top 15 Feature — XGBoost')
    plt.tight_layout(); plt.savefig('feature_importance.png',dpi=150); plt.close()

    print("[+] Đã lưu 3 chart: confusion_matrix_xgb.png, roc_curve.png, feature_importance.png")
    print("\n[✔] VERIFY XONG. Dùng metrics.json + 3 PNG cho Chương thực nghiệm.")

if __name__ == "__main__":
    main()
