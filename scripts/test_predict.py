"""
test_predict.py — Bắn vài record từ dataset vào AI Engine để kiểm tra.
Cần: cicids2017_combined.csv (hoặc sửa path) + AI Engine đang chạy ở :8000.
  python test_predict.py
"""
import pandas as pd, numpy as np, json, requests

DATA = "./cicids2017_combined.csv"
API  = "http://127.0.0.1:8000/predict"
N    = 5   # số record gửi thử

feat = json.load(open("./models/feature_list.json"))
df = pd.read_csv(DATA, low_memory=False, nrows=20000)
df.columns = df.columns.str.strip()
df = df[df['Destination Port'] != 'Destination Port']
# lấy vài dòng attack + benign cho dễ thấy
df['Label_Binary'] = df['Label'].apply(lambda x: 0 if x=='BENIGN' else 1)
sample = pd.concat([df[df.Label_Binary==1].head(N), df[df.Label_Binary==0].head(N)])

records = []
for _, row in sample.iterrows():
    fv = {}
    for f in feat:
        v = pd.to_numeric(row[f], errors='coerce')
        fv[f] = 0.0 if pd.isna(v) or np.isinf(v) else float(v)
    records.append({"features": fv, "src_ip": f"10.0.0.{np.random.randint(2,254)}"})

resp = requests.post(API, json={"records": records})
print(json.dumps(resp.json(), indent=2, ensure_ascii=False))
