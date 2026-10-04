import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import json
import gc
import os

def reduce_mem_usage(df):
    """Ép kiểu dữ liệu để bóp dung lượng RAM an toàn"""
    import pandas as pd
    import numpy as np
    
    for col in df.columns:
        # Kiểm tra xem cột có phải là kiểu số không (bỏ qua cột Label chứa text)
        if pd.api.types.is_numeric_dtype(df[col]):
            col_type = df[col].dtype
            c_min = df[col].min()
            c_max = df[col].max()
            
            if str(col_type)[:3] == 'int':
                if c_min > np.iinfo(np.int32).min and c_max < np.iinfo(np.int32).max:
                    df[col] = df[col].astype(np.int32)
            else:
                if c_min > np.finfo(np.float32).min and c_max < np.finfo(np.float32).max:
                    df[col] = df[col].astype(np.float32)
    return df

def clean_data(df):
    """Xử lý lỗi kinh điển của CICIDS2017"""
    # 1. Strip khoảng trắng ở tên cột
    df.columns = df.columns.str.strip()
    
    # 2. Xóa các dòng header lặp lại giữa data
    df = df[df['Destination Port'] != 'Destination Port']
    
    # 3. Ép kiểu cột Label, các cột khác về numeric
    label_col = df['Label']
    features = df.drop(columns=['Label'])
    features = features.apply(pd.to_numeric, errors='coerce')
    features['Label'] = label_col
    df = features
    
    # 4. Xử lý giá trị Inf -> NaN -> Drop
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    return df

def main():
    print("[+] Bắt đầu load dataset CICIDS2017...")
    # SỬA ĐƯỜNG DẪN NÀY ĐẾN FILE CSV CỦA MÀY
    data_path = './cicids2017_combined.csv' 
    
    # Đọc data & Ép kiểu ngay lập tức
    df = pd.read_csv(data_path, low_memory=False)
    df = clean_data(df)
    df = reduce_mem_usage(df)
    
    # Gom nhóm nhãn: 'BENIGN' là 0, Attack là 1
    df['Label_Binary'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    
    # Tách Features và Target
    X = df.drop(columns=['Label', 'Label_Binary'])
    y = df['Label_Binary']
    
    # Xuất danh sách 78 features để Thiện align lúc inference
    feature_list = X.columns.tolist()
    with open('feature_list.json', 'w') as f:
        json.dump(feature_list, f)
    print(f"[+] Đã lưu feature_list.json ({len(feature_list)} features)")
    
    # Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Dọn RAM
    del df, X, y
    gc.collect()

    # Chuẩn hóa dữ liệu (BẮT BUỘC lưu scaler)
    print("[+] Đang fit StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    joblib.dump(scaler, 'scaler.pkl')
    print("[+] Đã xuất scaler.pkl")
    
    # ==========================================
    # 1. TRAIN XGBOOST (Supervised)
    # ==========================================
    print("[+] Đang train XGBoost trên GPU...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        tree_method='hist',
        device='cuda',
        random_state=42
    )
    xgb_model.fit(X_train_scaled, y_train)
    
    xgb_model.save_model('xgboost_model.json')
    print("[+] Đã xuất xgboost_model.json")
    
    # ==========================================
    # 2. TRAIN ISOLATION FOREST (Unsupervised)
    # ==========================================
    print("[+] Đang chuẩn bị data cho Isolation Forest...")
    # Lọc riêng tập Benign từ tập train để dạy model hành vi "bình thường"
    X_train_benign = X_train_scaled[y_train == 0]
    
    # Subsample 500k dòng để không nổ RAM
    if len(X_train_benign) > 500000:
        idx = np.random.choice(len(X_train_benign), 500000, replace=False)
        X_train_benign_sub = X_train_benign[idx]
    else:
        X_train_benign_sub = X_train_benign
        
    print(f"[+] Bắt đầu train Isolation Forest với {len(X_train_benign_sub)} mẫu (CPU, n_jobs=-1)...")
    iforest_model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        n_jobs=-1,
        random_state=42
    )
    iforest_model.fit(X_train_benign_sub)
    
    joblib.dump(iforest_model, 'iforest_model.pkl')
    print("[+] Đã xuất iforest_model.pkl")
    
    print("\n[✔] HOÀN TẤT! Copy 4 file artifact (xgboost_model.json, iforest_model.pkl, scaler.pkl, feature_list.json) qua cho máy Thiện.")

if __name__ == "__main__":
    main()