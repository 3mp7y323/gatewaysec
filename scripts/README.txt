serve_ai_engine.py  — AI engine deploy (Eq.1: block p_xgb>=0.9; suspicious fused 0.6/0.4>=0.5). Khop Appendix C.
train_ids_models.py — train XGBoost + IsolationForest, xuat 4 artifact.
verify_models.py    — tai lap metrics.json + chart tu 4 artifact + CICIDS2017.
harness.py          — ban payload qua gateway, emit per_payload_results.csv + Wilson CI (Table 2).
test_predict.py     — smoke test engine.
requirements.txt    — da pin scikit-learn==1.9.0 (ban luc train .pkl).
