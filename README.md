# GatewaySec — Reproducibility Artifact

Artifacts for the paper *GatewaySec: Measuring What an Open-Source Inline Gateway Stops and Misses in Web Application Defense* (Nguyen Minh Thien, Duong Quang Tan; FPT University, Can Tho).

> **Scope of reproduction.** The virtual-machine testbed was decommissioned. This archive supports **offline reproduction of the machine-learning results (Table 3)** and **review of the request-path configuration**. It does **not** support live end-to-end replay, which requires rebuilding the testbed. We state this openly rather than imply full replay.

## What's here
| Folder | Contents | Reproduces |
|---|---|---|
| `models/` | `xgboost_model.json`, `iforest_model.pkl`, `scaler.pkl`, `feature_list.json` (78 features) | model scoring |
| `scripts/` | `train_ids_models.py`, `verify_models.py`, `serve_ai_engine.py`, `harness.py` | training, offline metrics, serving, payload injection |
| `config/` | sanitized gateway configuration (iptables, Suricata, ModSecurity/CRS, keepalived, Wazuh rules, `gwsec-drop`) | request-path review |
| `payloads/` | `manifest.csv` (payload index) + `per_payload_results.csv` (per-payload 403 outcome) | §5.1 blocking rates |
| `results/` | `metrics.json` + figures | Table 3 |
| `docs/` | paper PDF, notes | — |
| `xai/` | `custom-ollama` (Wazuh integration), `mitre_kb.json` (RAG KB) | LLM-assisted explanation (out-of-band; no block decision) |

> Latency (median of 20 requests, matching the paper) is measured by `scripts/gwsec_dr_test.sh`; `harness.py` covers blocking rate + Wilson CI only.

## Reproduce the ML results
```
pip install -r scripts/requirements.txt
# place CICIDS2017 combined CSV as cicids2017_combined.csv (public dataset, not redistributed here)
python scripts/verify_models.py
```
Expected: `metrics.json` with XGBoost F1 ≈ 0.9972 on the 565,576-flow test split (80/20, random_state=42, stratified). Dataset: CICIDS2017 (Sharafaldin et al., 2018) — obtain from the Canadian Institute for Cybersecurity; not included here.

## Data & payloads
- Attack payloads come from public lists (**SecLists, PayloadBox, html5sec**). We ship a **manifest** (source + hash + class) and the **per-payload 403 outcome**, not re-hosted copies beyond what the licenses allow.
- **Third-party application sources are NOT included.** The five tested applications are other students' course projects, used with permission arranged by our supervisor and anonymized as Apps A–E. They are not redistributed.

## Notes on honesty / limits
- Synthetic test addresses (the 5.x–9.x placeholder range used in testing) are removed from all shipped logs.
- Offline F1 is optimistic (CICIDS2017 known flow-construction/labelling issues; split not session-disjoint).
- The flow classifier does not inspect HTTP bodies and takes no part in payload blocking.

## Cite
See `CITATION.cff`. Zenodo DOI: `10.5281/zenodo.23140652`.

## Before publishing
Run `python scrub.py` (report mode) and resolve every FOUND; review WARN (private IPs, onrender URLs) by hand. Only push when clean.

## License
Code and configuration: MIT (see `LICENSE`). Model artifacts provided for research. Third-party payloads and application sources retain their original licenses and are not relicensed here.
