XAI (LLM-assisted alert explanation) — out-of-band, KHONG tham gia quyet dinh block.
custom-ollama — Wazuh integration (integratord goi khi alert level >= nguong o ossec.conf).
  Doc alert -> build prompt tieng Viet + RAG tu mitre_kb.json -> goi Qwen2.5:3b @ node XAI -> ghi
  giai thich nguoc vao Wazuh Dashboard. Wazuh goi file dung ten "custom-ollama" (khong .py).
  ĐÃ genericize IP node XAI -> 192.0.2.88 (sua ve IP that cua ban). temp 0.3, num_predict 400, dedup 600s.
mitre_kb.json — RAG knowledge base (7 technique: T1046/T1190/T1110/T1059/T1595/T1498 + DEFAULT).
  Ground Qwen theo dinh nghia MITRE co san -> chong hallucinate technique ID.
