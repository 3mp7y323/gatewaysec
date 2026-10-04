GatewaySec_config_sanitized.md — config dump (iptables, Suricata, ModSecurity/CRS, keepalived,
  Wazuh rules 100400/100401/100300-312, gwsec-drop, HA). ĐÃ redact khoá nhạy cảm (VRRP auth_pass, ZeroTier NWID, MAC)
  và genericize IP nội bộ + path/tên về placeholder (dải tài liệu RFC5737). Không chứa khoá nhạy cảm nào.
ai-engine.service — systemd unit (trỏ serve_ai_engine.py), path đã genericize.
