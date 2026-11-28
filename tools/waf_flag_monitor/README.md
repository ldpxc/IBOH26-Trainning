# WAF Flag Leak Monitor

> 📋 **Đi thi quên quy trình?** Xem [`CHECKLIST_THI_THAT.md`](CHECKLIST_THI_THAT.md) — checklist đẩy rule lên WAF + chạy exploit script, không cần đọc lại hết README.
> 🛡️ **Chưa biết app thật, muốn phòng trước?** Add [`baseline_ruleset_pass.conf`](baseline_ruleset_pass.conf) từ đầu giải — xem [`CHECKLIST_VAN_HANH_BASELINE.md`](CHECKLIST_VAN_HANH_BASELINE.md).

Công cụ giám sát traffic log realtime từ BunkerWeb WAF và cảnh báo ngay lập tức trên WebUI khi phát hiện response chứa flag theo mẫu `FHACKER2026{<64hex>}` (kiểm tra cả **Response Headers** lẫn **Response Body** đã tự động decode base64 + giải nén gzip/deflate).

## Chạy nhanh

```bash
python3 tools/waf_flag_monitor/app.py
```

Mặc định:
- WebUI: `http://127.0.0.1:9555`
- Target WAF: `http://localhost:9110` (`admin` / `ChangeMe_Bw_2026!`)

## Tùy chọn CLI

```bash
# Đổi cổng WebUI hoặc target WAF
python3 tools/waf_flag_monitor/app.py --port 9555 --waf-url http://localhost:9100 --user admin --password 'ChangeMe_Bw_2026!'

# Dùng chế độ Docker Tail (đọc trực tiếp /var/log/bunkerweb/traffic.log, độ trễ <10ms khi traffic rất lớn)
python3 tools/waf_flag_monitor/app.py --mode docker --container b_notevault-fuap_bunkerweb-1
```

## Tính năng WebUI
- **Realtime SSE Alert**: tự động đẩy cảnh báo ngay khi có response mới chứa flag, kèm âm thanh cảnh báo (Web Audio) và Desktop Notification.
- **Inspect Request & Response**: hiển thị đầy đủ HTTP Request/Response (đã giải nén gzip), highlight chính xác vị trí flag, nút `Jump to Flag`, `Copy cURL`, `Copy Raw`.
- **ModSecurity Hits**: hiển thị các rule ID đã trigger (hoặc báo `0 hits` để biết request đã lọt qua WAF).
- **Scan Recent (100)**: quét lại 100 request gần nhất trong log khi cần kiểm tra các exploit vừa xảy ra trước lúc bật tool.
