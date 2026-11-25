# Snippet LOG ATTACKER — vá vào `app.py` để xem đối thủ gửi gì

> Dùng khi **không root / không tcpdump** trên vulnbox (TOOLKIT.md mục 5.1b).
> Rẻ nhất: gần 0 RAM/đĩa, không cần binary. Thấy **chính xác payload attacker gửi**.
> Nhớ: đây là một **patch** → sửa xong `supervisorctl restart svc` và test SLA.

---

## 1) Web app (Flask) — log mỗi request

```python
import logging
logging.basicConfig(filename='/tmp/att.log', level=logging.INFO)

@app.before_request
def _log_req(e=None):
    from flask import request
    body = request.get_data()[:2000]           # tối đa 2KB, tránh phình
    logging.info("%s %s %s | hdr=%s | body=%r",
                 request.remote_addr, request.method, request.full_path,
                 dict(request.headers), body)
```
Xem: `tail -f /tmp/att.log`  ·  tìm RCE: `grep -iE "flag|/bin|cat|;|\\||\\$\\(" /tmp/att.log`

---

## 2) Dịch vụ socket thuần (pwn/TCP) — log data đọc vào

Tìm chỗ `data = conn.recv(...)` / `req = sock.recv(...)` rồi chèn NGAY SAU:
```python
open('/tmp/att.log','ab').write(
    b"%b | %r\n" % (conn.getpeername()[0].encode(), data[:2000]))
```
(Đổi `conn`/`data` cho khớp tên biến trong code.)

---

## 3) Đẩy THẲNG về laptop (không ghi đĩa vulnbox) — qua fileshare

```python
import requests   # hoặc dùng socket thuần nếu box thiếu requests
try:
    requests.put("http://<IP_VPN_BAN>:8000/u/att_<svc>.log",
                 params={"t": "<TOKEN_GHI>"}, data=data[:2000], timeout=1)
except Exception:
    pass          # KHÔNG để log làm chết service
```
> ⚠️ Dùng **TOKEN GHI** → nếu box bị chiếm, token lộ (ps/history). Nếu lo, ghi `/tmp/att.log`
> rồi kéo về bằng SSH (TOOLKIT.md mục 4-B), đừng nhúng token ghi vào app.

---

## 4) Chống phình đĩa (256MB) — xoay vòng log

```python
import os
if os.path.exists('/tmp/att.log') and os.path.getsize('/tmp/att.log') > 5_000_000:
    os.replace('/tmp/att.log', '/tmp/att.log.1')   # giữ tối đa ~10MB (2 file)
```

---

## Đọc nhanh — "họ làm gì"
```bash
grep -iE "flag|BOH26_|/bin/sh|cat |/flag|\\bid\\b|curl|wget|;|\\||\\$\\(" /tmp/att.log
#  payload lặp lại nhiều IP khác nhau = exploit chung → ĂN CẮP: gửi lại chính payload đó
#  tới ${hostname}:${port} trong ad-attack-console (Target VPN) → bắn mọi đội.
```

**BẮT BUỘC:** `try/except` quanh mọi dòng log — log KHÔNG được làm service chết (mất SLA).
