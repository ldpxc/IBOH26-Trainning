# WebSocket (không phải request/response HTTP thường)

Một số app dùng WebSocket (chat, bảng điểm live, game) — trong Burp bạn thấy không phải tab Repeater bình thường mà là tab **WebSocket history**, chỉ có 1 kết nối mở, gửi/nhận nhiều "message" qua lại, không phải 1 request = 1 response như HTTP.

`requests` **không** gửi được WebSocket. Cần thư viện riêng:

```bash
pip install websocket-client
```

## Snippet copy-là-chạy

```python
import json
import websocket   # từ package websocket-client, import tên là "websocket"

base_ws = "ws://10.0.2.1:8000/ws"   # đổi http(s):// thành ws(s):// -- xem URL trong Burp WS history

def solve_one(base_url_ws):
    ws = websocket.create_connection(base_url_ws, timeout=5)
    try:
        # 1) Gửi message mở đầu, đúng format bạn thấy trong Burp (thường là JSON)
        ws.send(json.dumps({"action": "join", "room": "general"}))

        # 2) Nhận message trả lời -- có thể phải nhận vài lần mới tới message cần
        for _ in range(10):
            msg = ws.recv()
            data = json.loads(msg)
            if data.get("type") == "flag":
                return data.get("value")
        return None
    finally:
        ws.close()   # luôn đóng kết nối, giống việc đóng tab WS trong Burp
```

## Giải thích cho người mới
- `websocket.create_connection(url)` mở 1 kết nối WebSocket, tương đương việc Burp tự giữ 1 kênh mở trong tab WS history — không có "Session()" kiểu `requests`, cookie login (nếu cần) phải lấy từ 1 request HTTP thường trước, rồi truyền vào `header=[f"Cookie: {cookie}"]` khi `create_connection`.
- `ws.send(...)` gửi 1 message lên server; `ws.recv()` chờ nhận 1 message (chặn luồng tới khi có dữ liệu hoặc hết timeout) — khác HTTP là **1 lần gửi có thể cần nhận nhiều message** mới ra được cái bạn cần, vì server có thể gửi nhiều message độc lập (ví dụ thông báo hệ thống trước, rồi mới tới message thật).
- Luôn giới hạn số lần `recv()` (`for _ in range(10)`) — đừng `while True` không có điều kiện dừng, kết nối WS có thể treo vô hạn nếu server không gửi gì thêm.
- Nếu cần cookie/token để kết nối WS (xem Burp WS history có header `Cookie` không):
  ```python
  ws = websocket.create_connection(
      base_url_ws,
      header=[f"Cookie: session={cookie_value}"],
      timeout=5,
  )
  ```
- Debug qua Burp: Burp Suite (bản có hỗ trợ WS) hiển thị message dạng text trong tab WebSocket history — copy đúng format JSON/text đó vào `ws.send(...)`, so message nhận được với tab đó khi sai.

## Lưu ý nhanh
- Không dùng `requests` cho WS — khác thư viện, khác cách gọi hoàn toàn.
- `ws://` cho HTTP thường, `wss://` cho HTTPS (giống `http`/`https`).
- Nếu không chắc app có dùng WS không: mở DevTools (F12) tab Network, lọc "WS", hoặc xem Burp có tab WebSocket history không.
