# HANDOFF — Chuẩn bị Web CTF cho F-Hacker 2026 (Bảng C)

> Bàn giao từ phiên Claude (web) sang Claude Code. Hai phiên **không chung session/context**, chỉ chung pool quota. File này + 2 file kèm theo là toàn bộ ngữ cảnh cần thiết để làm tiếp.

## 1. Bối cảnh
- **Cuộc thi:** F-Hacker 2026, Bảng C (sinh viên). Chung kết **29/11/2026**, 08h30–11h30, tại ĐH FPT Cần Thơ.
- **Thể thức:** **Attack-Defense (A/D)**. Mỗi đội 1 service web giống hệt nhau, cùng lỗ hổng, **không được sửa source**. Vừa tấn công đội khác lấy cờ (ATK), vừa phòng thủ bằng **WAF rule** (DEF), vừa giữ service sống cho bot healthcheck mỗi 30s (SVC). 10 round, mỗi round service reset + cờ mới.
- **Luật quan trọng:**
  - **Cấm Internet và AI hoàn toàn trong giờ thi** (kể cả AI local). Chỉ được mang tài liệu/công cụ/exploit **tải sẵn offline**.
  - Flag format: `FHACKER2026{64 hex}`.
  - Nộp tối đa **30 lần/phút** (vượt bị 429 + coi là vi phạm).
  - WAF: chặn theo payload, KHÔNG chặn theo IP, không deny-all, không chặn API phục vụ cờ. Chặn nhầm API có bug bị trừ SVC gấp đôi.
  - Repo luyện WAF của BTC: `github.com/f-hacker-macos/2026-waf-practice` (`make up`; app qua WAF cổng 8000, UI WAF cổng 8005).

## 2. Mục tiêu người dùng
Soạn **bài giảng/tài liệu tra cứu offline** mang vào phòng thi (vừa học vừa giải). Trình độ: mới nhập môn web CTF, Python cơ bản, chưa rành thư viện/exploit script. Thời gian gấp → ưu tiên thực dụng.

## 3. Trạng thái hiện tại (đã làm xong)
- **`web-ctf-vuln-map.md`** (kèm theo): bản đồ 16 mục phủ gần hết các lớp lỗ hổng web CTF + phần riêng cho A/D. Đây là bản markdown của tài liệu đã soạn trên Claude web (link gốc: https://claude.ai/artifact/59kZ1Gh5zodtcsEGZUHpAW — nhưng Claude Code không mở được Claude Doc, nên dùng file md này).
- **`survey_web_ctf.py`** (kèm theo): script quét offline repo `sajjadium/ctf-archives`, grep dấu hiệu từng nhóm lỗ hổng trong source của mọi folder `web/`, in bảng tần suất thực tế.

## 4. Phát hiện & quyết định chính (đã chốt)
- **Gần như mọi exploit web = gửi HTTP request.** Phần Python chỉ vài "khung" (~10), thứ đổi theo lỗ hổng là **payload**. Khung cần: GET/POST, Session+login, trích giá trị bằng regex, brute-force, blind từng ký tự, race (threads), gửi URL cho bot, listener nhận flag, JWT/base64/hash, request thô (socket).
- **Xu hướng web CTF 2024–2026:** nổi bật nhất là khai thác **theo CVE của framework + version** (nhận diện version → tra CVE → chạy PoC). Cụ thể hay gặp: PHP filter chain → RCE ("php2shell", công cụ Synacktiv `php_filter_chain_generator`); CVE-2024-2961 (glibc iconv) LFI→RCE; React2Shell = CVE-2025-55182 (RSC deserialization RCE); Next.js middleware bypass CVE-2025-29927; Next.js SSRF CVE-2024-34351 / CVE-2025-57822.
- **Khảo sát tần suất (mẫu ~35 writeup giải lớn, LỆCH về giải khó):** XSS+admin bot áp đảo (~½ bài) > prototype pollution > SSRF (nhiều qua Next.js) > LFI→RCE (filter chain) > file upload RCE > CVE framework > deserialization > SQLi > IDOR.
- **Cảnh báo cho Bảng C:** mẫu trên lệch về giải khó/quốc tế. Giải sinh viên/dễ thiên về **server-side cơ bản**: SQLi, LFI, upload, command injection, IDOR, auth yếu. → **Ưu tiên luyện mục 1 (injection), 3 (file/LFI/upload), 8 (access control) trước.**
- **Cách đếm tag CTFtime KHÔNG chạy được** (~95% challenge web chỉ tag `web`, không có tag kỹ thuật). Muốn thống kê kỹ thuật thật phải đọc source → dùng `survey_web_ctf.py`.

## 5. Việc cần làm tiếp (TODO cho Claude Code)
Theo thứ tự ưu tiên:
1. ~~**Chạy `survey_web_ctf.py`**~~ ✅ XONG (27/11/2026). Dùng partial clone + sparse-checkout
   để quét toàn bộ `sajjadium/ctf-archives` (1247 challenge web, 194 giải) thay vì mẫu ~35 bài.
   Đã tách riêng nhóm dễ/sinh viên (35 giải, 224 bài) vs nhóm khó/elite (28 giải, 273 bài) để
   so sánh. Kết quả chi tiết + diễn giải: xem **`survey-results.md`**. Kết luận: xác nhận lại
   ưu tiên ôn luyện SQLi/LFI/upload/SSTI(Flask)/command injection/JWT cho Bảng C; XSS+bot,
   Next.js CVE chain, prototype pollution là đặc trưng của giải khó/quốc tế, ít khả năng gặp
   ở Bảng C.
2. **Dựng bộ khung script `requests`** (~10 khung ở mục 4) — mỗi khung 1 file mẫu, chạy lại được, nhận host/IP làm tham số. Gồm cả: script exploit tái sử dụng (lặp qua các đội, trích flag bằng regex `FHACKER2026\{[0-9a-f]{64}\}`) và **script nộp flag có throttle ≤30/phút**.
3. **Thêm vào mỗi mục của `web-ctf-vuln-map.md`:** (a) 1–2 payload mẫu đầy đủ, (b) khung script tương ứng, (c) 1 regex WAF rule phòng thủ.
4. **Tải sẵn offline:** PayloadsAllTheThings, HackTricks (bản offline), exploit-db, `php_filter_chain_generator`, nuclei templates, jwt_tool, gittools. (Vì phòng thi cấm Internet.)
5. **Luyện WAF** tại repo BTC `f-hacker-macos/2026-waf-practice`.

## 6. Lưu ý đạo đức/phạm vi
Đây là **chuẩn bị hợp lệ** cho một cuộc thi CTF được cấp phép (luật cho mang tài liệu/exploit tải sẵn). Mọi script/payload chỉ dùng trên service do BTC cấp, trong giờ thi, chỉ lấy flag — KHÔNG phá service đội khác, KHÔNG DoS, KHÔNG tấn công hạ tầng BTC/đội khác (vi phạm luật Điều 6). Không dùng để tấn công hệ thống ngoài phạm vi thi.

## 7. File trong bộ handoff
- `HANDOFF.md` — file này.
- `web-ctf-vuln-map.md` — tài liệu tra cứu 16 mục (nội dung chính).
- `survey_web_ctf.py` — script khảo sát tần suất offline.
- `survey-results.md` — kết quả chạy survey trên toàn bộ dataset + so sánh dễ/khó (mục 5.1 đã xong).
