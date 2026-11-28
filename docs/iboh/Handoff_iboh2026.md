# Bàn giao: Luyện tập IBOH 2026 Attack-Defense

> File này tóm tắt toàn bộ bối cảnh và các quyết định đã chốt trong một phiên tư vấn,
> để chuyển giao cho Claude Code tiếp tục làm việc mà không cần mô tả lại từ đầu.
> Ngày lập: 2026-10-28.

## 1. Bối cảnh

- Đội gồm **3 người**, chuẩn bị thi **IBOH 2026 Stage 2 (Attack & Defense)** do APU (Malaysia) tổ chức.
- Trình độ hiện tại (**ĐÃ ĐÍNH CHÍNH 2026-10-28**): cả đội **đã chơi AD ở IBOH 2025**, một thành viên còn chơi AD giải khác năm ngoái.
  Nền jeopardy lâu năm ở cả 4 mảng nhưng **rỉ sét vì lâu không luyện** → cần mài lại phản xạ, không học từ đầu.
  Lộ trình hiện hành: xem `Roadmap_iboh2026.md` (thay thế mục 8 bên dưới).
- ~~chưa từng chơi Attack-Defense, nền yếu cả 4 mảng~~ (mô tả cũ, sai).
- Thời gian luyện: từ **28/10 đến hết 10/11**, thi khoảng **11/11**. Tức ~15 ngày.
- Cường độ: chốt **trung bình 7h/ngày**. Mạng nối bằng **Tailscale**. pwn/rev: **chỉ có binary, không source** (xác nhận từ IBOH 2025).
- Đội sẽ dùng AI hỗ trợ trong lúc luyện để tăng tốc phần học kiến thức, và ghi lại thành cheatsheet.

## 2. Format IBOH (ĐÃ XÁC NHẬN bằng briefing chính thức "BOH AD Briefing.pdf" — xem chi tiết ở `Roadmap_iboh2026.md` mục 7)

> Mục này trước đây dựa trên trí nhớ và nhiều chỗ SAI. Nay thay bằng facts từ briefing chính thức IBOH 2025.

- Mỗi đội nhận một **máy Linux** qua **OpenVPN**. 5 đội, IP `10.10.<team>.10`. Venue có thể chặn VPN → mang mobile data.
- Thời lượng **6 giờ**, **mỗi tick = 5 PHÚT** (KHÔNG phải 30 giây). Flag đổi mỗi tick, **sống 5 tick** (~25 phút).
- **White box** (có source, `/home/player/challengeN/`): vá được TRƯỚC khi bị pwn.
  **Black box** (không source, `/home/challengeN/`): **KHÔNG vá được cho tới khi tự pwn nó**.
- **Chỉ vá được code ứng dụng/binary** (vd `app.py`); **`Dockerfile`/`docker-compose.yml` KHÔNG vá được.**
- `restart_docker.sh` **cooldown 10 phút** → vá hỏng = chết dịch vụ ≥10 phút. Flag ở `/home/user/flag.txt`.
- Nộp flag: `nc gameserver 6666`, chỉ tính từ máy đội mình. Điểm: SLA (động) + Attack **+2**/flag + Defence **−1**/lần bị nộp.

Ba điểm đã được đội XÁC NHẬN (cập nhật 2026-10-28):

1. **Luật cho làm mọi thứ theo hướng CTF**, chỉ cấm tấn công hạ tầng một cách tiêu cực.
   → Được **sửa/vá binary thoải mái**.
2. Dịch vụ chạy **cả trên Docker lẫn trực tiếp trên server** (giả định cũ).
   → **SỬA theo briefing:** challenge đóng gói kiểu Docker (mỗi thư mục có `Dockerfile` + `docker-compose.yml`), và
   **`Dockerfile`/`compose` KHÔNG vá được** — chỉ vá code/binary. Nên luyện **chủ yếu kiểu Docker + chỉ vá app/binary**,
   bỏ kịch bản "chạy trực tiếp" làm trọng tâm. `restart_docker.sh` có cooldown 10 phút → test offline rồi deploy một lần.
3. **Được tải challenge về máy cá nhân, giải quyết rồi đưa kết quả lên vulnbox.**
   → KHÔNG cần lo vulnbox thiếu công cụ. Vá binary / phân tích có thể làm trên máy cá nhân (Ghidra, pwntools...) rồi đẩy binary đã vá lên.

## 3. Chiến lược đã chốt

- **Ưu tiên phòng thủ.** Tỉ lệ công sức: **~70% phòng thủ / ~30% tấn công**.
- Phòng thủ = giữ dịch vụ sống (điểm SLA/uptime cộng tự động mỗi tick) + vá lỗi mà
  **không làm chết dịch vụ**. Đây là nguồn điểm ổn định nhất cho đội mới.
- Tấn công = Do đội có nền CTF jeopardy nhưng đã lâu không luyện nên là sẽ thiết kế kế hoạch để luyện lại là exploit được, đồng thời cũng nên **replay** (bắt payload đội khác đánh mình, bắn lại, không cần hiểu lỗi)
- Nguyên tắc luyện xuyên suốt: mỗi lỗ hổng học xong phải làm đủ 2 bước —
  (1) khai thác được để thấy lỗi thật, (2) **vá lại + kiểm tra dịch vụ vẫn chạy**. Bước 2 mới là kỹ năng thi.

## 4. Phân vai 3 người (P1/P2/P3)

| Vai | Tên gọi          | Chuyên môn                               | Trách nhiệm trong trận                                                                |
| --- | ---------------- | ---------------------------------------- | ------------------------------------------------------------------------------------- |
| P1  | Deploy & Uptime  | Docker, Linux, mạng, pwn/rev (vá binary) | Giữ dịch vụ sống, deploy, restart, backup, rollback, theo dõi health-check, vá binary |
| P2  | Patch & Web      | Web, đọc source, vá lỗi                  | Mũi tấn công web chính, đọc dịch vụ tìm lỗ, vá web/crypto không làm chết dịch vụ      |
| P3  | Monitor & Replay | Crypto, script Python, phân tích traffic | Bắt gói tin phát hiện bị tấn công, replay, vận hành exploit farm nộp flag tự động     |

- **P1 là người host hệ thống luyện tập** (trùng chuyên môn hạ tầng).
- Rev là mảng khó và ít điểm nhất → P1 và P2 chia nhau khi cần, không ai ôm riêng.

## 5. Nền tảng mô phỏng Attack-Defense đã chọn

Kết luận quan trọng: **KHÔNG có repo nào làm trọn gói**. Phải ghép 3 phần.

### 5.1. Trọng tài / gameserver: ForcAD

- Repo: `github.com/pomo-mondreganto/ForcAD` (pure-Python, dựng bằng Docker Compose).
- Làm đúng mô hình IBOH: tick, checker, flag đổi mỗi vòng, scoreboard, nhận flag.
- Khớp với yêu cầu: **`round_time: 300` (tick 5 phút — sửa từ 30s sai cũ)**, `flag_lifetime: 5` vòng,
  khai từng đội với IP trong `config.yml`, lấy token bằng `./control.py print_tokens`.
- Dựng: sửa `config.yml` → `./control.py setup` → `./control.py start`.
  Scoreboard ở localhost:8080.
- **Chưa xác nhận**: port và giao thức nộp flag bằng netcat (README không ghi rõ;
  cần kiểm tra wiki hoặc source, rồi thử bằng `nc` thật trước khi dựa vào).
- ForcAD KHÔNG chứa lỗ hổng, KHÔNG lo VPN, KHÔNG lo vulnbox — những phần đó tự dựng.

### 5.2. Service để luyện (tự gom)

- Service tương thích ForcAD có sẵn trên GitHub (từ khoá "ForcAD service", "attack-defense service").
- Service của giải A-D cũ: **ENOWARS, saarCTF, FAUST** (công bố sau giải, nhiều ngôn ngữ, có checker,
  nhưng checker khác chuẩn ForcAD nên cần lớp chuyển đổi; link cụ thể CHƯA xác minh được, phải tải thử).
- Hoặc tự đóng gói lại một challenge Jeopardy cũ thành dịch vụ có lưu/đọc flag.
- Với pwn/rev: sau khi build image thì **xoá source, chỉ để binary** để mô phỏng đúng điều kiện IBOH.

### 5.3. Về DVWA

- `github.com/digininja/DVWA` — chỉ là app web lỗi để học 1 người, **KHÔNG có cơ chế A-D**
  (không tick, không flag, không checker, không đa đội), và **chỉ có web**.
- Vai trò: chỉ dùng **tuần 1** cho P2 học vỡ lòng lỗ hổng web. **Không thay được ForcAD.**
- Có thể bỏ hẳn nếu muốn học web trực tiếp trên service thật.

## 6. Kiến trúc hệ thống luyện tập cần dựng (tuần 2)

```
Máy P1 (host)
├─ ForcAD (trọng tài, scoreboard, nhận flag)
├─ OpenVPN/WireGuard server  →  mạng ảo chung
└─ (có thể) vulnbox của P1

Mỗi người = 1 vulnbox (máy Linux, có SSH + Docker) chạy các challenge giống nhau
```

- Người chơi kết nối VPN → SSH vào vulnbox của mình → vá & test. Từ đó tấn công IP đội khác, nộp flag về ForcAD.
- **Dịch vụ chạy cả trên Docker lẫn trực tiếp trên server** (theo mục 2). Khi dựng service để luyện, nên làm ~80% kiểu Docker
  và ~20% kiểu chạy trực tiếp (systemd/process thường) để đội quen cả hai cách restart/rollback.
- 3 người ngồi chung LAN: dùng IP nội bộ. Ở xa: dùng **Tailscale** (dễ nhất) hoặc WireGuard.
- Mỗi vulnbox chỉ cấp SSH cho đúng 1 người (tách khoá) để không ai vào máy đội khác.

### Yêu cầu phần cứng (ước tính)

- **Máy host (P1)**: ForcAD (~3-4GB) + 1 vulnbox (~2-3GB) + OS/công cụ (~4-6GB)
  → **tối thiểu 12GB RAM, khuyên 16GB**. CPU ≥ 4 nhân. SSD trống 30-50GB.
- **Máy đồng đội**: 8GB chạy được, 16GB thoải mái (khi mở Burp/Ghidra).
- Số RAM thật phụ thuộc service cắm vào → sau khi dựng chạy `docker stats` để đo.

### Phần khó nhất: checker

- Mỗi challenge cần một checker để ForcAD đặt flag + kiểm tra dịch vụ sống.
- Challenge Jeopardy thường không có chỗ "lưu/lấy flag" → checker làm 2 việc:
  đặt flag vào nơi lỗ hổng đọc được (file/DB), và kiểm tra sống bằng cách gọi chức năng bình thường.
- Ưu tiên viết checker cho web/TCP có chức năng rõ ràng trước (dễ). Pwn binary: checker chỉ gửi input hợp lệ và kiểm phản hồi.

## 7. Phòng thủ pwn/rev khi KHÔNG có source (phần khó nhất)

4 lớp, từ dễ đến khó:

1. **Gia cố môi trường** (không sửa binary): chạy bằng user thường, phân quyền file flag tối thiểu,
   container `read_only` + `cap_drop: [ALL]` + `no-new-privileges` + giới hạn CPU/RAM, bọc `socat`/`xinetd` có timeout.
2. **Proxy chặn ở tầng mạng**: proxy TCP Python trước binary, cắt input dài bất thường, chặn chuỗi nguy hiểm
   (`%n`, `%x%x`...), log traffic. Rủi ro: chặn nhầm checker → mất SLA. Mỗi rule phải test với checker trước khi bật.
3. **Vá binary trực tiếp** (đáng luyện nhất): Ghidra tìm hàm nguy hiểm (`gets`, `strcpy`, `sprintf`, `read` quá cỡ,
   `printf(buf)`) + `checksec`; xác nhận bằng pwntools `cyclic`; vá tối thiểu giữ nguyên kích thước/địa chỉ
   (sửa hằng số `read`, đổi `printf(buf)` an toàn, NOP đoạn nguy hiểm, hoặc code cave);
   test lại exploit + chạy bình thường; luôn giữ backup để rollback.
4. **Học từ traffic**: payload đội khác đánh mình chỉ ra chính xác lỗi ở hàm nào → vá đúng chỗ + replay.

Rev trong A-D thường là protocol/logic bị che, không phải lỗ hổng → chỉ cần hiểu đủ để biết chỗ nên vá, không dịch ngược toàn bộ.

Kỳ vọng thực tế: trong 15 ngày khó vá được mọi loại binary. Mục tiêu hợp lý: vá được **stack overflow + format string cơ bản**,
còn lại dựa vào lớp 1, 2, 4 cầm cự. P1 phụ trách phần này, bắt đầu sớm.

**Cập nhật theo luật đã xác nhận (mục 2):** vì luật CHO vá binary và CHO tải binary về máy cá nhân xử lý rồi đẩy lên,
nên **lớp 3 (vá binary trực tiếp) được nâng lên ưu tiên cao hơn**, làm trên máy cá nhân với đầy đủ công cụ (Ghidra, pwntools)
thay vì bị kẹt bởi vulnbox thiếu tool. Lớp 1 và 2 (gia cố môi trường, proxy) vẫn hữu ích nhưng lùi xuống làm giải pháp bổ trợ/cầm cự,
không còn là chỗ dựa chính. Quy trình chuẩn: tải binary về → phân tích & vá trên máy cá nhân → test → đẩy binary đã vá lên vulnbox → restart dịch vụ.

## 8. Lộ trình 15 ngày (tóm tắt)

Chi tiết đầy đủ nằm trong tài liệu kế hoạch riêng (Claude Docs). Tóm tắt:

**Tuần 1 (28/10-3/11) — Ôn nền:**

- Ngày 1: Linux (OverTheWire Bandit, log, cổng, tiến trình) — cả đội.
- Ngày 2: Docker & Compose (Play with Docker, tự dựng app nhiều container, DVWA) — cả đội.
- Ngày 3: tách mảng — P1 pwn cơ bản (pwn.college), P2 web SQLi/cmdi (PortSwigger), P3 crypto nhập môn + script (CryptoHack).
- Ngày 4: P1 format string + Ghidra, P2 path traversal/auth bypass/upload, P3 AES/ECB + vòng lặp request.
- Ngày 5: **luyện vá binary** (trọng tâm, cả đội) — tìm lỗi Ghidra, patch, test lại.
- Ngày 6: automation (DestructiveFarm/script farm) + bắt traffic (tcpdump/Wireshark) + nguyên lý replay.
- Ngày 7: kiểm tra chéo, bài tập đôi (cài lỗi/vá), rà danh sách challenge, P1 đọc trước ForcAD + VPN.

**Tuần 2 (4/11-11/11) — Dựng & mô phỏng:**

- Ngày 8: dựng ForcAD + VPN + nối 3 máy, kiểm tra nộp flag bằng nc (P1+P3).
- Ngày 9: cắm challenge + viết checker + xoá source pwn/rev (P1+P3). **Nặng nhất, dễ tràn giờ.**
- Ngày 10: phiên mô phỏng 1 (2-3h) — tập trung giữ uptime + vá không làm chết dịch vụ.
- Ngày 11: phiên mô phỏng 2 (3h) — thêm replay + exploit farm thật.
- Ngày 12: phiên mô phỏng dài (4-5h) — sát thi đấu.
- Ngày 13: vá điểm yếu lộ ra qua mô phỏng, hoàn thiện công cụ/script.
- Ngày 14: tổng duyệt cuối (3-4h) + chuẩn bị hậu cần, kết thúc sớm.
- Ngày 15: ngày đệm/thi — khởi động nhẹ, không học thứ mới.

### Ước tính thời gian/ngày (giờ tập trung, phần chính)

Ngày 1: 5-6h · Ngày 2: 5-6h · Ngày 3: 5h · Ngày 4: 5h · Ngày 5: 6h · Ngày 6: 5h · Ngày 7: 4-5h ·
Ngày 8: 6-7h · Ngày 9: 7-8h · Ngày 10: 4-5h · Ngày 11: 5h · Ngày 12: 5-6h · Ngày 13: 5h · Ngày 14: 4-5h · Ngày 15: 1-2h.
Tổng phần chính ~75-85h.

## 9. Về việc dùng AI khi luyện (lưu ý quan trọng)

- AI rút ngắn tốt **phần học kiến thức** (tra cú pháp, giải thích code, gợi ý cách vá, viết nháp checker). Dùng thoải mái.
- AI **KHÔNG rút ngắn phần luyện phản xạ**: vá binary bằng tay, giữ uptime dưới áp lực tick 5 phút + cooldown restart 10 phút,
  debug hệ thống nhiều thành phần, phối hợp 3 người. Đây là phần chiếm nhiều thời gian nhất và quyết định thứ hạng.
- Rủi ro: **thi thật thường không có internet / bị chặn**. Nếu quen hỏi AI mọi bước mà chưa thành phản xạ → mất mạng là đứng hình.
- **Cheatsheet là cách phòng rủi ro này**, NHƯNG chỉ ghi những gì **đã tự chạy thật**, không chép câu trả lời AI chưa kiểm chứng.
- **Thời gian tiết kiệm được nhờ AI → dồn vào chạy thêm phiên mô phỏng** (thay vì 3 phiên, chạy 5-6 phiên). Đây là thứ đáng đầu tư nhất.

## 10. Việc Claude Code nên làm tiếp (gợi ý)

1. Dựng khung thư mục dự án: nơi để `config.yml` ForcAD, các checker, service, script farm, cheatsheet.
2. Viết `config.yml` mẫu cho ForcAD: 3 đội, `round_time: 300` (5 phút), `flag_lifetime: 5`.
3. Viết một checker mẫu (kiểu hackerdom, có PUT/CHECK/GET) để thay logic cho từng challenge.
4. Viết script/hướng dẫn dựng Tailscale hoặc WireGuard nối 3 máy.
5. Chuẩn bị bộ script tiện ích: backup/restore dịch vụ một lệnh, khung exploit farm, script bắt+tách flag từ traffic.
6. Xác minh giao thức nộp flag netcat của ForcAD và ghi lại.
7. Giúp gom + kiểm thử danh sách challenge đủ 4 category, tương thích ForcAD.

## 11. Các điểm còn mở / chưa chốt

- Chưa xác nhận format IBOH 2026 có y hệt mô tả từ lần trước không (xem mục 2) — nhưng 3 điểm luật/môi trường ở mục 2 đã được đội xác nhận.
- Chưa xác minh được link cụ thể & chất lượng của service A-D cũ (ENOWARS/saarCTF/FAUST) — phải tải thử.
- Chưa xác nhận port/giao thức nộp flag của ForcAD.
- 3 người ngồi chung chỗ hay ở xa — quyết định dùng LAN hay Tailscale/WireGuard.
- Vulnbox dùng VM hay container có SSH. (Gợi ý: nên có cả hai kiểu để luyện mục 2 — Docker và chạy trực tiếp.)
