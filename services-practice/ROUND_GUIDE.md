# Luyện A/D 2 team — không cần dashboard

Mục đích: luyện nhịp tấn công/phòng thủ thật với 3 service đa-lỗ-hổng
(`notevault`, `pulseapi`, `socialhub`), qua đúng WAF BunkerWeb mà BTC dùng
(`2026-waf-practice`), **không mô phỏng điểm số/dashboard** — nhóm tự quyết
khi nào "hết round", tự nhận biết bị mất flag qua việc đối thủ show ra.

## 0. Trước buổi tập

- Build xong ít nhất 1 lần mỗi service (`docker compose build` sẽ tự chạy khi
  `spin.sh up` lần đầu, nhưng ảnh BunkerWeb (~vài trăm MB) và base image mỗi
  service nên tải trước nếu có thể, để buổi tập không bị chờ tải mạng).
- 7-8 người chia 2 team (`a`, `b`), vai trò ngang nhau, có thể đổi vai trò
  ATK/DEF giữa các round.
- Máy chạy `spin.sh` cần đủ RAM cho số stack định chạy đồng thời — mỗi
  `(team, service)` là 1 bộ (app + Postgres + BunkerWeb, BunkerWeb giới hạn
  cứng 3GB RAM). Khuyến nghị: **luyện từng service một** (cả 2 team cùng 1
  service tại 1 thời điểm) thay vì bật cả 6 bộ cùng lúc.

## 1. Dựng 1 service cho cả 2 team

```bash
cd services-practice
./spin.sh up a notevault
./spin.sh up b notevault
./spin.sh ps          # xem lại bảng cổng
```

Mỗi team nhận:
- **App qua WAF**: `http://127.0.0.1:<BW_PORT>/` — team B tấn công vào cổng
  của team A và ngược lại.
- **UI WAF (viết rule)**: `http://127.0.0.1:<BW_UI_PORT>/` — đăng nhập
  `admin` / `ChangeMe_Bw_2026!` (đổi trong `.runtime/<team>_<service>/.env`
  nếu muốn, rồi `up` lại).

Mỗi team **chỉ nên tự mở UI WAF của chính mình** (đúng cổng team đó) — mở
nhầm/cố tình vào UI WAF của team kia là vi phạm quy chế thật (Điều 6.1d), nên
luyện tập đúng kỷ luật này luôn từ bây giờ.

`spin.sh up` tự seed WAF về **DetectionOnly** (chỉ ghi log, chưa chặn) ngay từ
đầu, đúng mặc định lúc thi thật — không cần tự vào UI đổi. Nếu dòng log lúc
`up` báo "Seed DetectionOnly LỖI" (hiếm, do máy chậm/Postgres chưa kịp khởi
tạo bảng), vào UI WAF → **Cài đặt chung → ModSecurity** → đổi
`MODSECURITY_SEC_RULE_ENGINE` thành `DetectionOnly` → Save.

## 2. Vòng lặp 1 "round" (gợi ý 15-20 phút/service)

1. Mỗi team tự dò lỗ hổng trên **dịch vụ của đối thủ** (đúng cổng app WAF của
   họ), dùng đúng cheatsheet + tool trong `cheatsheets/web/` và `~/hoc/CTF/Tools/web/`.
2. Lấy được flag nào, **dán trực tiếp vào kênh chat chung** (Discord/Zalo) kèm
   tên lỗ hổng — đội kia biết ngay là mình vừa "mất điểm" ở đâu, tự chuyển
   sang vá/chặn lỗ đó. Đây là cách thay thế việc "nộp dashboard thấy điểm rớt".
3. Song song, mỗi team tự viết rule ModSecurity để chặn đúng lỗ hổng đã bị
   khai thác — **bắt buộc chạy qua `waf_rule_tester.py --wordlists --waf
   http://127.0.0.1:<BW_PORT>`** trước khi bật chặn thật trên UI (xem
   `tools/test_rules_waf/`), y hệt quy trình sẽ dùng lúc thi.
4. Hết thời gian round (tự canh đồng hồ), dừng lại so: team nào chặn được
   nhiều lỗ hổng hơn / vẫn giữ app hoạt động bình thường là thắng round đó.
   Dùng `healthcheck_notevault.py` (mô phỏng bot SLA 30s/lần của BTC, tự phân
   loại lỗi đúng 3 nguyên nhân Điều 5: sập/quá tải, WAF chặn nhầm, không đọc
   được cờ) thay vì tự `curl` tay từng endpoint:
   ```bash
   spwn
   python3 healthcheck_notevault.py --base-url http://127.0.0.1:9000 --env-file .runtime/a_notevault/.env
   # team b: đổi cổng + .env cho đúng (xem ./spin.sh ps):
   # python3 healthcheck_notevault.py --base-url http://127.0.0.1:9010 --env-file .runtime/b_notevault/.env
   ```
   Chạy song song 1 cửa sổ riêng, để liên tục trong lúc viết/bật rule — thấy
   ngay dòng `WAF CHAN NHAM` là biết rule vừa viết chặn nhầm người dùng hợp lệ.

   **Mật khẩu `admin`/`alice` của notevault giờ random riêng theo từng
   team** (sinh lúc `spin.sh up`, in ra ngay dưới dòng `✅ .../notevault:` —
   đọc lại bằng `./spin.sh up <team> notevault` nếu lỡ không chép kịp). 1
   team KHÔNG biết trước mật khẩu app của team kia — chỉ `--env-file` của
   **chính team mình** mới tính đúng mật khẩu của **chính team đó**, buộc
   phải tự tìm đường khai thác (SQLi/IDOR/deserialization/type juggling...)
   để lấy flag của đối thủ, đúng tinh thần thi thật — không còn chuyện tiện
   tay login bằng mật khẩu demo công khai của cả 2 bên.
5. Muốn "reset round" (như BTC dựng lại service + phát cờ mới mỗi round):
   ```bash
   ./spin.sh rotate a notevault
   ./spin.sh rotate b notevault
   ```
   Lệnh này sinh `FLAG_SECRET` mới + restart riêng container `app` (rule WAF
   đã viết trên UI **vẫn giữ nguyên** — đúng như quy chế thật "Rule WAF của
   đội được giữ nguyên qua các round", Điều 2.4).

## 3. Chuyển sang service khác / dọn dẹp

```bash
./spin.sh down a notevault
./spin.sh down b notevault
./spin.sh up a pulseapi
./spin.sh up b pulseapi
```

Lặp lại mục 2 cho `pulseapi` rồi `socialhub`. Muốn dựng cả 6 bộ cùng lúc (máy
đủ mạnh): `./spin.sh up-all`; huỷ hết: `./spin.sh down-all`.

## 4. Vài lưu ý khi luyện

- **`socialhub` cần RAM nhiều hơn** 2 service kia (admin bot chạy Chromium
  headless thật) — nếu máy yếu, ưu tiên luyện `notevault`/`pulseapi` trước.
- Admin bot của `socialhub` **đi qua chính WAF** của team đó (không vào
  thẳng app) — nếu rule WAF viết quá tay chặn nhầm cả request của bot, bot sẽ
  không ghé thăm report được nữa. Đây là bài học thật: *rule chặn quá rộng tự
  làm hại chính mình*, y hệt luật SVC thật.
- Flag "recon" (git leak) của `notevault` được nướng cứng lúc build image
  (`docker compose build`), **không đổi theo `rotate`** — muốn đổi phải build
  lại image (`./spin.sh up <team> notevault` sau khi sửa `FLAG_SECRET` trong
  `.env` rồi `docker compose build --no-cache` thủ công trong thư mục
  service) — việc này hiếm cần vì mục đích luyện recon không đổi mỗi round.
- Không có ai đóng vai "BTC" theo dõi SLA/giờ — nhóm tự giác là yếu tố quan
  trọng nhất của buổi tập này.

## 5. Dọn sạch sau buổi tập

```bash
./spin.sh down-all
docker system df   # xem còn chiếm bao nhiêu đĩa
docker system prune   # dọn image/container thừa nếu cần (hỏi trước khi chạy nếu không chắc)
```
