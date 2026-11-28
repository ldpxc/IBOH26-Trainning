# Vận hành buổi luyện A/D 2 team (dành cho người host — bạn)

Tài liệu này viết cho **người chạy `spin.sh`** (host, máy của bạn), hướng dẫn: khởi
động challenge cho 2 team → soạn + gửi thông tin kết nối cho từng người → vận hành
trong lúc chơi (reset round, theo dõi SVC) → tắt/dọn dẹp sau buổi tập.

Mục đích: luyện nhịp tấn công/phòng thủ thật với 3 service đa-lỗ-hổng
(`notevault`, `pulseapi`, `socialhub`), qua đúng WAF BunkerWeb mà BTC dùng
(`2026-waf-practice`), **không có dashboard điểm số tập trung** — mỗi team tự theo
dõi dịch vụ của chính mình, tự nhận biết bị mất flag qua việc đối thủ báo ra.

---

## 0. Trước buổi tập

- Build xong ít nhất 1 lần mỗi service (`docker compose build` sẽ tự chạy khi
  `spin.sh up` lần đầu, nhưng ảnh BunkerWeb (~vài trăm MB) và base image mỗi
  service nên tải trước nếu có mạng, để buổi tập không bị chờ tải).
- 7-8 người chia 2 team (`a`, `b`), vai trò ngang nhau, có thể đổi vai trò
  ATK/DEF giữa các round.
- Máy chạy `spin.sh` (máy bạn) cần đủ RAM cho số stack định chạy đồng thời —
  mỗi `(team, service)` là 1 bộ (app + Postgres + BunkerWeb, BunkerWeb giới hạn
  cứng 3GB RAM). Khuyến nghị: **luyện từng service một** (cả 2 team cùng 1
  service tại 1 thời điểm) thay vì bật cả 6 bộ cùng lúc.
- **Mọi người (kể cả bạn) đều ở cùng 1 mạng LAN/Wi-Fi** — cổng app/WAF UI/
  dashboard giờ lắng nghe trên mọi interface (`0.0.0.0`), đồng đội mở bằng IP
  LAN của máy bạn, không phải `127.0.0.1` (chỉ máy bạn mới dùng được
  `127.0.0.1`).

---

## 1. Lấy IP LAN của máy host (máy bạn)

```bash
hostname -I
# hoặc, nếu máy có nhiều interface (VPN, Docker, máy ảo...), lọc đúng dải LAN:
ip -4 addr show scope global | grep inet
```

Chọn đúng địa chỉ cùng dải với router Wi-Fi mọi người đang dùng (thường dạng
`192.168.x.x` hoặc `10.x.x.x` — **không chọn** địa chỉ Docker (`172.17-20.x.x`),
VPN (`100.x.x.x`), hay máy ảo (`192.168.56.x`, `192.168.122.x`) nếu có).
Không chắc thì mở Cài đặt mạng của hệ điều hành xem "địa chỉ IPv4" của card
Wi-Fi đang kết nối là nhanh và chắc nhất.

Gọi địa chỉ này là **`<HOST_IP>`** — dùng xuyên suốt tài liệu này.

> **Lưu ý an toàn**: từ bước này, app/WAF UI/dashboard của bạn có thể được
> **bất kỳ ai cùng mạng LAN** truy cập, không chỉ 2 team — chỉ làm việc này
> trên mạng riêng tư/tin cậy (nhà, phòng lab đóng), không làm ở Wi-Fi công
> cộng hoặc mạng cơ quan không kiểm soát được ai đang ở trong đó.

---

## 2. Khởi động challenge cho 2 team

```bash
cd services-practice
./spin.sh up a notevault
./spin.sh up b notevault
./spin.sh ps          # xem lại bảng cổng
```

Mỗi lệnh `up` tự in ra: cổng app/WAF UI, mật khẩu UI WAF (dùng chung mọi
team), và **mật khẩu app `admin`/`alice` riêng của đúng team đó** (xem lại
mục 6 — không gửi nhầm mật khẩu app của team này cho team kia).

**Chép lại ngay** phần `spin.sh up` vừa in ra cho từng team — bạn cần nó để
soạn tin nhắn gửi đi ở mục 3.

---

## 3. Soạn & gửi thông tin kết nối cho từng team

Mỗi team cần đúng 4 thứ, và **chỉ 4 thứ này** (không gửi WAF UI/mật khẩu app
của team kia — xem lưu ý kỷ luật bên dưới):

| Gửi cho team | Nội dung |
|---|---|
| **Team A** | 1) App **của họ** (để vá): `http://<HOST_IP>:9000/` · 2) WAF UI **của họ**: `http://<HOST_IP>:9100/` (`admin` / `ChangeMe_Bw_2026!`) · 3) Tài khoản app của họ: `admin`/`<mật khẩu admin in ra lúc up a>`, `alice`/`<mật khẩu alice in ra lúc up a>` · 4) Mục tiêu tấn công (app của **team B**): `http://<HOST_IP>:9010/` |
| **Team B** | 1) App **của họ**: `http://<HOST_IP>:9010/` · 2) WAF UI **của họ**: `http://<HOST_IP>:9110/` (`admin` / `ChangeMe_Bw_2026!`) · 3) Tài khoản app của họ: `admin`/`<mật khẩu admin in ra lúc up b>`, `alice`/`<mật khẩu alice in ra lúc up b>` · 4) Mục tiêu tấn công (app của **team A**): `http://<HOST_IP>:9000/` |

Mẫu tin nhắn (copy, điền số thật từ `spin.sh up` rồi gửi đúng kênh riêng của
từng team — Discord/Zalo riêng từng team, không gửi vào kênh chung):

```text
[Team A — thông tin của team bạn]
App của team mình (để vá, đối thủ sẽ tấn công vào đây): http://<HOST_IP>:9000/
WAF UI của team mình (viết rule, xem traffic log): http://<HOST_IP>:9100/
  đăng nhập: admin / ChangeMe_Bw_2026!
Tài khoản đăng nhập app (để tự test/debug, không chia sẻ cho team B):
  admin / <điền từ dòng "admin / ..." lúc up a>
  alice / <điền từ dòng "alice / ..." lúc up a>
Mục tiêu tấn công (app của Team B): http://<HOST_IP>:9010/
```

```text
[Team B — thông tin của team bạn]
App của team mình (để vá, đối thủ sẽ tấn công vào đây): http://<HOST_IP>:9010/
WAF UI của team mình (viết rule, xem traffic log): http://<HOST_IP>:9110/
  đăng nhập: admin / ChangeMe_Bw_2026!
Tài khoản đăng nhập app (để tự test/debug, không chia sẻ cho team A):
  admin / <điền từ dòng "admin / ..." lúc up b>
  alice / <điền từ dòng "alice / ..." lúc up b>
Mục tiêu tấn công (app của Team A): http://<HOST_IP>:9000/
```

### Gửi kèm mã nguồn (giống Điều 2.3: "đội không được sửa mã nguồn" — ngụ ý có source để đọc)

```bash
python3 export_source.py --service notevault
# pulseapi: python3 export_source.py --service pulseapi
# socialhub: python3 export_source.py --service socialhub
```

Ra file `.runtime/export/notevault_source.zip` — **giống hệt nhau cho cả 2
team** (đúng "mỗi đội 1 cụm service giống hệt nhau, cùng lỗ hổng"), nên chỉ
cần xuất **1 lần/service**, gửi cùng 1 file cho cả Team A lẫn Team B kèm tin
nhắn ở trên. Script tự loại bỏ phần code debug ẩn không nên lộ qua đọc
source (không ảnh hưởng tới service đang chạy, chỉ cắt ở bản zip xuất ra).

**Kỷ luật quan trọng (tập đúng từ bây giờ, giống Điều 6.1.d quy chế thật)**:
mỗi team **chỉ nên tự mở WAF UI của chính mình** (đúng cổng team đó). Mở
nhầm/cố tình vào UI WAF của team kia lúc thi thật là hành vi bị cấm — luyện
tập đúng kỷ luật này luôn từ bây giờ, dù đây chỉ là buổi tập.

`spin.sh up` tự seed WAF về **DetectionOnly** (chỉ ghi log, chưa chặn) ngay từ
đầu, đúng mặc định lúc thi thật — không cần tự vào UI đổi. Nếu dòng log lúc
`up` báo "Seed DetectionOnly LỖI" (hiếm, do máy chậm/Postgres chưa kịp khởi
tạo bảng), vào UI WAF → **Cài đặt chung → ModSecurity** → đổi
`MODSECURITY_SEC_RULE_ENGINE` thành `DetectionOnly` → Save.

---

## 4. Theo dõi trong lúc chơi (SVC) — chạy trên máy host, đồng đội xem qua LAN

Mở thêm 2 cặp cửa sổ trên máy bạn (host), 1 cặp cho mỗi team — việc này do
**bạn** (người host) chạy, không phải từng team tự chạy, vì cần đọc file
`.runtime/` trên máy bạn:

```bash
spwn
# cửa sổ 1 (team a): healthcheck liên tục
python3 healthcheck_notevault.py --base-url http://127.0.0.1:9000 --env-file .runtime/a_notevault/.env

# cửa sổ 2 (team b): healthcheck liên tục
python3 healthcheck_notevault.py --base-url http://127.0.0.1:9010 --env-file .runtime/b_notevault/.env

# cửa sổ 3: dashboard team a
python3 dashboard.py --team a

# cửa sổ 4: dashboard team b
python3 dashboard.py --team b
```

Gửi thêm cho từng team link dashboard **của chính họ** (không phải của đội
kia): team A → `http://<HOST_IP>:8800/`, team B → `http://<HOST_IP>:8810/`.
Trang tự load lại mỗi 5 giây, hiện SVC% vòng gần nhất, lý do lỗi nếu có (sập,
WAF chặn nhầm, không đọc được cờ), và timeline theo từng vòng check + vạch
phân round.

---

## 5. Vòng lặp 1 "round" (gợi ý 15-20 phút/service)

1. Mỗi team tự dò lỗ hổng trên **dịch vụ của đối thủ** (đúng cổng app WAF của
   họ, mục "Mục tiêu tấn công" ở mục 3), dùng đúng cheatsheet + tool trong
   `cheatsheets/web/` và `~/hoc/CTF/Tools/web/`.
2. Lấy được flag nào, **dán trực tiếp vào kênh chat chung** (Discord/Zalo) kèm
   tên lỗ hổng — đội kia biết ngay là mình vừa "mất điểm" ở đâu, tự chuyển
   sang vá/chặn lỗ đó. Đây là cách thay thế việc "nộp dashboard thấy điểm rớt".
3. Song song, mỗi team tự viết rule ModSecurity để chặn đúng lỗ hổng đã bị
   khai thác — **bắt buộc chạy qua `waf_rule_tester.py --wordlists --waf
   http://<HOST_IP>:<cổng app của team mình>`** trước khi bật chặn thật trên
   UI (xem `tools/test_rules_waf/`), y hệt quy trình sẽ dùng lúc thi.
4. Hết thời gian round (tự canh đồng hồ), dừng lại so: team nào chặn được
   nhiều lỗ hổng hơn / vẫn giữ app hoạt động bình thường (xem dashboard của
   chính mình, mục 4) là thắng round đó.

---

## 6. Vận hành trong buổi tập

### Reset 1 round (như BTC dựng lại service + phát cờ mới)

```bash
./spin.sh rotate a notevault
./spin.sh rotate b notevault
```

Sinh `FLAG_SECRET` mới + restart riêng container `app` — **rule WAF đội đã
viết vẫn giữ nguyên** (đúng quy chế thật, Điều 2.4), **mật khẩu app
`admin`/`alice` cũng giữ nguyên** (không cần gửi lại thông tin kết nối mục 3
sau mỗi lần rotate — chỉ flag đổi). Lệnh này tự đánh dấu "round mới" trên
dashboard của đúng team đó.

### Chuyển sang service khác

```bash
./spin.sh down a notevault
./spin.sh down b notevault
./spin.sh up a pulseapi
./spin.sh up b pulseapi
```

Lặp lại mục 2-5 cho `pulseapi` rồi `socialhub` — nhớ **gửi lại thông tin kết
nối mới** (mục 3) cho 2 team vì cổng/mật khẩu đổi theo service, kèm
`python3 export_source.py --service pulseapi` (hoặc `socialhub`) để gửi đúng
mã nguồn của service mới. Muốn dựng cả
6 bộ cùng lúc (máy đủ mạnh): `./spin.sh up-all`; huỷ hết: `./spin.sh down-all`.

### Dừng tạm (nghỉ giữa buổi, giữ nguyên dữ liệu để chơi tiếp sau)

```bash
./spin.sh down a notevault
./spin.sh down b notevault
```

`down` (không `-v`) giữ nguyên volume (DB, rule WAF, log) — `up` lại đúng
(team, service) đó sẽ khôi phục y như lúc dừng, không mất tiến trình.

---

## 7. Tắt hẳn / dọn sạch sau buổi tập

```bash
./spin.sh down-all
```

Nếu buổi tập đã xong hẳn (không định chơi lại) và muốn dọn thật sạch (xoá cả
DB, rule WAF, log — **mất hết tiến trình đã lưu**, không hoàn tác được):

```bash
for team in a b; do
  for svc in notevault pulseapi socialhub; do
    [ -f ".runtime/${team}_${svc}/.env" ] && \
      docker compose --env-file ".runtime/${team}_${svc}/.env" -f "${svc}/compose.arena.yml" down -v
  done
done
rm -rf .runtime
```

Dọn image/container Docker thừa (không bắt buộc, chỉ cần khi thiếu ổ đĩa):

```bash
docker system df   # xem đang chiếm bao nhiêu
docker system prune   # hỏi xác nhận trước khi chạy nếu không chắc
```

> **Image đã build** (`a_notevault-app`, `b_notevault-app`...) nên **giữ
> lại** nếu còn luyện tập tiếp các buổi sau — `docker system prune` mặc định
> không xoá image đang gắn với container nào, chỉ xoá image/container mồ côi,
> nên chạy bình thường là an toàn.

---

## 8. Vài lưu ý khi luyện

- **`socialhub` cần RAM nhiều hơn** 2 service kia (admin bot chạy Chromium
  headless thật) — nếu máy yếu, ưu tiên luyện `notevault`/`pulseapi` trước.
- Admin bot của `socialhub` **đi qua chính WAF** của team đó (không vào
  thẳng app) — nếu rule WAF viết quá tay chặn nhầm cả request của bot, bot sẽ
  không ghé thăm report được nữa. Bài học thật: *rule chặn quá rộng tự làm
  hại chính mình*, y hệt luật SVC thật.
- Flag "recon" (git leak) của `notevault` được nướng cứng lúc build image
  (`docker compose build`), **không đổi theo `rotate`** — muốn đổi phải build
  lại image, việc này hiếm cần vì mục đích luyện recon không đổi mỗi round.
- Không có ai đóng vai "BTC" theo dõi SLA/giờ — nhóm tự giác là yếu tố quan
  trọng nhất của buổi tập này.

---

## 9. Xử lý sự cố nhanh

| Triệu chứng | Nguyên nhân thường gặp | Cách sửa |
|---|---|---|
| Đồng đội không mở được `http://<HOST_IP>:9000/` dù máy bạn mở được | Firewall của hệ điều hành host đang chặn cổng tới từ máy khác | Linux: `sudo ufw allow 9000:9999/tcp` (mở đủ dải cổng spin.sh dùng) hoặc tắt tạm firewall; Windows/Mac: cho phép kết nối trong hộp thoại "Windows Defender Firewall"/"macOS Firewall" khi Docker hỏi lần đầu |
| Đồng đội dùng nhầm IP (dò được IP nhưng không vào được) | Lấy nhầm IP của interface khác (Docker/VPN/máy ảo) ở mục 1 | Kiểm tra lại đúng dải IP router nhà/lab đang cấp — thường `192.168.x.x`, hỏi người còn lại xem máy họ tự nhận IP dải nào (gợi ý cùng dải 3 số đầu) |
| `./spin.sh up` báo cổng đã được dùng (`port is already allocated`) | Stack cũ chưa `down` hết, hoặc 2 người cùng chạy `spin.sh up` cùng lúc | `./spin.sh ps` xem cái nào "đang chạy", `down` nó trước khi `up` lại |
| App 503 ngay sau `up`/`rotate` | BunkerWeb đang tự generate config, bình thường mất 10-30s | Đợi rồi thử lại, xem `docs/huong-dan.md` nếu lâu hơn 1-2 phút chưa hết |
| Dashboard báo "CHƯA CÓ DỮ LIỆU" | Chưa chạy `healthcheck_notevault.py` cho đúng team/service đó | Chạy đúng lệnh ở mục 4 cho team/service đang xem |
