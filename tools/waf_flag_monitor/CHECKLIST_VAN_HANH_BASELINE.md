# Vận hành Bộ Rule Nền Tảng (Baseline) — Detect trước, Prevent sau

Chiến lược: BunkerWeb có 2 chế độ (`DetectionOnly` = chỉ ghi log, `On` = chặn
thật). Thay vì chờ bị tấn công rồi mới viết rule theo từng alert (cách làm cũ,
an toàn nhưng chậm), ta add **ngay một bộ rule nền tảng toàn diện** (sinh bởi
`rule_engine.generate_baseline_ruleset()`, 51 rule, route-agnostic — không
khoá theo path cụ thể) **ngay từ đầu giải lúc còn `DetectionOnly`**, quan sát
một thời gian xem có cảnh báo nhầm traffic thật (đặc biệt bot healthcheck BTC)
không, rồi mới quyết định bật `On`.

File rule sẵn dùng: [`baseline_ruleset_pass.conf`](baseline_ruleset_pass.conf)
(action mặc định `pass,log`, an toàn tuyệt đối để add — không chặn gì cả).

**Đã test thật** trên 3 service tập (`notevault`/PHP, `pulseapi`/Python,
`socialhub`/Node) qua BunkerWeb sống: không FP trên traffic bình thường đa
dạng (~90 request), vẫn chặn đúng tấn công thật, ReDoS <1.5ms/rule, load test
16 đội song song p95=11-85ms (xa dưới ngưỡng). Xem `HANDOVER.md` mục lịch sử
để biết chi tiết 4 bug đã tìm và vá trong lúc test.

---

## Bước 1 — Add bộ rule (ngay khi vừa nhận được service đầu round 1)

1. Vào UI WAF của đội mình, **Configs → New**.
2. **Service: chọn Global** — **TUYỆT ĐỐI KHÔNG chọn tên service cụ thể**, kể
   cả khi chỉ có 1 service. Đã verify thật: chọn theo tên service khiến rule
   bị lưu vào thư mục mà nginx không include tới, **không bao giờ chạy, không
   báo lỗi gì**.
3. Config Type: `MODSEC`.
4. Dán nguyên nội dung [`baseline_ruleset_pass.conf`](baseline_ruleset_pass.conf).
5. Save. **Tự kiểm tra lại ngay** (đừng chỉ tin UI báo "đã lưu"):
   - Gửi lại 1 request bất kỳ có payload rõ ràng (vd `search?q=' OR 1=1 UNION
     SELECT 1--`) rồi mở tab Traffic Log, xem cột rule ID khớp — phải thấy 1
     ID trong dải `28000-28050` xuất hiện. Không thấy = rule chưa nạp thật,
     quay lại bước 2 kiểm tra Service đã chọn Global chưa.
   - (Nếu có quyền truy cập container WAF qua SSH/docker) xác nhận số lượng
     rule ID thực tải đúng 51: không tin trạng thái "healthy"/"OK" của UI —
     **đã có trường hợp thật** reload nginx thất bại âm thầm (lỗi trùng Rule
     ID do config cũ chưa dọn sạch, hoặc file `msg:` chứa ký tự `%` làm vỡ cú
     pháp) mà UI vẫn hiện "đã lưu", WAF **vẫn chạy ruleset CŨ** không có gì
     mới.

## Bước 2 — Quan sát trong `DetectionOnly` (KHÔNG vội bật chặn)

Để `SecRuleEngine` nguyên `DetectionOnly` (mặc định lúc mới dựng/lúc thi
thật). Theo dõi Traffic Log hoặc dùng `tools/waf_flag_monitor` qua **ít nhất
1-2 chu kỳ healthcheck của BTC** (bot chạy mỗi 30 giây — đợi vài phút là đủ
thấy pattern) trước khi quyết định gì thêm.

**Cách đọc log đúng:** lọc traffic có cột rule ID nằm trong dải `28000-28050`
(dải riêng của bộ baseline, phân biệt được với OWASP CRS `9xxxxx` và rule
cũ của chính đội nếu có). Với MỖI request có ID trong dải này, tự hỏi:

> Request này có phải là traffic BÌNH THƯỜNG (bot healthcheck, người dùng
> thật dùng tính năng hợp lệ) hay THỰC SỰ là tấn công?

- Nếu là tấn công thật (đối thủ đang dò) → tốt, rule đang hoạt động đúng, cứ
  để `pass,log` quan sát thêm, **không cần làm gì**.
- Nếu là traffic hợp lệ (SVC bot hoặc người dùng thật) → đây là **FALSE
  POSITIVE**, chuyển sang quy trình xử lý ở Bước 3.

## Bước 3 — Xử lý khi phát hiện chặn nhầm (False Positive)

### 3.1. Xác định đúng rule nào

Trong traffic log, mở chi tiết request bị gắn cờ, xem **rule ID cụ thể**
(không chỉ tag). Mỗi rule trong file `.conf` có comment `# <tên nhóm>` ngay
phía trên — tra theo ID để biết nó thuộc nhóm nào (A-H, xem mục lục cuối file
`.conf`).

### 3.2. Quyết định: sửa hẹp lại, loại trừ riêng request đó, hay xoá hẳn?

| Tình huống | Quyết định |
|---|---|
| Rule quá rộng nhưng VẪN cần giữ (vd chặn `role`/`is_admin` trong body — đúng hướng, chỉ 1 route Admin hợp lệ thật sự cần gửi field đó) | **Thêm 1 rule loại trừ riêng cho ĐÚNG route đó** (dùng `generate_waf_rules` bình thường với route cụ thể, hoặc thêm điều kiện `REQUEST_FILENAME "!@rx ^/route/admin/that/\z"` vào trước rule baseline) — KHÔNG xoá rule baseline. |
| Rule đụng đúng 1 tính năng có thật của app mà không có cách nào tách biệt với payload tấn công (vd OAuth/webhook redirect_uri dùng chính IP nội bộ của app — xem ví dụ thật bên dưới) | **Xoá đúng (các) rule ID đó khỏi file `.conf`** đang dùng trên UI, giữ nguyên phần còn lại. Ghi chú lại route nào đã loại trừ, để khi áp Khuôn 1 Allowlist cho route đó sau này nhớ bù lại bằng cách khác (vd ép định dạng tham số chặt hơn thay vì chặn theo payload). |
| Không chắc, traffic ít, muốn xác nhận thêm | Cứ để `pass,log`, không xoá vội — bản chất `pass,log` không chặn ai cả, chỉ cần tránh BẬT `deny` cho đúng rule đó khi chuyển sang Bước 4. |

### 3.3. Ví dụ THẬT đã gặp khi test (dùng làm mẫu suy luận)

**Triệu chứng:** request `GET /oauth/authorize?redirect_uri=http://127.0.0.1:80/oauth/callback`
(redirect_uri hợp lệ, trỏ về đúng chính service) bị gắn **2 rule cùng lúc**:
1 rule tag `ssrf` (khớp vì giá trị chứa `http://127.0.0.1`) và 1 rule tag
`open-redirect` (khớp vì tên tham số `redirect_uri` có giá trị bắt đầu bằng
`http://`).

**Suy luận:** 2 rule này được thiết kế đúng — chặn SSRF/Open Redirect là hợp
lý nói chung. Nhưng app có tính năng OAuth/webhook hợp lệ cần CHÍNH redirect
URL trỏ về bản thân nó, mà trong mạng thi đấu AD CTF mọi IP đều là private —
đây là tính năng thật, không phải tấn công.

**Quyết định:** xoá 2 rule ID đó khỏi `.conf` đang dùng (không có cách tách
biệt an toàn giữa "redirect về chính mình" và "SSRF thật" chỉ bằng regex tĩnh
không biết trước host của app). Nếu đội có thời gian, có thể tự viết thêm 1
rule riêng CHỈ chặn khi `redirect_uri`/SSRF target KHÁC domain/IP thật của
app (cần biết IP thật, làm được sau khi xác nhận route).

## Bước 4 — Chuyển sang chặn thật (Prevent)

Chỉ làm khi đã quan sát `DetectionOnly` đủ lâu (khuyến nghị: hết round 1,
hoặc tối thiểu vài chu kỳ healthcheck) và đã xử lý xong mọi False Positive ở
Bước 3.

1. Trong file `.conf` đang dùng, đổi `pass,log` thành `deny,status:403,log`
   cho MỌI rule còn lại (có thể dùng `sed -i 's/,pass,log,/,deny,status:403,log,/g'`
   trên bản copy local rồi dán lại, hoặc sinh lại bằng
   `generate_baseline_ruleset(action_mode="deny")` rồi copy `rules_text`).
2. Lưu lại trên UI (vẫn **Service = Global**).
3. **Bắt buộc**: vào **Cài đặt chung → ModSecurity**, đổi
   `MODSECURITY_SEC_RULE_ENGINE` từ `DetectionOnly` sang `On`. Nếu bỏ qua
   bước này, đổi `deny` trong rule **không có tác dụng gì cả** — đây là 2
   công tắc độc lập (đã verify thật).
4. Gửi lại 1 payload tấn công mẫu → phải thấy `403`. Gửi vài request bình
   thường (đăng nhập, dùng tính năng chính của app) → phải vẫn `200`.
5. Tiếp tục quan sát traffic log định kỳ suốt giải — nếu phát hiện FP mới sau
   khi bật `deny` (traffic BTC có thể đa dạng hơn lúc đầu), quay lại Bước 3.

## Phần KHÔNG có trong baseline (cố ý) — chỉ thêm khi đã biết app thật

- **Allowlist Khuôn 1** (ép định dạng `id`/`sort`/`locale`...) — cần biết tên
  tham số thật app dùng, dùng `generate_waf_rules` bình thường sau khi đã rõ
  route.
- **Guard HPP / JSON Array** theo tên tham số cụ thể.
- **Phase 3/4 Flag DLP** (chặn response lộ flag ngoài route hợp lệ) — **TUYỆT
  ĐỐI không đoán route cờ**, chỉ sinh qua `generate_waf_rules(...,
  legit_flag_routes=[...])` sau khi tự xác nhận route trả cờ thật của bot
  SVC. Xem `CHECKLIST_THI_THAT.md` mục A.
- **GraphQL Array Batching** (`REQUEST_BODY` bắt đầu bằng `[`) — quá rộng,
  trùng với API bulk-import hợp lệ, chỉ thêm khi đã xác nhận đúng route
  `/graphql` thật.

## Rủi ro đã biết, chưa thể tự động hoá hoàn toàn (theo dõi thủ công)

- **Mass Assignment** (rule nhóm F, chặn field `role`/`is_admin`/`permissions`/...
  trong body): nếu route Admin THẬT của app cần client tự gửi field này (hiếm
  nhưng có thể), sẽ bị chặn nhầm khi bật `deny`. Theo dõi kỹ route nào dùng
  tính năng cập nhật profile/settings.
- **OAuth/Webhook redirect_uri nội bộ**: xem ví dụ Bước 3.3 ở trên.
- Nếu BTC năm nay đổi sang **1 WAF dùng cho nhiều service** (khác giả định
  hiện tại), toàn bộ quy trình "Service = Global" ở Bước 1 cần kiểm chứng
  lại — xem ghi chú riêng, chưa làm (user chủ động hoãn việc này).
