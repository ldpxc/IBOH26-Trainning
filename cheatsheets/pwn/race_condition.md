# Race condition & TOCTOU — khai thác khe thời gian giữa kiểm tra và dùng

> **Bài giảng tự chứa.** Đọc hết là hiểu: race condition là gì, **TOCTOU** (time-of-check to
> time-of-use) và **double-fetch** hoạt động ra sao, vì sao một biến/điều kiện "đúng trong tích tắc"
> lại chiếm được quyền, **cách nhận biết trong source**, cách **thắng cuộc đua** (timing/spam), và
> **nhìn challenge thế nào thì biết áp dụng**. Bài mẫu local dùng cờ `is_admin` bật-tắt trong luồng
> khác.

---

## 0. Bạn cần nắm trước: hai luồng chạy xen kẽ

Chương trình đa luồng (`pthread`) hoặc có thao tác **không nguyên tử (non-atomic)** thì hai đoạn
code có thể **chen vào giữa** nhau. Một "race condition" xảy ra khi **kết quả phụ thuộc thứ tự
chạy** của các luồng — và kẻ tấn công **điều khiển thời điểm** để lọt vào đúng khe.

Trường hợp kinh điển **TOCTOU**: chương trình **kiểm tra** một điều kiện ở thời điểm A, rồi **dùng**
nó ở thời điểm B. Nếu giữa A và B điều kiện **bị đổi** (bởi luồng khác / thao tác khác), thì hành
động ở B dựa trên thông tin **đã cũ** → ta lách được.

> **Nói ngắn:** *có một khoảng thời gian mà điều kiện "đang đúng" rồi sẽ sai. Đua để thực hiện hành
> động đặc quyền NGAY trong khoảng đó.*

---

## 1. Các dạng race hay gặp

| Dạng | Cơ chế | Ví dụ CTF |
|------|--------|-----------|
| **Flag race (biến chia sẻ)** | luồng A bật cờ rồi tắt sau `usleep`; đua để dùng cờ trong lúc bật | `is_admin=1; usleep; is_admin=0` → gọi "get shell" đúng lúc cờ còn 1 |
| **TOCTOU file** | `access(path)` (check) rồi `open(path)` (use); đổi symlink ở giữa | privesc trên SUID binary |
| **Double-fetch** | kernel/chương trình đọc **cùng một giá trị user 2 lần**; đổi nó giữa 2 lần đọc | lần 1 qua kiểm size, lần 2 dùng size lớn → overflow |
| **Heap race** | 2 luồng cùng `malloc/free` một con trỏ → double-free/UAF | heap note đa luồng |

### Bài mẫu local (`admin.c`)
```c
int is_admin = 0;
void try_admin(){ is_admin = 1; usleep(250000); is_admin = 0; }   // bật 0.25s rồi tắt
// menu: 1 -> pthread_create(try_admin);  2 -> if(is_admin) system("/bin/sh");
```
Chọn `1` tạo luồng bật `is_admin` trong **250ms**; phải chọn `2` **trong cửa sổ 250ms** đó →
`is_admin` còn `1` → shell. Đây là **flag race** điển hình.

---

## 2. Vì sao thắng được: cửa sổ thời gian + spam

Cửa sổ 250ms là **cực rộng** so với tốc độ gửi lệnh qua socket (micro giây). Nên chỉ cần:
1. Gửi lệnh `1` (mở cửa sổ).
2. **Ngay lập tức** gửi lệnh `2` (hoặc spam `2` nhiều lần) trước khi `usleep` kết thúc.

Khi cửa sổ hẹp (vài µs, như double-fetch kernel), phải **spam liên tục từ nhiều luồng** để tăng
xác suất trúng khe — đó là "đua" theo đúng nghĩa.

---

## 3. Viết exploit (pwntools) — mẫu flag race

```python
from pwn import *
p = process("./admin")
p.sendlineafter(b"> ", b"1")          # mở cửa sổ: tạo luồng bật is_admin
p.sendlineafter(b"> ", b"2")          # dùng ngay trong cửa sổ -> system("/bin/sh")
p.interactive()
```
Cửa sổ hẹp hơn thì **bỏ chờ prompt** (đừng `sendlineafter`, dùng `sendline` liên tiếp) và **spam**:
```python
p.sendline(b"1")
for _ in range(50):
    p.sendline(b"2")                  # bắn liên tục cho trúng khe
```
> **Mẹo timing:** `sendlineafter` phải chờ echo prompt → chậm, dễ lỡ cửa sổ hẹp. Khi đua gấp, gửi
> thẳng `sendline`/`send` không chờ, hoặc mở **nhiều kết nối/luồng** cùng lúc.

---

## 4. Nhận diện trong source (kỹ năng cốt lõi)

Tìm các mẫu:
```c
// 1) biến chia sẻ bật-tắt quanh một thao tác chậm:
flag = 1;  usleep/sleep/ IO ;  flag = 0;
// 2) check rồi use trên cùng tài nguyên, KHÔNG khoá:
access(path);  ...  open(path);          // TOCTOU file
if (user->size < N) { ... copy(user->size) }  // nếu đọc user->size 2 lần -> double-fetch
// 3) pthread_create / fork + biến global không mutex
// 4) có sleep/usleep "vô cớ" -> thường là cửa sổ race do đề cố ý mở
```
**Dấu hiệu mạnh nhất:** có `pthread`/`fork` + **biến global** được ghi bởi một luồng và đọc bởi
luồng khác **mà không có `mutex`/atomic**; hoặc một `sleep/usleep` nằm giữa "bật" và "tắt".

---

## 5. Nhận diện challenge: khi nào là race?

| Dấu hiệu | Kết luận |
|---------|----------|
| Có `pthread_create`/`fork` + biến chia sẻ không khoá | ✅ flag race |
| `sleep/usleep` kẹp giữa set và unset một quyền | ✅ cửa sổ race rộng → dễ |
| check và use tách rời trên file/con trỏ | ✅ TOCTOU |
| giá trị user được đọc **2 lần** (size kiểm rồi dùng) | ✅ double-fetch |
| Một luồng, không tài nguyên chia sẻ, không sleep | ❌ không phải race |

**Phản xạ:** thấy **menu + luồng/fork + một quyền bật tạm thời** → đua ngay. Cửa sổ càng rộng
(`usleep` lớn) càng dễ; cửa sổ µs thì chuyển sang **spam đa luồng**.

---

## 6. Writeup rút gọn
Bài `admin`: `1` tạo luồng bật `is_admin` 250ms, `2` gọi shell nếu `is_admin`. Gửi `1` rồi `2`
ngay → shell (§3). Video có sẵn (xem roadmap). Nếu cửa sổ hẹp hơn → bỏ chờ prompt + spam `2`.

---

## 7. Bài tập + lộ trình

| Bài | Mức | Học gì |
|-----|-----|--------|
| `advance/Race_Condition` (mp4) | ⭐⭐ | flag race cửa sổ rộng (`usleep`) |
| TOCTOU file SUID (exploit.education) | ⭐⭐⭐ | đổi symlink giữa access/open |
| double-fetch kernel (pwn.college) | ⭐⭐⭐⭐ | cửa sổ µs, spam đa luồng |

**Lộ trình:** flag race cửa sổ rộng (bài local) → bỏ chờ prompt/spam cho cửa sổ hẹp → TOCTOU file
→ double-fetch (kernel, [kernel_pwn.md](kernel_pwn.md)).

---

## Nguồn tham khảo
- CTF Wiki — *Race Condition*: <https://ctf-wiki.mahaloz.re/pwn/linux/race-condition/race_condition/>
- exploit.education — bài TOCTOU/race: <https://exploit.education/>
- Liên quan: [kernel_pwn.md](kernel_pwn.md) (double-fetch) · [heap.md](heap.md) (race → double-free)
