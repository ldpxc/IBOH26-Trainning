# Integer bugs — overflow / underflow / signedness / truncation (type casting)

> **Bài giảng tự chứa.** Đọc hết là hiểu: số nguyên trong C được lưu/giới hạn thế nào, 4 kiểu lỗi
> integer (tràn, âm hoá, ép kiểu thu nhỏ, nhầm dấu), **cách nhận ra chúng trong source/decompiler**,
> vì sao một con số sai lại dẫn tới ghi/đọc ngoài biên, và **nhìn challenge thế nào thì biết áp
> dụng**. Bản thân integer bug **hiếm khi cho shell trực tiếp** — nó là **bước mở cửa** cho BOF /
> heap / OOB. Nền BOF: [ret2libc.md](ret2libc.md); OOB: [oob.md](oob.md).

---

## 0. Bạn cần nắm trước: số nguyên trong C có GIỚI HẠN

CPU lưu số nguyên trong số bit cố định → có **trần và sàn**. Khi vượt, nó **cuộn vòng (wrap)**
chứ không báo lỗi.

| Kiểu (x86-64) | Bit | Dải |
|------|-----|-----|
| `int` / `int32_t` | 32 | `-2^31 … 2^31-1` (−2147483648 … 2147483647) |
| `unsigned int` | 32 | `0 … 2^32-1` (0 … 4294967295) |
| `long` / `size_t` | 64 | 64-bit |
| `short` | 16 | `-32768 … 32767` |
| `char` | 8 | `-128 … 127` (hoặc `0..255` nếu unsigned) |

Hai sự thật nền tảng khai thác dựa vào:
1. **Wrap-around:** `unsigned` cộng vượt trần → quay về 0 (`0xffffffff + 1 = 0`). `signed` vượt
   trần → thành số âm (undefined behavior nhưng thực tế wrap).
2. **Ép kiểu ngầm (implicit conversion):** C tự đổi kiểu khi so sánh/gán. `signed` so với `unsigned`
   → **signed bị ép thành unsigned** (số âm hoá thành số rất lớn). Gán `int` vào `short`/`char` →
   **cắt cụt bit cao (truncation)**.

> **Nói ngắn:** *một phép so sánh/cộng/ép kiểu trên số nguyên cho ra giá trị "không ngờ" (âm hoá,
> wrap, cắt cụt) → qua được một kiểm tra kích thước, rồi dùng kích thước sai đó để read/write/malloc
> ngoài biên.*

---

## 1. Bốn dạng lỗi — nhận mặt từng cái

### 1.1. Signed/unsigned confusion (nhầm dấu) — phổ biến nhất trong CTF
```c
char buf[64];
int len = get_int();              // người dùng nhập
if (len > 64) { puts("too big"); return; }   // CHỈ chặn trần, quên chặn ÂM
read(0, buf, len);                // len là int -> ép unsigned trong read(size_t) -> số KHỔNG LỒ
```
Nhập `len = -1` → qua `(-1 > 64)` = **false** (lọt), nhưng `read(0, buf, (size_t)-1)` = đọc
`0xffffffffffffffff` byte → **BOF khổng lồ**. Đây đúng là **IOF Signed Integer Overflow** (bài
B21). **Dấu hiệu:** biến kích thước/chỉ số là `signed` (`int`) nhưng chỉ kiểm **cận trên**.

### 1.2. Integer overflow/underflow (tràn/thiếu)
```c
unsigned int n = get_uint();
char *p = malloc(n * 8);          // n*8 tràn 32-bit: n=0x20000000 -> n*8 = 0 (wrap)
for (i=0;i<n;i++) p[i*8]=...;     // malloc(0) nhỏ xíu, nhưng vòng lặp ghi n lần -> heap overflow
```
`n * size` **tràn** → `malloc` cấp **quá ít**, nhưng code sau dùng `n` gốc để ghi → tràn heap.
**Dấu hiệu:** phép nhân/cộng kích thước trước `malloc`/`alloca` không kiểm tràn.

### 1.3. Truncation (cắt cụt khi ép xuống kiểu nhỏ hơn) — **IOF Type Casting (B22)**
```c
int len = get_int();              // vd 0x10000 (65536)
short slen = len;                 // short 16-bit: 0x10000 & 0xffff = 0  -> slen = 0
char buf[0x100];
if (slen < 0x100) read(0, buf, len);   // kiểm bằng slen=0 (lọt), nhưng read dùng len=0x10000 -> BOF
```
Kiểm bằng biến **đã bị cắt** (`short`/`char`) nhưng thao tác bằng biến **gốc** → lệch. **Dấu hiệu:**
gán một biến rộng vào biến hẹp hơn (`int→short`, `int→char`, `size_t→int`) rồi dùng lẫn lộn.

### 1.4. Negative index (chỉ số âm) → cầu nối sang OOB
`idx` là `signed` và không kiểm `idx >= 0` → `arr[idx]` với `idx<0` đọc/ghi **trước mảng** (vùng
nhớ khác). Chi tiết: [oob.md](oob.md). Integer bug ở đây = **cho phép index âm lọt qua**.

---

## 2. Tìm trong source / decompiler (kỹ năng cốt lõi)

Integer bug **đọc source/Ghidra là ra nhanh nhất** — tìm các mẫu:
```c
// 1) kiểm kích thước chỉ một phía:
if (len > MAX) ...        // thiếu  (len < 0)  -> nghi signed bug
// 2) kiểu signed cho size/index:
int size; int idx;        // nên là size_t/unsigned mà lại int
// 3) ép kiểu hẹp:
short/char/int8 <- int/long
// 4) toán trước malloc:
malloc(a * b)  /  malloc(n + k)   // có kiểm tràn không?
```
Trong **GDB**, xác nhận giá trị thực sau phép ép kiểu:
```gdb
b *<ngay sau lệnh so sánh / ép kiểu>
p/x $eax            # xem giá trị ĐÃ BỊ cắt/âm hoá mà hàm dùng
p (size_t)$rax      # xem nó thành số khổng lồ cỡ nào khi ép unsigned 64-bit
```
Dấu hiệu trong decompiler: Ghidra hiện `(uint)`, `(short)`, `CONCAT`/`SUB` cast — chỗ đó là nơi
dấu/độ rộng bị đổi.

---

## 3. Nhận diện: khi nào là integer bug?

| Dấu hiệu | Dạng |
|---------|------|
| Kích thước/độ dài là `int` (signed) + chỉ kiểm cận trên | signed bug (§1.1) → nhập **số âm** |
| Nhân/cộng kích thước trước `malloc` không kiểm tràn | overflow (§1.2) → ép **wrap về nhỏ** |
| Gán `int`→`short`/`char` rồi kiểm bằng biến hẹp | truncation (§1.3) → chọn giá trị **cắt xong qua kiểm** |
| Chỉ số mảng là signed, không kiểm `>= 0` | negative index → [OOB](oob.md) |
| Chương trình **tin một giá trị đếm/độ dài do user nhập** | luôn nghi integer bug trước |

**Phản xạ:** thấy **một biến kích thước/đếm/chỉ số kiểu signed mà kiểm tra thiếu một phía** → thử
ngay **giá trị biên**: `-1`, `0`, `0x80000000`, `0xffffffff`, số làm phép nhân wrap. Integer bug
gần như luôn là **cửa mở** cho BOF/heap-overflow/OOB, nên sau khi "qua kiểm" thì nối sang kỹ thuật
chính tương ứng.

---

## 4. Luồng khai thác (tổng quát)

1. **Tìm phép kiểm/phép toán số nguyên đáng ngờ** (source/Ghidra) — biến nào user điều khiển.
2. **Chọn giá trị biên** để phá: `-1` (âm hoá), giá trị wrap, giá trị truncation.
3. **Qua được kiểm tra** → giành được primitive thật: BOF (read dài), heap overflow (malloc nhỏ +
   ghi nhiều), hoặc OOB (index âm).
4. **Chuyển sang kỹ thuật chính** khai thác primitive đó → shell (ret2libc / tcache / OOB write GOT…).

---

## 5. Writeup rút gọn (hướng, không phải full)

- **B21 Signed Integer Overflow:** biến `len` kiểu `int`, chỉ `if(len>size)`. Gửi `len` **âm** →
  `read(0, buf, (size_t)len)` thành BOF khổng lồ → ret2win/ret2libc như BOF thường.
- **B22 Type Casting Bug:** độ dài bị ép xuống `short`/`char` trước khi kiểm; chọn giá trị mà **phần
  thấp qua kiểm** nhưng **giá trị gốc lớn** → BOF.
- Video có sẵn (xem roadmap). Sau khi "qua cửa", phần còn lại là BOF chuẩn ([ret2libc.md](ret2libc.md)).

---

## 6. Bài tập + lộ trình

| Bài | Mức | Học gì |
|-----|-----|--------|
| `iof/Basic_B21_IOF-Signed_Integer_Overflow` (mp4) | ⭐ | signed bug → nhập số âm mở BOF |
| `iof/Basic_B22_IOF-Type_Casting_Bug` (mp4) | ⭐⭐ | truncation → giá trị cắt-cụt qua kiểm |
| protostar/exploit-education `format`/`stack` biến thể | ⭐⭐ | luyện nhận mẫu signed/trunc |

**Lộ trình:** signed bug (số âm, dễ nhất) → truncation (int→short/char) → multiply-overflow trước
malloc → negative index ([oob.md](oob.md)). Luôn coi integer bug là **bước 1**, nối sang kỹ thuật
chính ở bước 2.

---

## Nguồn tham khảo
- CTF Wiki — *Integer Overflow*: <https://ctf-wiki.mahaloz.re/pwn/linux/integeroverflow/basic_operations/>
- exploit-education (Phoenix/Protostar) — bài integer: <https://exploit.education/>
- Liên quan: [oob.md](oob.md) (negative index) · [ret2libc.md](ret2libc.md) (BOF sau khi qua cửa) · [heap.md](heap.md)
