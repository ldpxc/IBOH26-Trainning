# Hướng dẫn viết bài giảng pwn (đọc TRƯỚC khi viết/sửa bất kỳ file bài giảng nào)

> File này là **chuẩn viết**. Mọi bài giảng trong `cheatsheets/pwn/` phải tuân theo. Mẫu tham chiếu
> đã đạt chuẩn: **[ret2dlresolve.md](ret2dlresolve.md)** — khi phân vân, mở nó ra đối chiếu.

---

## 0. Triết lý cốt lõi (điều quan trọng nhất)

**Mục tiêu: đọc XONG MỘT file là hiểu hết + tự vận dụng được, KHÔNG phải tra cứu ngoài.**

Người đọc là người đang **học** kỹ thuật lần đầu, không phải người đã biết cần nhắc nhanh. Vì vậy:

- ❌ **Cấm viết kiểu cheatsheet hời hợt:** liệt kê thuật ngữ (`_dl_runtime_resolve`, `Elf64_Sym`,
  `.fini_array`, `__malloc_hook`...) rồi bỏ đó. Mỗi thuật ngữ **lần đầu xuất hiện phải được giải
  thích: nó là gì, nằm ở đâu, làm gì, liên quan gì tới kỹ thuật.**
- ❌ **Cấm "nói sơ qua rồi quăng challenge + link writeup bảo tự học".** Writeup/verify chỉ là phụ.
- ✅ **Giảng từng chi tiết một.** Giả định người đọc chưa biết gì về cơ chế nền. Thà dài mà hiểu.
- ✅ **Dạy kỹ năng nhận diện:** sau khi đọc, người học phải biết *nhìn challenge thế nào thì biết
  áp dụng kỹ thuật này*, và *áp dụng theo ý tưởng gì*.

**Phép thử:** nếu người đọc phải lên Google để hiểu một từ bạn vừa dùng → bài giảng đã thất bại ở
chỗ đó. Giải thích nó ngay tại chỗ.

---

## 1. Mỗi bài giảng BẮT BUỘC trả lời đủ các câu hỏi sau

Khi viết, tự kiểm từng câu. Thiếu câu nào là chưa đạt:

1. **Kỹ thuật này giải quyết vấn đề gì?** Vì sao các kỹ thuật trước không đủ, nó ra đời để làm gì.
2. **Cơ chế nền hoạt động thế nào?** Cái cơ chế bình thường của hệ thống (lazy binding, signal
   frame, exit handler, malloc bins...) — giải thích **như nó vốn hoạt động**, trước khi nói ta
   phá nó. Người đọc phải hiểu cơ chế đúng rồi mới hiểu được chỗ lừa.
3. **Kỹ thuật tập trung vào cái gì cụ thể?** Liệt kê rõ:
   - **Vùng nhớ** nào (stack / bss / .data / GOT / .fini_array / heap chunk / libc...)
   - **Biến / cấu trúc** nào (từng trường quan trọng của struct, kèm offset)
   - **Thanh ghi** nào (rdi/rsi/rdx/rip/rsp... và tại sao)
   - **Lỗ hổng đầu vào** nào để trigger (BOF / format string / UAF / off-by-one...)
4. **Vì sao lừa được?** Chỉ đúng chỗ hệ thống *không kiểm tra* → điểm ta chèn giá trị giả.
5. **Cách TỰ TÌM mọi thứ trong GDB / readelf / objdump.** Đây là phần hay bị bỏ nhất và quan trọng
   nhất. Phải có **lệnh cụ thể + giải thích đọc output ra sao** (xem §3).
6. **Luồng / ý tưởng khai thác tổng quát.** Các bước, và điểm then chốt dễ sai.
7. **Cách nhận diện challenge áp dụng được.** Bảng dấu hiệu: điều kiện nào ✅ dùng được, nào ❌ không,
   kèm **giải thích vì sao** (vd "Full RELRO chặn vì...").
8. **Writeup rút gọn** (phụ, cuối bài) + **bài tập theo lộ trình**.

---

## 2. Cấu trúc file chuẩn (theo thứ tự)

```
# <tên kỹ thuật> — <một câu nói nó làm được gì, ngắn gọn dễ nhớ>

> Blockquote mở đầu: "Bài giảng tự chứa. Đọc hết là hiểu: <liệt kê 3-5 thứ sẽ hiểu được>."

## 0. Bạn cần nắm trước (kiến thức nền)   ← BẮT BUỘC nếu kỹ thuật dựa trên cơ chế hệ thống
   - Giải thích từ đầu cơ chế bình thường. Chia tiểu mục 0.1, 0.2...
   - Kết bằng blockquote "Nói ngắn: ..." tóm cả ý tưởng trong 1-2 câu.

## 1. Kỹ thuật tập trung vào cái gì?   ← bảng: Thành phần | Vai trò | Nằm ở đâu
## 2. Mổ xẻ cấu trúc / vùng nhớ chính   ← từng trường, offset, cạm bẫy
## 3. Tự tìm trong GDB / readelf   ← lệnh cụ thể + cách đọc output
## 4. Dựng payload (pwntools và/hoặc tay)
## 5. Nhận diện challenge: khi nào ĐƯỢC / KHÔNG   ← bảng dấu hiệu + giải thích
## 6. Luồng khai thác (ý tưởng tổng quát)
## 7. Writeup rút gọn (tham khảo nhanh)
## 8. Bài tập + lộ trình học
## Nguồn tham khảo
```

Số section linh hoạt theo kỹ thuật, nhưng **thứ tự ý tưởng giữ nguyên**: nền → thành phần → tìm ở
đâu → nhận diện → ý tưởng khai thác → writeup phụ.

---

## 3. Chuẩn cho phần "tìm trong GDB" (phần dễ ăn gian nhất — làm cho tử tế)

Đây là cách biến bài giảng từ lý thuyết thành kỹ năng thực. Với mỗi địa chỉ/biến/cấu trúc then
chốt, phải chỉ rõ:

- **Lệnh gì để lấy nó** (`readelf -d`, `readelf -S`, `objdump -d -j`, `info files`, `x/`,
  `telescope`, `vmmap`, `p &symbol`, `search`...).
- **Output trông thế nào và đọc dòng nào.** Đừng chỉ nói "dùng info files" — nói *tìm dòng nào,
  cột nào, con số đó nghĩa là gì*.
- **Vì sao nó nằm ở đó** (No PIE → cố định; PIE → cộng base; section này ghi được/không...).

Ví dụ mẫu đạt chuẩn (trích ret2dlresolve §3): *"`readelf -d` → tìm dòng `(JMPREL)` = đầu
`.rela.plt`; `(PLTRELSZ)` chia 24 = số relocation thật"*. Đó là mức chi tiết cần đạt.

Với kỹ thuật kiểu `.fini_array`/exit handlers phải nói rõ: **cách nhận biết vị trí nó trên stack
trong GDB**, **cách lấy địa chỉ bằng `info files`**, **cơ chế nó được gọi lúc `exit` (exe_base +
offset cố định)**, và **đổi giá trị ở nơi lưu trong stack thì đổi được cái sẽ bị gọi** — tức dạy
luôn thao tác tay trong debugger, không chỉ kể tên.

---

## 4. Văn phong & quy ước trình bày

- **Tiếng Việt**, giọng giảng bài, giải thích — không phải ghi chú gạch đầu dòng cộc lốc.
- Section đánh số `## 1.`, `## 2.`... Tiểu mục `### 2.1.`.
- Dùng **bảng** cho: liệt kê thành phần, dấu hiệu nhận diện, bài tập.
- Dùng **blockquote `>`** cho "Nói ngắn", cạm bẫy, cảnh báo quan trọng.
- Code block có comment tiếng Việt giải thích **từng dòng làm gì** (nhất là payload).
- Struct C: ghi **offset `+0x..`** và chú thích vai trò từng trường.
- Dùng ✅ ❌ ⚠️ trong bảng nhận diện cho dễ quét.
- Mức độ bài tập: ⭐ → ⭐⭐⭐⭐.
- Link nội bộ tới file liên quan bằng markdown tương đối: `[ret2csu.md](ret2csu.md)`.

---

## 5. Writeup — giữ nhưng rút gọn (đã chốt với người học)

- Writeup **không phải** trọng tâm. Người học tự tìm writeup đầy đủ trên mạng được.
- Giữ **một** ví dụ payload ngắn minh hoạ **luồng** (nguồn C + script pwntools gọn), kèm 1-2 dòng
  "chạy ra shell". **Không** sa đà vào log verify, không dán output dài, không nhiều biến thể.
- Trọng tâm công sức dồn vào §0–§6 (giảng cơ chế + nhận diện), không phải vào chứng minh khả thi.

---

## 6. Checklist trước khi coi là XONG một bài giảng

- [ ] Mọi thuật ngữ đều được giải thích ngay lần đầu xuất hiện (không có từ "mồ côi").
- [ ] Có §0 giảng cơ chế nền từ đầu (nếu kỹ thuật dựa trên cơ chế hệ thống).
- [ ] Nói rõ vùng nhớ + cấu trúc/biến + thanh ghi + lỗ hổng trigger.
- [ ] Có phần tìm-trong-GDB với **lệnh cụ thể + cách đọc output**.
- [ ] Có bảng nhận diện challenge (✅/❌ + vì sao).
- [ ] Có luồng/ý tưởng khai thác tổng quát để tự áp dụng.
- [ ] Writeup rút gọn, không lấn át phần giảng.
- [ ] Người chưa biết gì đọc một lượt là hiểu — tự đọc lại và tự hỏi "có chỗ nào phải Google không?".
