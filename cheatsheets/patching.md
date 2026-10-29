# Cheatsheet — Vá (patch) không làm chết dịch vụ

> Phần khó thật (mục 3 README + HT7 + Drill Vá-Sống). Ràng buộc: chỉ sửa code/binary, **không** `Dockerfile`/`compose`; cooldown restart 10 phút → test offline chắc rồi deploy **một lần**.

## Quy trình 6 bước (luôn theo đúng thứ tự)
1. **Backup** file sắp sửa (giữ bản gốc).
2. **Vá** điểm lỗi, nhỏ nhất có thể.
3. **Test exploit** trên bản clone offline → phải **thất bại**.
4. **Test chức năng** / request hợp lệ (như checker) → phải **thành công**.
5. **Deploy + restart** đúng 1 lần.
6. **Verify** checker xanh lại; hỏng thì rollback ngay.

## Vá binary (pwn/rev)
- Giữ nguyên kích thước & offset: sửa hằng số (vd giảm size `read`), NOP đoạn nguy hiểm, đổi nhánh nhảy, vá hex tại chỗ.
- **Code cave**: nhét logic kiểm tra mới vào vùng trống rồi nhảy tới.
- Hook: ghi đè GOT/PLT trỏ hàm nguy hiểm sang wrapper an toàn.
- Công cụ: `pwntools`, **LIEF**, `patchelf`, **keystone**, Ghidra patch, `objcopy`.
- Sau deploy: xác nhận hash/`file`/kiến trúc của binary đang chạy.

## Vá web/source
- Parameterized query, whitelist input, output-encoding, ép kiểu, giới hạn độ dài.
- Middleware/filter mini-WAF nhưng **vẫn cho checker đi qua**.
- Vá config lộ: tắt debug, bịt `.git`/backup, sửa quyền file flag, bỏ endpoint thừa.
- **Rủi ro lớn nhất: chặn nhầm checker → mất SLA. Test mỗi rule với checker trước khi bật.**

<!-- Thêm mục của đội bên dưới -->
