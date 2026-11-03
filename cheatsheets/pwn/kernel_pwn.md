# Kernel pwn (nhập môn) — khai thác lỗ hổng trong nhân Linux

> **Bài giảng định hướng (tự chứa cho mức nhập môn).** Đọc hết là hiểu: khai thác kernel khác
> userland ở chỗ nào, **mục tiêu cuối** là gì (leo lên root), các **lá chắn** (KASLR/SMEP/SMAP/KPTI)
> và cách vượt, các **đích khai thác kinh điển** (`modprobe_path`, `cred`, ret2usr), **cách dựng môi
> trường chạy/debug (QEMU + initramfs + GDB)**, và **nhìn challenge thế nào thì biết hướng nào**.
> Đây là tier **stretch xa** (chưa có bài local) → bài giảng này là bản đồ + nguồn luyện, không phải
> writeup một bài cụ thể.

---

## 0. Bạn cần nắm trước: kernel vs userland

Chương trình thường chạy ở **ring 3 (user mode)**, quyền hạn chế. Nhân Linux chạy ở **ring 0
(kernel mode)**, toàn quyền phần cứng. Ta tương tác với kernel qua **syscall** và qua các
**device driver** — đặc biệt là **LKM (Loadable Kernel Module)** tạo ra `/dev/<tên>` mà CTF hay
dùng: ta `open("/dev/foo")` rồi `read/write/ioctl` để chạm vào code kernel có bug.

Khác biệt cốt lõi so với userland:
- **Bug ở ring 0** → nếu chiếm được luồng thực thi trong kernel, ta chạy code **với quyền tối cao**
  → mục tiêu không phải `system("/bin/sh")` mà là **biến tiến trình hiện tại thành root** rồi mở
  shell ở userland.
- **Crash = kernel panic** (sập cả máy ảo), debug khó hơn → luôn chạy trong **QEMU** có GDB stub.
- **Không có libc**; thay vào đó là các hàm/biến kernel (`commit_creds`, `prepare_kernel_cred`,
  `modprobe_path`…), địa chỉ tra trong `/proc/kallsyms` hoặc `System.map`.

> **Nói ngắn:** *tìm bug trong một driver `/dev/*` (hoặc syscall), chiếm control flow ở ring 0, rồi
> nâng quyền tiến trình user của ta lên root (`commit_creds(prepare_kernel_cred(0))`) hoặc ghi
> `modprobe_path` để chạy script root — cuối cùng return an toàn về userland và `exec` shell.*

---

## 1. Mục tiêu cuối — ba cách "thành root"

| Cách | Làm gì | Khi nào |
|------|--------|---------|
| **`commit_creds(prepare_kernel_cred(0))`** | gọi 2 hàm kernel → cấp `cred` root cho tiến trình hiện tại; xong `return` ra user rồi `exec("/bin/sh")` | có **control flow** (ghi được con trỏ hàm / ROP kernel) |
| **Ghi đè `modprobe_path`** | đổi biến global `modprobe_path` (mặc định `/sbin/modprobe`) thành script của ta; rồi trigger kernel chạy modprobe (exec file "lạ") → script chạy **với quyền root** | có **arbitrary write** nhưng khó control flow |
| **Ghi đè `cred` của task** | tìm `struct cred` của tiến trình, zero các uid/gid | có arbitrary write + leak được `task_struct` |

`modprobe_path` thường **dễ nhất** khi chỉ có arbitrary write: chỉ cần ghi một chuỗi, không cần ROP
kernel, không cần vượt SMEP/SMAP cho việc thực thi.

---

## 2. Lá chắn kernel & cách vượt

| Lá chắn | Chặn gì | Vượt thế nào |
|---------|---------|--------------|
| **KASLR** | random base kernel | **leak** một địa chỉ kernel (từ dmesg, OOB read, con trỏ rò) → suy base |
| **SMEP** (CR4 bit 20) | kernel **không thực thi** được code ở trang user → chặn ret2usr | **ROP trong kernel** (không nhảy ra user), hoặc tắt SMEP bằng ghi CR4 |
| **SMAP** (CR4 bit 21) | kernel **không đọc/ghi** trực tiếp bộ nhớ user | ROP hoàn toàn trong kernel; đặt dữ liệu trong kernel space |
| **KPTI** | tách bảng trang kernel/user → return ra user phải qua trampoline | dùng **`swapgs_restore_regs_and_return_to_usermode`** (KPTI trampoline) để về user đúng cách, hoặc `signal handler`/`iretq` khung |

**ret2usr** (cổ điển, khi **không** có SMEP): trỏ con trỏ hàm kernel vào **shellcode nằm ở userland**
(ta mmap sẵn) chạy `commit_creds(...)`. SMEP bật thì phải **ROP trong kernel** thay vì ret2usr.

---

## 3. Các bug class thường gặp (như userland nhưng ở ring 0)

- **Stack/heap overflow trong driver** → kernel ROP.
- **UAF / double-free** trên **slab (kmalloc)** → **heap spray** + **cross-cache**; đích thường là
  cấu trúc có con trỏ hàm (`tty_struct`, `pipe_buffer`…).
- **OOB read/write** trong `ioctl` (thiếu kiểm index/size — xem [oob.md](oob.md), [integer_bugs.md](integer_bugs.md)).
- **Double-fetch** (đọc giá trị user 2 lần trong syscall) → race ([race_condition.md](race_condition.md)).
- **CVE thực tế:** dirtypipe (CVE-2022-0847), dirtycow — đọc để hiểu primitive thật.

---

## 4. Dựng môi trường chạy & debug (bước thực hành bắt buộc)

Đề kernel thường cho: `bzImage` (kernel nén), `initramfs.cpio.gz` (rootfs), `run.sh` (lệnh QEMU).
```bash
# 1) giải nén rootfs để xem/đổi init, thêm exploit đã build tĩnh:
mkdir fs && cd fs && zcat ../initramfs.cpio.gz | cpio -idm
#   build exploit:  gcc -static -o exploit exploit.c  ; copy vào fs/ ; đóng gói lại cpio
# 2) chạy QEMU (thường run.sh có sẵn); để debug thêm -s (gdb stub :1234) và -S (dừng chờ):
#    qemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio.gz -append "console=ttyS0 ..." -s
# 3) GDB:
gdb vmlinux            # (nếu có vmlinux; trích từ bzImage bằng extract-vmlinux)
(gdb) target remote :1234
(gdb) b *<địa chỉ hàm driver>
```
Lấy địa chỉ symbol kernel (nếu đề cho quyền): `cat /proc/kallsyms | grep commit_creds` (thường bị
che `0000...` nếu không root → phải **leak**). `modprobe_path`, `commit_creds`,
`prepare_kernel_cred` tra trong `System.map`/`kallsyms`.

> **Quan trọng:** `/proc/kallsyms` bị ẩn địa chỉ với user thường (`kptr_restrict`). Nên trong thực
> chiến phải **leak KASLR base** rồi cộng offset tĩnh (đo offset giữa các symbol từ `vmlinux` cục bộ).

---

## 5. Nhận diện: hướng nào cho challenge nào?

| Dấu hiệu đề | Hướng |
|------------|-------|
| Có `/dev/*` + driver `.ko` + `ioctl` | đọc driver, tìm overflow/OOB/UAF trong handler |
| Chỉ có **arbitrary write**, khó control flow | **`modprobe_path`** (dễ nhất) |
| Có **control flow** (ghi con trỏ hàm / ROP) | `commit_creds(prepare_kernel_cred(0))` |
| SMEP **tắt** | ret2usr (shellcode ở user) |
| SMEP/SMAP **bật** | ROP toàn bộ trong kernel + KPTI trampoline để về user |
| UAF trên slab | heap spray cấu trúc có con trỏ hàm (`tty_struct`/`pipe_buffer`), cross-cache |

**Phản xạ:** *(1) có control flow hay chỉ có write?* → chọn `commit_creds` hay `modprobe_path`.
*(2) SMEP bật?* → ret2usr được không hay phải ROP kernel. *(3) KASLR?* → cần leak trước.

---

## 6. Luồng khai thác tiêu biểu (ROP kernel + commit_creds)

1. **Leak KASLR** (OOB read / dmesg / con trỏ rò) → kernel base.
2. **Lưu trạng thái user** (cs/ss/rflags/rsp/rip) để quay về sau (`save_state` bằng asm).
3. **Chiếm control flow** trong driver → **kernel ROP**: gọi `prepare_kernel_cred(0)` → `rdi =
   kết quả` → `commit_creds(...)`.
4. **Return về user an toàn** qua **KPTI trampoline** (`swapgs_restore_regs_and_return_to_usermode`)
   với khung cs/ss/rip trỏ về hàm user chạy `system("/bin/sh")`.
5. Shell chạy với **uid=0**.

Với `modprobe_path`: bỏ bước ROP — chỉ **ghi `modprobe_path = "/tmp/x"`**, tạo file thực thi "định
dạng lạ" rồi `execve` nó (kernel không nhận dạng → gọi modprobe = chạy `/tmp/x` **as root**).

---

## 7. Bài tập + lộ trình (chưa có bài local → nguồn ngoài)

| Nguồn | Mức | Học gì |
|-------|-----|--------|
| **pwn.college — Kernel Exploitation** | ⭐⭐⭐ | 8 level tăng dần, có hint — <https://pwn.college/software-exploitation/kernel-exploitation> |
| **lkmidas — Learning Linux Kernel Exploitation** | ⭐⭐⭐ | chuỗi bài step-by-step (ret2usr → SMEP → SMAP → KPTI) |
| **ctf-wiki kernel** | ⭐⭐ | tổng quan bug class + protection |
| **dirtypipe/dirtycow writeups** | ⭐⭐⭐⭐ | CVE thực tế |

**Lộ trình:** dựng QEMU+GDB chạy được 1 module → ret2usr (SMEP tắt) → `commit_creds` ROP (SMEP bật)
→ KPTI trampoline → `modprobe_path` (arbitrary write) → UAF slab + heap spray → cross-cache/CVE thật.

---

## Nguồn tham khảo
- pwn.college — Kernel Exploitation: <https://pwn.college/software-exploitation/kernel-exploitation>
- lkmidas — *Learning Linux Kernel Exploitation*: <https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/>
- CTF Wiki — *Kernel*: <https://ctf-wiki.mahaloz.re/pwn/linux/kernel/>
- Liên quan: [oob.md](oob.md), [integer_bugs.md](integer_bugs.md), [race_condition.md](race_condition.md)
