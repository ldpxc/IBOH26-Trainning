# IBOH 2026 AD — Toolkit & Truyền file (ĐỌC OFFLINE trong phòng thi)

> Trong phòng **cấm Google/AI**. Cài sẵn mọi thứ TRƯỚC ngày thi. File này + bộ bài
> giảng `iboh26/cheatsheets/pwn/*.html` là tài liệu tra cứu offline của bạn.

---

## 1) Công cụ trên LAPTOP (đã cài đủ — chỉ cần biết dùng venv nào)

Sẵn trong PATH: **Ghidra · gdb + gdb-multiarch + pwndbg · radare2/r2 · one_gadget · seccomp-tools ·
ROPgadget · ropper · pwninit · checksec · patchelf · objdump/readelf/nm/strings · strace/ltrace ·
wireshark · docker**.

Hai môi trường Python (kích hoạt khi cần):
```bash
spwn        # venv Pwn/Rev (alias) = source /home/ld/hoc/CTF/Tools/venv/pwn/bin/activate
#           có: pwntools · capstone · unicorn · keystone · r2pipe · pycryptodome · requests

source /home/ld/hoc/CTF/Tools/venv/angr/bin/activate   # venv angr (symbolic/rev): angr · z3 · sympy
#   gợi ý thêm vào ~/.zshrc:  alias sangr='source /home/ld/hoc/CTF/Tools/venv/angr/bin/activate'
```

Tiện ích riêng của bộ này (`iboh26/tools/`): `pwnld.py` · `pwnretry.py` · `adflag.py` · `vulncheck.py`.

#### Dùng nhanh `vulncheck` (Quét SAST + Lên kịch bản khai thác thực chiến):
```bash
vulncheck service.c --bin ./service          # Quét C/C++ + Checksec ELF lên kịch bản PWN
vulncheck ./service/ -c all -f md -o rep.md  # Quét toàn bộ service xuất báo cáo Markdown
vulncheck app.py -c web                      # Quét Web (SQLi f-string, SSTI, Pickle, SSRF)
vulncheck crypto.py -c crypto                # Quét Crypto (AES-ECB, RSA yếu, PRNG time seed)
vulncheck crackme.c -c rev                   # Quét Rev (Bẫy ptrace, TracerPid, rdtsc timing)
```
*(Chi tiết xem tài liệu đầy đủ tại [`vulncheck.md`](vulncheck.md))*

**Còn thiếu — tự chạy (cần sudo):**
```bash
sudo apt install -y tshark qemu-user-static    # phân tích pcap CLI + chạy binary cross-arch
```
IDA (nếu có) + bỏ `keypatch.py` vào `plugins/`. Không có IDA → **Ghidra** thay được.

---

## 2) File-share server (thay app nhắn tin bị cấm — CHIA SẺ GIỮA ĐỒNG ĐỘI)

**Chạy trên máy bạn**, nghe trên **IP card VPN** (xem bằng `ip -o -4 addr`, thường `tun0`):

```bash
python3 iboh26/tools/fileshare.py --host <IP_VPN_CUA_BAN> --port 8000 --dir ./share \
        --allow <ip_laptop_đồng_đội_1> --allow <ip_laptop_đồng_đội_2>
```
In ra **2 token**: **TOKEN ĐỌC** (tải về/liệt kê) và **TOKEN GHI** (upload) — đọc cho đồng đội.

> ⚠️ **OPSEC (VPN dùng chung với đối thủ → họ cũng reach máy bạn):**
> - **Token GHI và token ĐỌC tách riêng** → ai chỉ có token đọc **không upload/đầu độc** được.
> - **KHÔNG đặt flag / private key / exploit nhạy cảm** vào `share/`.
> - **`--allow`** chỉ IP laptop đồng đội → token lộ cũng khó dùng từ máy lạ.
> - **Đổi token** (khởi động lại server) khi nghi box/đồng đội bị thủng.

| Việc | Lệnh (dùng đúng loại token) |
|---|---|
| Đồng đội **tải lên** | `curl -T exploit.py "http://<H>:8000/u/exploit.py?t=<TOKEN_GHI>"` |
| Đồng đội **tải về** | `curl "http://<H>:8000/f/exploit.py?t=<TOKEN_ĐỌC>" -o exploit.py` |
| Liệt kê | `curl "http://<H>:8000/ls?t=<TOKEN_ĐỌC>"` |
| Trình duyệt | `http://<H>:8000/?t=<TOKEN_GHI>` (mở bằng token ghi mới upload được) |

### 2.1) ⭐ VULNBOX: ĐỪNG dùng fileshare — dùng SSH (token KHÔNG chạm box)

Nếu vulnbox bị chiếm, kẻ tấn công **thấy token trong `ps`/`/proc/<pid>/cmdline` + history** khi bạn
`curl` trên box → tải/đầu độc `share/` của bạn. **Cách an toàn: deploy/exfil bằng SSH**, token không bao giờ lên box:
```bash
cat patch.py | ssh user@10.10.1.10 'cat > /path/app.py'          # ĐẨY bản vá LÊN (mục 5)
ssh user@10.10.1.10 'base64 -w0 /path/svc' | base64 -d > svc     # KÉO file VỀ (mục 4-B)
```
**Nếu BẮT BUỘC vulnbox phải curl** → chạy riêng 1 instance **read-only** chỉ cấp **token đọc**
(không upload được, không đầu độc được):
```bash
python3 iboh26/tools/fileshare.py --host <IP_VPN> --port 8000 --read-only --read-token <TOKEN_ĐỌC>
# trên vulnbox: export HISTFILE=/dev/null ; curl -H "X-Token: <TOKEN_ĐỌC>" http://<H>:8000/f/patch.py -o app.py
# rồi: sha256sum app.py  (so hash — chống bản vá bị đầu độc) ; supervisorctl restart svc
```

---

## 3) ĐƯA FILE **LÊN** vulnbox (không có SCP — dùng curl)

Vulnbox chỉ có **curl + nano**, **có Internet trực tiếp**, **không** scp/git/tcpdump.

```bash
# CÁCH AN TOÀN (khuyên dùng) — SSH, token KHÔNG chạm vulnbox:
cat patch.py | ssh user@10.10.1.10 'cat > /path/app.py'
ssh user@10.10.1.10 'supervisorctl restart svc'

# HOẶC fileshare (chỉ TOKEN ĐỌC, nên chạy instance --read-only — xem mục 2.1):
curl -s "http://<IP_VPN_BAN>:8000/f/patch.py?t=<TOKEN_ĐỌC>" -o /path/app.py && supervisorctl restart svc
```
> Nhớ **256MB disk** — đừng kéo file to lên vulnbox. OPSEC token: xem **mục 2.1**.

### 3.1) Cài tcpdump & công cụ (STATIC binary) lên vulnbox

Vulnbox không có apt/scp/git/tcpdump và chỉ 256MB → thêm công cụ bằng cách **tải binary STATIC**
(chạy không cần thư viện) qua `curl`. **Chuẩn bị TRƯỚC ngày thi** (ở nhà, có mạng): tải sẵn về
`iboh26/tools/vulnbox-bins/`, lúc thi bỏ vào `share/` để vulnbox `curl` từ **fileshare nội bộ**
(nhanh, không phụ thuộc Internet, khỏi nhớ URL).

**Nguồn static binary x86-64 (tải ở nhà) — đều RẤT NHẸ, vài MB:**
- **busybox 1.07MB** (1 file = ps, netstat, nc, vi, wget, tar, find, kill, df, top…):
  `https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox`.
- **socat 0.36MB · ncat 2.78MB** (static): repo `github.com/andrew-d/static-binaries`
  → `binaries/linux/x86_64/`. *(Repo này còn có objdump/readelf/strings/python static nếu cần.)*
- **tcpdump / strace / gdbserver**: KHÔNG có trong repo trên → phải **build static** (~1–3MB/cái),
  hoặc BỎ QUA: **busybox (recon) + log tầng app (mục 5.1b)** đủ xem payload mà không cần chúng.

**Chuẩn bị ở nhà (copy-paste, có mạng):**
```bash
mkdir -p iboh26/tools/vulnbox-bins && cd iboh26/tools/vulnbox-bins
curl -LO https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
SB=https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64
curl -LO $SB/socat ; curl -LO $SB/ncat
chmod +x busybox socat ncat
file busybox          # xác nhận: "ELF 64-bit ... statically linked"
# LÚC THI: copy các file này vào thư mục share/ của fileshare.py (để vulnbox curl về)
```

**Lúc thi — nạp lên vulnbox (qua fileshare nội bộ):**
```bash
# trên vulnbox (SSH whitebox của mình):
curl -s "http://<IP_VPN_BAN>:8000/f/busybox?t=<TOKEN_ĐỌC>" -o /tmp/bb    && chmod +x /tmp/bb
curl -s "http://<IP_VPN_BAN>:8000/f/socat?t=<TOKEN_ĐỌC>"   -o /tmp/socat && chmod +x /tmp/socat
# (nếu đã BUILD static tcpdump/strace thì nạp y hệt rồi chmod +x)
```

**⚠️ Giữ đĩa 256MB:** để ở `/tmp`, **xóa sau khi dùng** (`rm /tmp/bb`). Kiểm đĩa: `/tmp/bb df -h`.
Một `busybox` (1MB) thay rất nhiều lệnh — ưu tiên nó, đừng nạp nhiều binary to.

**Dùng từng công cụ:**
- **busybox — recon nhanh trên box MÌNH (phòng thủ):**
  ```bash
  /tmp/bb netstat -tnp            # AI đang KẾT NỐI tới mình → IP đối thủ + cổng dịch vụ bị đánh
  /tmp/bb netstat -tlnp           # cổng đang MỞ → phát hiện cổng LẠ (reverse shell / backdoor)
  /tmp/bb ps -w                   # mọi tiến trình → tìm tiến trình LẠ đối thủ cài
  /tmp/bb top                     # CPU/RAM → phát hiện fork-bomb / tiến trình ngốn tài nguyên
  /tmp/bb find / -newermt '-5 min' -type f 2>/dev/null   # file tạo trong 5' qua → webshell/backdoor
  ```
  → thấy **ai đang tấn công (IP)** · **tiến trình/file lạ để GỠ** · **tài nguyên để cứu SLA**.
- **Kiểm root trước** (tcpdump cần root): `id` → `uid=0` là root. Không root → thử `sudo` (box tối giản
  có thể KHÔNG có sudo) → không được thì **bỏ tcpdump, dùng `strace` hoặc log tầng app (mục 5.1b)**.
- **tcpdump** (cần root): bắt + stream pcap về laptop — xem **mục 5.1**.
- **strace** (KHÔNG cần root nếu là tiến trình của CHÍNH BẠN) — xem payload attacker **không cần pcap**:
  ```bash
  /tmp/bb ps | grep <tên_svc>       # lấy PID của service
  /tmp/strace -f -p <PID> -e trace=read,write,recvfrom,sendto -s 500 2>trace.txt
  #   read()/recvfrom() = dữ liệu attacker GỬI VÀO ;  -s 500 = in tới 500 byte payload
  ```
  → **rất nhẹ**, thấy ngay bytes attacker gửi. (Nếu bị yama chặn `ptrace` → quay lại log tầng app.)
- **gdbserver** (debug service sống từ laptop): `/tmp/gdbserver --attach :4444 <PID>` rồi ở laptop
  `gdb-multiarch -ex "target remote <vulnbox>:4444"`.
  ⚠️ Cổng 4444 **đối thủ trong VPN cũng reach được** → rủi ro. **An toàn hơn: kéo binary về laptop
  (mục 4) rồi gdb trên laptop.** Chỉ dùng gdbserver khi thật sự cần xem trạng thái đang chạy.

---

## 4) ĐƯA FILE **TỪ** vulnbox VỀ máy để phân tích (câu hỏi #3)

Không có scp. **Ưu tiên theo OPSEC:** box **MÌNH → Cách B (SSH)** · box **ĐỐI THỦ → Cách C**.
Cách A tiện nhưng **lộ TOKEN GHI** nếu chạy trên box đối thủ.

### Cách A — `curl -T` đẩy thẳng về file-share (chỉ cho box MÌNH)
```bash
curl -s -T /path/to/svc_binary "http://<IP_VPN_BAN>:8000/u/svc_binary?t=<TOKEN_GHI>"
```
→ binary xuất hiện ngay trong `share/` trên máy bạn để mở IDA/gdb.
> ⚠️ `curl -T` cần **TOKEN GHI**. Chạy trên **box ĐỐI THỦ** = họ đọc được token ghi (ps/history) →
> **đầu độc `share/` của bạn**. Box đối thủ: **dùng Cách C** (đọc qua kênh exploit), đừng dùng Cách A.

### Cách B — SSH + base64 (vulnbox CỦA MÌNH có SSH, không cần curl về được)
```bash
# chạy TRÊN MÁY BẠN; SSH là HỢP LỆ (chỉ CẤM ssh -L tunneling):
ssh user@<vulnbox> 'base64 -w0 /path/to/svc' | base64 -d > svc        # 1 file
ssh user@<vulnbox> 'tar czf - /home/challenge1 | base64 -w0' | base64 -d | tar xz  # cả thư mục
```
> Dùng khi vulnbox không gọi ngược được tới máy bạn. `base64` thay cho scp.

### Cách C — qua RCE trên box ĐỐI THỦ (blackbox, chưa có SSH)
Bạn chỉ có kênh exploit (socket/HTTP), chưa có shell:
```python
# trong exploit: đọc file & in ra để bắt về (an toàn với binary nhờ base64)
io.sendline(b"cat /path/svc | base64 -w0")   # nếu có command exec
data = base64.b64decode(io.recvall())
open("svc","wb").write(data)
# ĐỪNG ép box đối thủ `curl -T ...token_ghi` — họ sẽ đọc được token GHI của bạn.
# Luôn exfil qua chính kênh exploit (base64 ở trên) để token không lộ.
```
> Blackbox: phải exploit + nộp **first flag** thì mới mở SSH để vá (luật IBOH26).

---

## 5) BẮT & PHÂN TÍCH traffic tấn công (tcpdump → Wireshark)

> Mục tiêu: xem **đội khác đã làm gì với vulnbox của mình**, **lấy luôn payload/exploit của họ** để bắn lại.
> Đòn tấn công đập vào **vulnbox** (10.10.N.10), KHÔNG vào laptop → phải bắt **tại vulnbox**.
> Nhưng **256MB đĩa** → tuyệt đối **đừng ghi pcap trên vulnbox** (đầy đĩa → box chết → Reset 60').

### 5.1 Bắt traffic — stream từ vulnbox VỀ laptop (0 đĩa trên vulnbox)

```bash
# CHẠY TRÊN LAPTOP. tcpdump chạy ở vulnbox, pcap chảy qua SSH về laptop (SSH exec, KHÔNG tunnel).
ssh user@10.10.1.10 'sudo tcpdump -i any -U -s0 -w - "tcp port 9001"' > cap_$(date +%s).pcap
#   -w -  : ghi pcap ra stdout (về laptop)   -s0 : lấy đủ payload   -U : xả ngay
#   "tcp port 9001" : CHỈ bài đó (lọc hẹp để nhẹ CPU/RAM vulnbox).  Ctrl+C khi đủ.
```
- tcpdump **không cài sẵn** trên vulnbox (Q11) → nạp **static tcpdump** trước (xem **mục 3.1**), hoặc dùng 5.1b.
- RAM tcpdump ~10MB (OK với 256MB nếu service chưa kịch trần). **Đừng để chạy liên tục nhiều giờ.**
- 🛠️ **Script sẵn:** `./capture.sh user@10.10.1.10 9001 --open` → tự stream về laptop + mở Wireshark
  lọc sẵn `tcp.port==9001`. Thêm `--bin /tmp/tcpdump` nếu dùng static tcpdump (mục 3.1).

**5.1b — Rẻ nhất, không cần root/tcpdump: LOG ở tầng app** (khuyên dùng khi bí)
```python
# vá app.py: ghi lại request thô của attacker (xoay vòng, cực nhẹ)
open('/tmp/req.log','a').write(repr(data)[:2000]+'\n')
# hoặc đẩy thẳng về laptop: requests.post(f'http://{LAPTOP}:8000/u/req.log?t={T}', data=data)
```
→ thấy **chính xác attacker gửi gì**, gần 0 RAM/đĩa, không cần pcap. Kéo `req.log` về (mục 4).
Snippet đầy đủ (Flask / socket / đẩy về laptop / xoay vòng chống phình đĩa): **`attacker_log.md`**.

### 5.2 Mở & phân tích trong WIRESHARK — từng thao tác (cho người mới)

**Mở:** `wireshark cap_*.pcap`  (hoặc Wireshark → File → Open).
Màn hình 3 phần: **trên** = danh sách gói · **giữa** = chi tiết gói · **dưới** = byte thô (hex).

**Thao tác theo thứ tự — làm đúng là ra ngay:**

1. **Lọc đúng dịch vụ.** Ô **Display filter** (thanh trắng trên cùng) gõ rồi Enter:
   ```
   tcp.port == 9001
   ```
   → chỉ còn gói của bài đó, bỏ nhiễu.

2. **Xem trọn 1 lần tấn công = thao tác QUAN TRỌNG NHẤT.** Chuột phải một gói bất kỳ →
   **Follow → TCP Stream**. Cửa sổ hiện **toàn bộ hội thoại**:
   - **chữ MÀU ĐỎ** = client→server = **CHÍNH XÁC PAYLOAD attacker gửi** (exploit của họ).
   - **chữ MÀU XANH** = server→client = phản hồi (có thể chứa flag bị lấy).
   → Đây là nơi bạn **đọc được exploit đối thủ** và **thấy họ làm gì**.

3. **Lướt qua các lần tấn công khác.** Trong cửa sổ Follow, góc dưới ô **Stream** có mũi tên
   ◀ ▶ (hoặc số) — bấm để qua kết nối kế (mỗi stream = 1 lần khai thác).

4. **Chỉ xem đòn của MỘT đội** (vd đội 3 = 10.10.3.10). Display filter:
   ```
   ip.addr == 10.10.3.10 && tcp.port == 9001
   ```

5. **Bạn có bị LẤY FLAG không?** Display filter:
   ```
   frame matches "flag\{[0-9a-f]{32}\}"
   ```
   → gói nào chứa flag. Nếu flag **đi RA** tới IP đối thủ (server→client) → bài đó **đã bị thủng** → **ưu tiên vá ngay**.

6. **Họ chạy lệnh gì (RCE)?** Trong Follow Stream hoặc dùng filter, tìm chuỗi:
   `/bin/sh`, `cat`, `/flag`, `id`, `curl`, `wget`, `python`, `;`, `|`, `$(`.
   Nhanh: nhấn **Ctrl+F** → chọn **String** + **Packet bytes** → gõ `/flag` → **Find**.

7. **Bỏ gói rỗng** (SYN/ACK không payload): thêm `&& tcp.len > 0` vào filter.

8. **Nếu là dịch vụ HTTP:** filter `http.request` (chỉ request) ; chuột phải →
   **Follow → HTTP Stream** → thấy method, path, header, body (payload trong body/param).

9. **Lấy payload thô ra file** (để tái dựng exploit): trong Follow Stream → **Show data as**:
   chọn **Raw** hoặc **Hex Dump** → nút **Save as…** → lưu payload client→server.

### 5.3 Đọc nhanh — trả lời "họ đã làm gì & lấy được payload"

| Muốn biết | Làm |
|---|---|
| **Payload/exploit của họ** | Follow TCP Stream kết nối từ IP đối thủ → copy phần **đỏ** (client→server) |
| **Họ có lấy flag mình không** | filter `frame matches "flag\{[0-9a-f]{32}\}"`, xem chiều server→client |
| **Họ chạy lệnh/RCE gì** | Ctrl+F tìm `/flag`,`sh`,`cat`,`curl` trong stream |
| **Họ cài backdoor không** | tìm họ ghi/upload file → rà box mình gỡ |

### 5.4 ⚡ Ăn cắp exploit = ghi điểm nhanh nhất
Payload **client→server** của đối thủ chính là **exploit sẵn**. Chỉ việc **đổi IP đích** sang các đội khác là bắn lại toàn bảng:
1. Wireshark → Follow Stream → copy payload đỏ.
2. Dán vào worker Python trong `ad-attack-console` (gửi đúng bytes đó tới `${hostname}:${port}`).
3. Tab **Target VPN** đã có mọi đội → auto bắn mỗi tick → nộp flag.

### 5.5 (Tùy chọn) Tulip — mạnh cho AD
Tulip (docker, **chạy trên laptop**, KHÔNG trên vulnbox) tự gom pcap, nhóm theo "flow", **tự highlight flow chứa flag**, lọc theo tick/service. Tiện khi nhiều traffic. Nhưng **Wireshark + Follow TCP Stream** là đủ và nhanh để bắt đầu.

---

## 6) Vòng lặp VÁ (giữ SLA — service chết là mất điểm)

```bash
# 1) sửa tại chỗ:        nano /path/app.py        (hoặc kéo bản vá: mục 3)
# 2) khởi động lại:      supervisorctl restart svc
# 3) kiểm tra còn sống:  supervisorctl status     +  curl/nc thử dịch vụ
# vá hỏng → service down → mất SLA. Reset vulnbox có cooldown 60'. TEST TRƯỚC.
```

---

## 7) Checklist 15 phút WARM-UP (10:45–11:00, chưa tính điểm)

- [ ] Nối **VPN** (OpenVPN). `ip -o -4 addr` → ghi lại **IP VPN của mình**.
- [ ] SSH vào **5 vulnbox** của mình; đọc source whitebox; vá lỗi lộ rõ ngay.
- [ ] `ping`/`curl` thử 1 IP vulnbox **đối thủ** → xác nhận **reach thẳng trong VPN** (không tunnel).
- [ ] Chạy `fileshare.py` trên IP VPN; từ 1 vulnbox thử `curl .../ping?t=<T>` →
      xác nhận **vulnbox reach được máy bạn** (nếu không → dùng Cách B mục 4).
- [ ] Trong `ad-attack-console` → Cài Đặt Giải Đấu → tab **Target VPN**:
      khai báo **dịch vụ** (Tên + Port) → **Sinh IP các đội** → **③ Sinh & THAY THẾ** →
      kiểm **bảng target đã lưu**. Flag Server (tab TCP) = endpoint BTC.
      Test chuỗi auto-submit bằng **mock gameserver** (format `flag{<md5>}`).
- [ ] Đọc flag chuẩn: **`cat /flag`** (KHÔNG phải flag.txt).

---

## 8) Nhớ nhanh luật (dính 1 = strike, 3 strike = loại)

- ❌ **SSH tunneling / Tailscale / ngrok** · ❌ Nmap/mass-scan · ❌ DoS/flood ·
  ❌ chặn firewall IP đội khác · ❌ AI/điện thoại trong phòng.
- ✅ **HTTP server nội bộ trong VPN** để chia sẻ (file này dùng đúng điều đó).
- ✅ SSH ra ngoài lấy tool (GitHub) được; chỉ **cấm tunneling**.
- ✅ Post-exploitation được khuyến khích (backdoor/kill/fork-bomb box đối thủ) —
  đồng thời **rà gỡ** backdoor đối thủ cài trên box mình.
