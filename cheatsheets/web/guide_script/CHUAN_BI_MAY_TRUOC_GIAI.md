# Chuẩn bị máy trước ngày thi (gửi đồng đội, làm khi còn Internet)

Danh sách này phục vụ đúng bộ cheatsheet `guide_script/` (xem `README.md`). **Tất cả bước dưới đây cần Internet — phải làm trước ngày thi**, vì lúc thi không có mạng.

Giả định máy chạy Linux kiểu Ubuntu/Debian (dùng `apt`). Nếu máy khác (Mac/Windows/WSL), đổi lệnh cài phần mềm hệ thống ở Bước 1 cho đúng (brew/choco/...), các bước còn lại (pip, git clone) giữ nguyên.

---

## 1. Phần mềm hệ thống

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git perl php-cli gcc make maven openjdk-11-jdk openjdk-21-jdk
```

| Gói | Dùng cho |
|---|---|
| `python3`, `python3-venv`, `python3-pip` | Chạy toàn bộ script trong cheatsheet |
| `git` | Clone tool + clone chính repo cheatsheet này |
| `perl` | Chạy `PadBuster` |
| `php-cli` | Chạy `phpggc`, test chuỗi filter của `php_filter_chain_generator` |
| `gcc`, `make` | Build `hash_extender` |
| `maven` | Build `ysoserial` từ source |
| `openjdk-11-jdk` | **Bắt buộc** để chạy `ysoserial` đúng — JDK 21 mặc định sẽ báo lỗi `InaccessibleObjectException` |
| `openjdk-21-jdk` | Dùng cho mọi việc Java khác bình thường (giữ cả 2 bản JDK, không gỡ bản nào) |

**Burp Suite**: cài riêng (Community hoặc Pro) từ https://portswigger.net/burp — không có trong `apt`.

---

## 2. Tạo venv Python riêng + alias kích hoạt nhanh

```bash
mkdir -p ~/hoc/CTF/Tools/venv ~/hoc/CTF/Tools/web
python3 -m venv ~/hoc/CTF/Tools/venv/pwn
echo 'alias spwn="source ~/hoc/CTF/Tools/venv/pwn/bin/activate"' >> ~/.bashrc   # dùng ~/.zshrc nếu máy chạy zsh
source ~/.bashrc
spwn
```

Từ giờ, mỗi khi mở terminal mới cần chạy script/tool Python trong cheatsheet, gõ `spwn` trước.

---

## 3. Cài thư viện Python (đang trong venv, đã `spwn`)

Sau khi đã `git clone` repo cheatsheet này (bước 8), chạy đúng 1 lệnh ở gốc `guide_script/`:

```bash
pip install -r requirements.txt
```

Nếu chưa clone repo kịp, cài tay tương đương:

```bash
pip install requests beautifulsoup4 lxml PyYAML tenacity pyjwt flask flask-unsign websocket-client pycryptodome
```

| Thư viện | Dùng cho |
|---|---|
| `requests` | Toàn bộ script gửi HTTP — thư viện quan trọng nhất |
| `beautifulsoup4`, `lxml` | Đọc/trích dữ liệu từ HTML (lấy CSRF token...) |
| `PyYAML` | Đọc file cấu hình dạng YAML nếu cần |
| `pyjwt` | Bài `JWT_Attacks.md`, `02_Chuoi_Request/05_Tinh_Toan_Cuc_Bo.md` |
| `flask`, `flask-unsign` | Bài `Session_Cookie_Forge.md` |
| `websocket-client` | Bài `03_Thao_Tac_Nang_Cao/04_WebSocket.md` |
| `pycryptodome` | Các bài crypto cần tự mã hoá/giải mã (padding oracle, hash length extension) |

---

## 4. Clone toàn bộ tool vào `~/hoc/CTF/Tools/web/`

```bash
cd ~/hoc/CTF/Tools/web

git clone --depth 1 https://github.com/commixproject/commix.git commix
git clone --depth 1 https://github.com/epinna/tplmap.git tplmap
git clone --depth 1 https://github.com/defparam/smuggler.git smuggler
git clone --depth 1 https://github.com/dolevf/graphql-cop.git graphql-cop
git clone --depth 1 https://github.com/nikitastupin/clairvoyance.git clairvoyance
git clone --depth 1 https://github.com/s0md3v/XSStrike.git XSStrike
git clone --depth 1 https://github.com/synacktiv/php_filter_chain_generator.git php_filter_chain_generator
git clone --depth 1 https://github.com/arthaud/git-dumper.git git-dumper
git clone --depth 1 https://github.com/internetwache/GitTools.git GitTools
git clone --depth 1 https://github.com/iagox86/hash_extender.git hash_extender
git clone --depth 1 https://github.com/AonCyberLabs/PadBuster.git padbuster
git clone --depth 1 https://github.com/ticarpi/jwt_tool.git jwt_tool
git clone --depth 1 https://github.com/ambionics/phpggc.git phpggc
git clone https://github.com/frohoff/ysoserial.git ysoserial
git clone --depth 1 https://github.com/tarunkant/Gopherus.git Gopherus
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git PayloadsAllTheThings
git clone --depth 1 https://github.com/danielmiessler/SecLists.git SecLists
git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git exploitdb
```

> `SecLists` và `PayloadsAllTheThings` khá nặng (vài trăm MB) — clone sớm, kiểm tra còn đủ dung lượng đĩa.
> `ysoserial` clone KHÔNG dùng `--depth 1` vì bước build cần đầy đủ (dùng maven).

| Tool | Dùng ở bài |
|---|---|
| `commix` | `Command_Injection.md` |
| `tplmap` | `SSTI.md` |
| `smuggler` | `HTTP_Request_Smuggling.md` |
| `graphql-cop`, `clairvoyance` | `GraphQL.md` |
| `XSStrike` | `XSS_CSRF.md`, `XSS_Filter_CSP_Bypass.md` |
| `php_filter_chain_generator` | `Path_Traversal_LFI.md` |
| `git-dumper`, `GitTools` | `Recon_Source_Leak.md` |
| `hash_extender` | `Crypto_Hash_Length_Extension.md` |
| `padbuster` | `Crypto_Padding_Oracle.md` |
| `jwt_tool` | `JWT_Attacks.md` |
| `phpggc`, `ysoserial` | `Deserialization.md` |
| `Gopherus` | SSRF qua gopher:// (payload khai thác Redis/Memcached nội bộ) |
| `PayloadsAllTheThings`, `SecLists` | Kho payload/wordlist tra cứu offline khi payload mẫu không ăn |
| `exploitdb` | Tra CVE/exploit có sẵn khi challenge dùng phần mềm/CMS cụ thể |

---

## 5. Build / cài thêm cho từng tool (sau khi clone xong)

```bash
# hash_extender -- build bằng C
cd ~/hoc/CTF/Tools/web/hash_extender && make && cd ..

# ysoserial -- build bằng maven (mất vài phút)
cd ~/hoc/CTF/Tools/web/ysoserial && mvn -q clean package -DskipTests && cd ..

# jwt_tool, graphql-cop, XSStrike -- mỗi tool có requirements.txt riêng, cài vào ĐÚNG venv pwn
spwn
pip install -r ~/hoc/CTF/Tools/web/jwt_tool/requirements.txt
pip install -r ~/hoc/CTF/Tools/web/graphql-cop/requirements.txt
pip install -r ~/hoc/CTF/Tools/web/XSStrike/requirements.txt
```

**Nhớ**: chạy `ysoserial` luôn bằng JDK 11, không phải JDK mặc định của máy:

```bash
/usr/lib/jvm/java-11-openjdk-amd64/bin/java -jar ~/hoc/CTF/Tools/web/ysoserial/target/ysoserial-*-all.jar <gadget> '<command>'
```

---

## 6. CyberChef (không phải git repo — tải file HTML đơn, dùng offline không cần server)

```bash
mkdir -p ~/hoc/CTF/Tools/web/CyberChef && cd ~/hoc/CTF/Tools/web/CyberChef
# Lấy đúng link bản mới nhất ở https://github.com/gchq/CyberChef/releases, ví dụ bản 11.6.0:
wget https://github.com/gchq/CyberChef/releases/download/v11.6.0/CyberChef_v11.6.0.zip
unzip CyberChef_v11.6.0.zip && rm CyberChef_v11.6.0.zip
```

Dùng: mở file `CyberChef_v11.6.0.html` bằng trình duyệt — không cần chạy server, không cần Internet sau khi đã mở trang 1 lần.

---

## 7. Kiểm tra lại mọi thứ đã sẵn sàng (chạy hết không lỗi là xong)

```bash
spwn
python3 -c "import requests, bs4, jwt, flask, websocket, Crypto; print('OK: thu vien python')"

python3 ~/hoc/CTF/Tools/web/commix/commix.py --help > /dev/null && echo "OK: commix"
python3 ~/hoc/CTF/Tools/web/tplmap/tplmap.py --help > /dev/null && echo "OK: tplmap"
python3 ~/hoc/CTF/Tools/web/XSStrike/xsstrike.py --help > /dev/null && echo "OK: XSStrike"
python3 ~/hoc/CTF/Tools/web/graphql-cop/graphql-cop.py --help > /dev/null && echo "OK: graphql-cop"
python3 -m venv --help > /dev/null && python3 ~/hoc/CTF/Tools/web/git-dumper/git_dumper.py --help > /dev/null && echo "OK: git-dumper"
python3 ~/hoc/CTF/Tools/web/jwt_tool/jwt_tool.py -h > /dev/null && echo "OK: jwt_tool"
perl ~/hoc/CTF/Tools/web/padbuster/padBuster.pl 2>&1 | grep -q "Use:" && echo "OK: PadBuster"
test -x ~/hoc/CTF/Tools/web/hash_extender/hash_extender && echo "OK: hash_extender"
test -f ~/hoc/CTF/Tools/web/ysoserial/target/ysoserial-*-all.jar && echo "OK: ysoserial build xong"
test -f ~/hoc/CTF/Tools/web/phpggc/phpggc && echo "OK: phpggc"
```

---

## 8. Clone chính repo cheatsheet này

```bash
git clone <URL repo IBOH26-Trainning do đội trưởng cung cấp>
cd IBOH26-Trainning/cheatsheets/web/guide_script
cat README.md
```

Nếu repo để **private trên GitHub**, đội trưởng cần thêm từng người làm collaborator trước, hoặc gửi file zip/tarball nếu không muốn cấp quyền GitHub.

Sau khi clone xong, đọc theo đúng thứ tự: [`00_Bat_Dau_Tu_Zero.md`](00_Bat_Dau_Tu_Zero.md) trước, rồi [`CHEATSHEET_NHANH.md`](CHEATSHEET_NHANH.md) để tra cứu nhanh lúc thi.
