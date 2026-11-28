Video ghi lại buổi phổ biến quy chế thi đấu **Attack & Defense (CTF)** thuộc sự kiện **International Battle of Hackers 2026** tổ chức tại **Asia Pacific University (APU)** (hợp tác cùng FSEC-SS), lần đầu tiên mở rộng cho đối tượng nhân sự trong ngành công nghiệp.

## 1. Thông tin chung & Lịch trình thi đấu

| Mốc thời gian          | Sự kiện                         | Trạng thái tính điểm | Hình thức nhận                        |
| ---------------------- | ------------------------------- | -------------------- | ------------------------------------- |
| Ngày 14/11/2026        | Ngày thi đấu chính thức         | Theo giai đoạn       | Trực tiếp tại Cyber Range & Cisco Lab |
| T - 6 giờ (hoặc 3 giờ) | Gửi file ZIP mã hóa             | Không tính điểm      | Qua Email                             |
| T - 30 phút (10:30)    | Công bố mật khẩu ZIP & URL      | Không tính điểm      | Thông báo tại phòng thi               |
| T - 15 phút (10:45)    | Giai đoạn khởi động (Warm-up)   | Không tính điểm      | Mở hệ thống & VPN                     |
| T - 0 (11:00)          | Bắt đầu thi đấu (Tick đầu tiên) | Có tính điểm         | Hệ thống chạy chính thức              |
| Kết thúc (17:00)       | Đóng hệ thống nộp cờ            | Ngừng tính điểm      | Đóng cổng lúc 17:00                   |

**Chi tiết lịch trình và tiếp cận thông tin:**

- **Địa điểm:** Phòng Cyber Range và Cisco Lab tại APU. Thí sinh gặp khó khăn khi tìm phòng có thể đến quầy đăng ký (Registration Counter) để được hướng dẫn.
- **File công cụ & thông tin đăng nhập:** Ban tổ chức gửi trước một file ZIP có đặt mật khẩu qua email chứa toàn bộ công cụ và cấu hình cần thiết. Mật khẩu giải nén và đường dẫn nền tảng được công bố trực tiếp tại phòng thi trước giờ bắt đầu 30 phút.
- **Giai đoạn Warm-up (10:45 - 11:00):** Hệ thống và VPN mở trước 15 phút để các đội kiểm tra kết nối VPN, SSH, làm quen với 5 máy chủ mục tiêu (vulnboxes) và có thể bắt đầu vá lỗi (patching) ngay trong thời gian này mà chưa bị tính điểm.

## 2. Cơ chế nền tảng & Hạ tầng kỹ thuật (Vulnbox)

| Hạng mục           | Thông số   | Chu kỳ / Giới hạn     | Ghi chú vận hành      |
| ------------------ | ---------- | --------------------- | --------------------- |
| Thời lượng 1 Tick  | 5 phút     | 12 ticks mỗi giờ      | Đơn vị vòng đấu       |
| Thời hạn Cờ (Flag) | 3 ticks    | Khoảng 15 phút        | Hết hạn sau 3 ticks   |
| Hồi chiêu Reset    | 60 phút    | Tính riêng từng bài   | Reset toàn bộ vulnbox |
| Checker kiểm tra   | Ngẫu nhiên | Lệch 1 đến 2 phút     | Kiểm tra SLA mọi đội  |
| Cấu hình Vulnbox   | 256 MB RAM | 1 vCPU, 256 MB bộ nhớ | 5 máy chủ mỗi đội     |

**Hướng dẫn vận hành nền tảng và Vulnbox:**

- **Bộ công cụ tích hợp sẵn trên nền tảng:** Hỗ trợ 4 tác vụ cơ bản gồm nộp cờ (Flag Submission), truy cập VPN và SSH vào vulnbox, danh sách địa chỉ IP của các vulnbox, và cài đặt khóa cá nhân (Private Key Setup).
- **Đặc điểm Vulnbox:** Mỗi đội nhận 5 vulnbox (mỗi máy chạy 1 dịch vụ đại diện cho 1 bài thi/category). Đây là các máy chủ Linux rút gọn (lightweight container), có kết nối Internet trực tiếp, được cài sẵn công cụ hỗ trợ vá lỗi là curl và nano, nhưng đã gỡ bỏ hoàn toàn giao thức truyền file SCP.
- **Cơ chế vá lỗi (Patching):** Các dịch vụ chạy dưới trình quản lý tiến trình supervisord. Sau khi chỉnh sửa mã nguồn trực tiếp trên máy chủ, thí sinh khởi động lại dịch vụ bằng lệnh `supervisorctl restart svc`.
- **Giới hạn tài nguyên:** Mỗi vulnbox chỉ có 256 MB RAM, 1 vCPU và 256 MB dung lượng lưu trữ. Nếu vượt quá giới hạn tài nguyên, vulnbox sẽ tự động bị tắt (terminated) và đội thi bắt buộc phải dùng quyền Reset (chịu thời gian chờ 60 phút cho bài đó) để khôi phục lại.

## 3. Luật thi đấu, Giám sát & Cách tính điểm

| Nhóm quy định    | Hành vi bị cấm                        | Quy định cho phép                           | Mức xử phạt                             |
| ---------------- | ------------------------------------- | ------------------------------------------- | --------------------------------------- |
| Tại phòng thi    | Dùng điện thoại, mạng xã hội, AI      | Ra ngoài nghe điện thoại, tra Google/GitHub | Cảnh cáo đến loại trực tiếp             |
| Kết nối mạng     | Mạng ngoài không phép                 | Chỉ dùng Wi-Fi Guest APU                    | Theo quy tắc 3 lỗi                      |
| Trên hệ thống    | DoS, chặn Firewall, nâng quyền Docker | Phá hủy dịch vụ bên trong container         | Thưởng 200 RM nếu báo lỗi Docker escape |
| Quét & Đường hầm | Port scan, Mass scan, التunneling     | Dùng công cụ phân tích gói tin hợp lệ       | Theo quy tắc 3 lỗi                      |

**Chi tiết quy định và giám sát:**

- **Quy định tại phòng thi (On the ground):**
- **Cấm điện thoại trong phòng:** Mọi hoạt động nhắn tin, nghe gọi phải thực hiện bên ngoài phòng thi; laptop bắt buộc phải để lại trên bàn trong phòng.
- **Cấm mạng xã hội & liên lạc ngoài:** Không sử dụng WhatsApp, Email, Discord hoặc đăng bài về cuộc thi trong suốt thời gian diễn ra.
- **Cấm tuyệt đối AI:** Không dùng chatbot, trợ lý ảo, công cụ tích hợp AI và bắt buộc phải tắt tính năng Google AI Overview trên trình duyệt.
- **Kết nối Wi-Fi:** Chỉ kết nối vào mạng Wi-Fi khách của trường (Guest APU). Trường hợp mạng APU gặp sự cố giới hạn, ban tổ chức mới cho phép dùng Hotspot cá nhân.

- **Quy định trên nền tảng (On the platform):**
- **Cấm tấn công từ chối dịch vụ mạng (Flooding/DoS):** Không được spam IP của đội khác hoặc hạ tầng ban tổ chức.
- **Cấm thoát khỏi container (Docker Escape):** Nếu phát hiện lỗ hổng thoát khỏi Docker và báo cáo cho ban tổ chức, đội thi sẽ nhận phần thưởng (bounty) trị giá 200 Ringgit Malaysia.
- **Cấm chặn tường lửa (Firewall blocking):** Không được dùng công cụ kiểm soát truy cập để chặn IP của các đội khác hoặc hệ thống.
- **Cấm tạo đường hầm (Tunneling):** Nghiêm cấm sử dụng Tailscale, ngrok, SSH tunneling hoặc các công cụ tương tự.
- **Cấm quét diện rộng và quét cổng:** Không dùng các trình quét lớn như Nessus, Nmap để quét cổng hay quét mạng. Mọi thao tác tấn công chỉ được diễn ra bên trong mạng VPN.

- **Quy tắc 3 lần vi phạm (Three strikes) & Trọng tài (Referee):**
- Mỗi đội có 1 trọng tài riêng theo dõi màn hình trong suốt cuộc thi và là đầu mối tiếp nhận câu hỏi, khiếu nại hoặc hỗ trợ kỹ thuật.
- **Vi phạm lần 1:** Trọng tài nhắc nhở bằng lời và ghi nhận lỗi vào hồ sơ đội.
- **Vi phạm lần 2:** Cảnh cáo lần cuối.
- **Vi phạm lần 3:** Loại trực tiếp khỏi bảng xếp hạng (Disqualification) và không giải quyết khiếu nại trong ngày thi.

- **Tiêu chí chấm điểm thắng cuộc (3 yếu tố tổng hợp ở tick cuối cùng):**

1. **Điểm tấn công (Attack):** Số lượng cờ chiếm được từ đội khác và nộp thành công trước khi hết hạn (3 ticks).
2. **Điểm phòng thủ (Defense):** Số vòng (ticks) giữ cho cờ của đội mình không bị đội khác chiếm đoạt.
3. **Điểm duy trì dịch vụ (SLA):** Giữ dịch vụ hoạt động ổn định và vượt qua các đợt kiểm tra ngẫu nhiên từ kịch bản Checker.

## 4. Tổng hợp chi tiết toàn bộ phần Hỏi - Đáp (Q&A)

| STT | Chủ đề câu hỏi         | Nội dung câu hỏi từ thí sinh                                               | Phản hồi chính thức từ Ban tổ chức                                                                                                                              |
| --- | ---------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Giao tiếp nội bộ       | Làm sao để giao tiếp hoặc chia sẻ script với đồng đội?                     | Có thể mở một HTTP server nội bộ bên trong mạng VPN để chia sẻ.                                                                                                 |
| 2   | Mạng APU chặn          | Mạng Wi-Fi APU có chặn các đòn tấn công không?                             | Không, vì toàn bộ tấn công diễn ra bên trong VPN nên mạng APU không phát hiện hay chặn.                                                                         |
| 3   | Thưởng lỗi Docker      | Tiền thưởng (bounty) cho lỗi Docker Escape là bao nhiêu?                   | Mức thưởng hiện tại là 200 Ringgit Malaysia (RM).                                                                                                               |
| 4   | Dùng máy chủ tại nhà   | Có được dùng Tailscale kết nối về server cá nhân ở nhà không?              | Không cho phép Tailscale hay mang máy bàn; phải chuẩn bị sẵn mọi công cụ trên laptop cá nhân.                                                                   |
| 5   | Bắt gói tin mạng       | Có được sử dụng công cụ tcpdump và Tulip không?                            | Được phép dùng cả hai, nhưng tcpdump không được cài sẵn trong container.                                                                                        |
| 6   | Truyền file vá lỗi     | Không có SCP thì tải file vá lỗi (Pwn/Rev) lên server bằng cách nào?       | Sử dụng lệnh `curl` để tải file lên vì mỗi vulnbox đều có kết nối Internet trực tiếp.                                                                           |
| 7   | Kết nối SSH ra ngoài   | Có được SSH ra IP bên ngoài qua Wi-Fi APU để lấy dữ liệu không?            | Được phép truy cập lấy công cụ (như lên Google, GitHub, server riêng), nhưng tuyệt đối cấm tạo SSH tunneling.                                                   |
| 8   | Thuật ngữ phòng thủ    | Có quy định nào về "Superman defense" không?                               | Ban tổ chức không rõ thuật ngữ này, miễn là phương thức phòng thủ không vi phạm các luật đã nêu trên slide.                                                     |
| 9   | Số lượng file VPN      | Đội 3 người dùng 2 laptop thì nhận mấy file cấu hình VPN?                  | Hệ thống cấp tự động 1 file VPN cho mỗi tài khoản; nếu dùng 2 laptop cho 1 tài khoản thì dùng chung file cấu hình đó.                                           |
| 10  | Đa kết nối VPN         | Một file cấu hình VPN có cho phép 2 thiết bị kết nối cùng lúc không?       | Ban tổ chức cho phép thử trong giờ Warm-up, nhưng việc kết nối đồng thời có hoạt động hay không phụ thuộc vào nền tảng tự động.                                 |
| 11  | Cài thêm công cụ       | Có thể tự tải binary của tcpdump hoặc dùng git trên vulnbox không?         | Không có sẵn git và tcpdump; có thể tự tải binary lên nhưng phải chú ý giới hạn 256 MB để tránh sập máy chủ.                                                    |
| 12  | Phá hoại sau khai thác | Có giới hạn nào về kỹ thuật lấy cờ hoặc tấn công hậu khai thác không?      | Khuyến khích thực hiện Post-Exploitation và Incident Response: được phép cài mã độc, mã hóa file, tắt dịch vụ hoặc dùng fork bomb làm sập container đối phương. |
| 13  | Thử nghiệm API         | Có thời gian chạy thử để kiểm tra API nộp cờ tự động không?                | Có thể kiểm tra đầy đủ trong 15 phút giai đoạn Warm-up trước giờ tính điểm.                                                                                     |
| 14  | Vị trí lưu Cờ          | Lệnh đọc cờ tiêu chuẩn cho mọi dịch vụ có phải là đọc file flag.txt không? | Cờ nằm ở đường dẫn gốc, sử dụng lệnh `cat /flag` thay vì đọc file flag.txt.                                                                                     |
| 15  | Dạng bài thi           | Các thử thách là Whitebox (hộp trắng) hay Blackbox (hộp đen)?              | Đa số là Whitebox, chỉ có 1 hoặc 2 bài Blackbox bị khóa SSH lúc đầu và yêu cầu phải khai thác lấy cờ đầu tiên mới mở khóa được SSH.                             |
| 16  | Cấu trúc thư mục       | Mã nguồn bài thi nằm ở thư mục người dùng hay ở đâu?                       | Mã nguồn đã được tích hợp sẵn và quản lý dưới supervisord; cấu trúc tên file mỗi bài khác nhau nhưng đều khởi động lại qua lệnh `supervisorctl restart svc`.    |
| 17  | Số lượng dịch vụ       | Mỗi đội có bao nhiêu dịch vụ và thuộc những mảng nào?                      | Mỗi đội có 5 dịch vụ tương ứng 5 vulnbox; các mảng (categories) cụ thể được giữ bí mật trước giờ thi.                                                           |

**Chi tiết giải thích bổ sung từ phần Hỏi - Đáp:**

- **Định hướng chiến thuật (Post-Exploitation & Incident Response):** Ban tổ chức nhấn mạnh cuộc thi không chỉ dừng lại ở việc khai thác lỗ hổng lấy cờ mà khuyến khích tấn công hậu khai thác. Khi chiếm được quyền truy cập vào vulnbox của đội khác, thí sinh được phép để lại backdoor, script độc hại, mã hóa dữ liệu, tắt dịch vụ hoặc dùng fork bomb để đánh sập container của đối thủ (ép đối thủ mất điểm SLA hoặc phải tốn lượt Reset có thời gian chờ 60 phút). Ngược lại, đội phòng thủ phải chủ động rà soát và gỡ bỏ các script độc hại đó trên máy chủ của mình.
- **Cơ chế mở khóa SSH đối với bài Blackbox:** Đây là chi tiết quan trọng được người thuyết trình bổ sung ngoài slide. Một số bài thi dạng Blackbox sẽ không cho phép truy cập SSH ngay khi bắt đầu mà đòi hỏi đội thi phải khai thác dịch vụ thành công và nộp được lá cờ đầu tiên (first flag submission) thì quyền truy cập SSH vào vulnbox đó mới được mở để thực hiện vá lỗi.
