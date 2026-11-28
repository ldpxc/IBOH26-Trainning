# Deserialization không an toàn

## 1. Bản chất

Serialization chuyển object/dữ liệu thành dạng lưu trữ hoặc truyền tải; deserialization dựng lại dữ liệu/object. Lỗ hổng xuất hiện khi ứng dụng **giải tuần tự hóa dữ liệu không tin cậy bằng cơ chế có thể tạo object, gọi hook hoặc kích hoạt hành vi ngoài việc khôi phục dữ liệu**.

Rủi ro không chỉ là "input có class name". Nó phụ thuộc vào:

- Thư viện và cấu hình deserializer.
- Type nào được phép khôi phục.
- Có constructor/magic method/callback chạy trong quá trình load không.
- Các class có sẵn trong classpath/runtime.
- Quyền của process và dữ liệu/công cụ mà gadget có thể chạm tới.

JSON thuần thường chỉ tạo kiểu dữ liệu cơ bản; nhưng JSON có type metadata, custom type resolver hoặc framework tự bind object vẫn có thể nguy hiểm.

## 2. Nhận diện dữ liệu serialized

### 2.1. Vị trí tìm

- Cookie/session/token không phải JWT chuẩn.
- Hidden form field.
- Tham số `data`, `state`, `object`, `view`, `return`.
- Body binary/base64.
- Message queue, cache, file import.
- API remoting/RPC.
- View state trong framework web.

### 2.2. Dấu hiệu theo hệ sinh thái

| Hệ | Dấu hiệu có thể gặp | Lưu ý |
|---|---|---|
| Python | Chuỗi pickle/base64, opcode pickle, `__reduce__` trong code | Không load dữ liệu để "kiểm tra" trên máy thật |
| PHP | Chuỗi dạng `O:...`, `a:...`, `s:...`, magic methods | Cần biết framework và class autoload |
| Java | Binary stream có header đặc trưng, Java serialization API, framework view state | Gadget phụ thuộc classpath |
| .NET | Formatter/type metadata, view state, `TypeNameHandling` | Cấu hình binder/formatter rất quan trọng |
| Node.js | Serialize format của package, `node-serialize`-style input, custom revive | JSON thường không tự tạo gadget; phụ thuộc thư viện |

Dấu hiệu trên chỉ giúp **định hướng**. Base64 không đồng nghĩa với serialized object, và chuỗi có vẻ giống format cũng có thể chỉ là token ngẫu nhiên.

### 2.3. Xác nhận bằng mã nguồn/cấu hình

Bằng chứng mạnh hơn là tìm:

- Hàm deserialize được gọi với dữ liệu từ request.
- Dữ liệu có integrity check trước khi load không.
- Có allowlist type/binder không.
- Class nào có hook chạy khi load/read/resolve.
- Có chữ ký/MAC nhưng verify sau deserialize không.

Nếu kiểm thử black-box trong lab, thay đổi một byte ở dữ liệu test và quan sát lỗi format; không gửi object độc hại.

## 3. Gadget và POP chain là gì?

Một **gadget** là đoạn code/class có sẵn trong ứng dụng hoặc dependency mà quá trình deserialization có thể kích hoạt trực tiếp hoặc gián tiếp. Một **chain** là chuỗi các gadget nối nhau để đạt hành vi như ghi file, gọi command, truy cập network hoặc thay đổi logic.

Điều kiện cần:

1. Có entry point deserialization không an toàn.
2. Có gadget tương thích phiên bản runtime/dependency.
3. Có đường từ input tới các field/callback của gadget.
4. Hành vi cuối có tác động trong quyền process.

Một chain từ internet thường không dùng được nếu phiên bản package khác, class không tồn tại, autoload khác hoặc mitigations đã bật.

**Không nên thử payload chain lên hệ thống không thuộc lab.** Với lab, nên dùng gadget giả do bạn tự viết để chứng minh hook được gọi, thay vì gadget thực thi lệnh.

## 4. Theo từng ngôn ngữ

### 4.1. Python

Nguy cơ chính thường liên quan `pickle` và các format tương thích:

```python
# Không an toàn nếu data có thể bị người khác kiểm soát
obj = pickle.loads(data)
```

Pickle không phải format dữ liệu trung lập: quá trình load có thể gọi callable và phục hồi object theo opcode. `pickle.loads` trên dữ liệu không tin cậy có thể dẫn tới code execution.

Cách kiểm chứng an toàn trong lab:

- Dùng một class giả có hook chỉ ghi marker vào file trong thư mục lab hoặc append vào list.
- Chạy trong process/container throwaway.
- So sánh với JSON chỉ khôi phục scalar/list/dict.

Không chạy pickle không tin cậy trên máy chính để xem nó có thực thi không.

Thay thế:

```python
import json

obj = json.loads(data)  # Chỉ dùng nếu schema dữ liệu phù hợp
if not isinstance(obj, dict):
    raise ValueError("Sai dữ liệu")
```

JSON vẫn cần schema validation, nhưng không tự gọi gadget Python.

### 4.2. PHP

Các magic method thường được xem xét gồm `__wakeup`, `__destruct`, `__unserialize`, `__toString`, `__call`... tùy luồng sử dụng.

Vấn đề thường là:

```php
$obj = unserialize($userControlledData);
```

Sau khi object được tạo, destructor hoặc method được gọi bởi code khác có thể tạo chain. Phân tích cần:

- Version PHP.
- Framework/autoload.
- Class thực tế tồn tại.
- Có `allowed_classes` hoặc cơ chế giới hạn không.
- Dữ liệu có signed/encrypted trước khi unserialize không.

Trong lab, dùng gadget chỉ ghi log marker; không dùng chain ghi file thực thi hoặc gọi lệnh.

### 4.3. Java

Java native deserialization có object graph và callback như `readObject`, `readResolve` tùy class. Rủi ro phụ thuộc classpath: các thư viện phổ biến có thể cung cấp gadget, nhưng không phải phiên bản nào cũng giống nhau.

Cách phòng thủ hiện đại:

- Không dùng native Java serialization cho dữ liệu không tin cậy.
- Dùng JSON/binary schema an toàn với kiểu dữ liệu rõ ràng.
- JEP 290 serialization filter/allowlist nếu bắt buộc tương thích.
- Giới hạn depth, references, array size, bytes.
- Giảm classpath và quyền process.

Không nên kết luận "có thư viện X nên có RCE" nếu chưa chứng minh entry point và chain tương thích.

### 4.4. .NET

Rủi ro thường liên quan formatter nguy hiểm hoặc type metadata tự động. Cấu hình như cho phép type tự do có thể làm dữ liệu JSON trở thành object graph có hành vi ngoài mong muốn.

Cách giảm rủi ro:

- Không dùng formatter nguy hiểm với input không tin cậy.
- Không bật tự động resolve type nếu không cần.
- Dùng binder/allowlist nghiêm ngặt.
- Validate schema và chữ ký trước khi xử lý.
- Cập nhật framework và giảm quyền ứng dụng.

### 4.5. Node.js

JavaScript JSON thông thường không có cơ chế native object serialization giống pickle/Java. Rủi ro thường đến từ:

- Package deserialize cụ thể.
- Custom reviver gọi function/constructor.
- Merge object không an toàn dẫn prototype pollution (lỗ hổng liên quan nhưng không đồng nhất với deserialization RCE).
- Framework RPC/remoting có type resolution.

Cần đọc đúng package/version và luồng gọi, không suy từ một chuỗi JSON có key đặc biệt thành code execution.

## 5. Quy trình kiểm chứng an toàn

1. Xác định endpoint nhận dữ liệu serialized.
2. Xác định format bằng code/config hoặc lỗi parse trong lab.
3. Kiểm tra integrity: có chữ ký/MAC, thứ tự verify và deserialize.
4. Xác định type được phép.
5. Tìm hook/gadget trong source/dependency.
6. Dùng gadget giả chỉ tạo marker vô hại.
7. Ghi lại điều kiện phiên bản và giới hạn khai thác.
8. Dừng trước mọi hành vi đọc dữ liệu thật, ghi file hệ thống hoặc chạy lệnh.

Một PoC tốt trong lab có thể chỉ chứng minh:

> Khi thay đổi trường type trong dữ liệu không có MAC, deserializer khởi tạo class test và gọi hook ghi `DESERIALIZATION_LAB_OK` vào log.

Điều đó chứng minh cơ chế mà không cần chạy lệnh hệ điều hành.

## 6. Phân biệt với các lỗ hổng hay nhầm

- **JWT yếu:** thường là vấn đề chữ ký/claim/session, không mặc nhiên là deserialization.
- **Prototype pollution:** thay đổi prototype/object properties, khác gadget chain nhưng có thể kết hợp.
- **Mass assignment:** bind dữ liệu vào field không được phép, không nhất thiết có code execution.
- **XXE:** parser XML xử lý entity, không phải object deserialization nói chung.
- **SSTI:** template render input, không phải dựng object serialized.

## 7. Khắc phục

### Nguyên tắc ưu tiên

1. Không deserialize dữ liệu không tin cậy bằng format có khả năng thực thi/tạo object tùy ý.
2. Dùng JSON/MessagePack/Protobuf theo schema, chỉ với kiểu dữ liệu cơ bản.
3. Nếu cần bảo toàn dữ liệu phía server, lưu server-side và chỉ gửi opaque ID.
4. Nếu bắt buộc gửi state cho client: authenticated encryption hoặc MAC đúng chuẩn, verify **trước** mọi parse nguy hiểm.
5. Allowlist type/binder/filter, giới hạn graph/depth/size.
6. Cập nhật dependency và loại bỏ gadget/format không cần thiết.
7. Chạy process với quyền tối thiểu, hạn chế filesystem/network.

### Ví dụ chuyển từ stateful object sang ID

Thay vì gửi toàn bộ object đã serialize trong cookie:

```text
cookie: session_id=<random opaque id>
```

Server giữ dữ liệu trong store. Client không thể sửa object graph vì không nhận được object graph.

### Lưu ý về mã hóa/chữ ký

- Base64 không phải bảo vệ.
- Chữ ký phải kiểm tra trước khi deserialize.
- MAC không thay thế việc bỏ format nguy hiểm nếu có lựa chọn an toàn hơn.
- Không tự thiết kế "mã hóa" hoặc ghép hash + dữ liệu theo cách riêng.

## 8. Bằng chứng và báo cáo

Báo cáo nên nêu:

- Điểm nhận dữ liệu và format.
- Thư viện/phiên bản/cấu hình.
- Dữ liệu có được xác thực trước khi load không.
- Hook/gadget được kích hoạt trong lab.
- Tác động tối thiểu đã chứng minh.
- Các phiên bản/điều kiện không kiểm chứng.
- Đề xuất thay format hoặc filter/binder cụ thể.

Tránh viết "RCE" nếu mới chỉ thấy lỗi parse hoặc khởi tạo object. Phải phân biệt khả năng tiềm ẩn với tác động đã chứng minh.

## 9. Checklist

- [ ] Xác định đúng format và thư viện.
- [ ] Kiểm tra thứ tự verify chữ ký và deserialize.
- [ ] Không load dữ liệu không tin cậy trên máy thật.
- [ ] Dùng gadget giả/marker trong lab throwaway.
- [ ] Không sao chép chain thực thi lệnh ra hệ thống ngoài phạm vi.
- [ ] Phân biệt lỗi parse, object injection và code execution.
- [ ] Sửa bằng format an toàn/ID server-side; filter chỉ là biện pháp bổ sung.
- [ ] Có giới hạn kích thước/depth và quyền process tối thiểu.
