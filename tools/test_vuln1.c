#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_SESSIONS       4
#define MAX_PAYLOAD_SIZE   128
#define HEADER_MAGIC       0x504B // "PK"

typedef enum {
    STATE_INIT = 0,
    STATE_AUTHENTICATED,
    STATE_PROCESSING,
    STATE_TERMINATED
} SessionState;

#pragma pack(push, 1)
typedef struct {
    uint16_t magic;
    int16_t  length;       // Lưu ý: Kiểu có dấu (Signed)
    uint8_t  command_id;
} PacketHeader;
#pragma pack(pop)

typedef struct {
    uint32_t session_id;
    SessionState state;
    char *cached_response;
    size_t response_len;
} UserSession;

typedef struct {
    UserSession sessions[MAX_SESSIONS];
    size_t active_count;
} ServerContext;

// Hệ thống ghi log nội bộ (Helper)
void internal_logger(const char *module, const char *raw_message) {
    char log_buf[256];
    // Điểm đáng ngờ 1: Ghép chuỗi tạo log rồi truyền trực tiếp vào printf
    snprintf(log_buf, sizeof(log_buf), "[%s] ", module);
    strncat(log_buf, raw_message, sizeof(log_buf) - strlen(log_buf) - 1);
    
    // Lỗ hổng Format String tiềm tàng nếu raw_message chứa ký tự định dạng
    printf(log_buf);
    printf("\n");
}

// Khởi tạo ngữ cảnh hệ thống
ServerContext* init_server(void) {
    ServerContext *ctx = (ServerContext *)calloc(1, sizeof(ServerContext));
    if (!ctx) return NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        ctx->sessions[i].session_id = 1000 + i;
        ctx->sessions[i].state = STATE_INIT;
        ctx->sessions[i].cached_response = NULL;
    }
    return ctx;
}

// Xử lý dọn dẹp phiên
void cleanup_session_cache(UserSession *session) {
    if (session->cached_response != NULL) {
        free(session->cached_response);
        // Điểm đáng ngờ 2: Thiếu gán NULL sau khi giải phóng
    }
}

// Xử lý gói tin phức tạp với phân tích điều kiện lồng nhau
int process_packet(UserSession *session, const uint8_t *stream, size_t stream_len) {
    if (stream_len < sizeof(PacketHeader)) {
        return -1;
    }

    PacketHeader hdr;
    memcpy(&hdr, stream, sizeof(PacketHeader));

    if (hdr.magic != HEADER_MAGIC) {
        return -2;
    }

    const uint8_t *payload = stream + sizeof(PacketHeader);
    size_t available_bytes = stream_len - sizeof(PacketHeader);

    // Điểm đáng ngờ 3: Lỗi logic ép kiểu số nguyên có dấu (Signed Comparison)
    // hdr.length là int16_t. Nếu nhận giá trị âm, điều kiện kiểm tra bên dưới sẽ đúng.
    if (hdr.length <= MAX_PAYLOAD_SIZE) {
        if ((size_t)hdr.length <= available_bytes) {
            
            // Xử lý theo Command ID
            switch (hdr.command_id) {
                case 0x01: // Set cached response
                    cleanup_session_cache(session);
                    // Cấp phát theo kích thước nhận từ header
                    session->cached_response = (char *)malloc(hdr.length + 1);
                    if (session->cached_response) {
                        // Nếu hdr.length âm, khi cast sang size_t của memcpy sẽ trở thành số rất lớn
                        memcpy(session->cached_response, payload, hdr.length);
                        
                        // Điểm đáng ngờ 4: Off-by-one tiềm ẩn nếu hdr.length đạt ngưỡng tối đa
                        session->cached_response[hdr.length] = '\0';
                        session->response_len = hdr.length;
                        session->state = STATE_PROCESSING;
                    }
                    break;

                case 0x02: // Log message
                    if (session->state == STATE_PROCESSING) {
                        internal_logger("DISPATCHER", (const char *)payload);
                    }
                    break;

                case 0x03: // Reset cache nhưng tiếp tục dùng lại (Use-After-Free)
                    cleanup_session_cache(session);
                    // Lỗi: Logic rẽ nhánh có thể tái sử dụng con trỏ đã giải phóng nếu không kiểm tra cờ
                    if (session->response_len > 0) {
                        // Truy cập vào vùng nhớ đã bị giải phóng ở cleanup_session_cache()
                        printf("Last active cache tag: %c\n", session->cached_response[0]);
                    }
                    break;

                default:
                    return -3;
            }
        }
    }

    return 0;
}

int main(void) {
    ServerContext *ctx = init_server();
    if (!ctx) return 1;

    // Giả lập luồng dữ liệu gói tin đến từ bên ngoài
    uint8_t dummy_packet[] = {
        0x50, 0x4B,             // Magic: "PK"
        0x08, 0x00,             // Length: 8
        0x01,                   // Command: 0x01
        'T', 'E', 'S', 'T', '_', 'O', 'K', '\0'
    };

    process_packet(&ctx->sessions[0], dummy_packet, sizeof(dummy_packet));

    // Thu dọn tài nguyên
    for (int i = 0; i < MAX_SESSIONS; i++) {
        cleanup_session_cache(&ctx->sessions[i]);
    }
    free(ctx);

    return 0;
}