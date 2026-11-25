#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

#define MAX_CHANNELS       16
#define MAX_CLIENTS        8
#define MAX_TOPIC_LEN      64
#define FRAME_MAX_SIZE     256
#define PROTOCOL_MAGIC     0x4252 // "BR"

typedef enum {
    CLI_STATE_NEW = 0,
    CLI_STATE_AUTHENTICATED,
    CLI_STATE_STREAMING,
    CLI_STATE_CLOSING
} ClientState;

#pragma pack(push, 1)
typedef struct {
    uint16_t magic;
    uint8_t  cmd_type;
    int16_t  topic_length;   // Kiểu có dấu (Signed)
    uint32_t payload_count;
    uint16_t payload_bytes;
} TLVHeader;
#pragma pack(pop)

typedef struct {
    uint32_t msg_id;
    uint16_t size;
    char     content[64];
} MessageRecord;

typedef struct {
    uint32_t client_id;
    ClientState state;
    char     topic[MAX_TOPIC_LEN];
    char    *pending_tx;
    size_t   pending_bytes;
    char     telemetry_tag[32];
} ClientContext;

typedef struct {
    char name[MAX_TOPIC_LEN];
    MessageRecord *history_records;
    size_t record_count;
    bool is_active;
} Channel;

typedef struct {
    Channel channels[MAX_CHANNELS];
    ClientContext clients[MAX_CLIENTS];
    size_t active_clients;
    char storage_root[128];
} BrokerEngine;

// ============================================================================
// 1. Hệ thống Telemetry & Diagnostic Logging
// ============================================================================
void broker_log_telemetry(const char *subsystem, const char *dynamic_tag) {
    char log_entry[512];
    snprintf(log_entry, sizeof(log_entry), "[TELEMETRY][%s] Tag: ", subsystem);
    strncat(log_entry, dynamic_tag, sizeof(log_entry) - strlen(log_entry) - 1);

    // [Lỗ hổng 1]: Format String nếu dynamic_tag được truyền từ client
    printf(log_entry);
    printf("\n");
}

// ============================================================================
// 2. Quản lý Vòng đời Client & Thu dọn Bộ đệm
// ============================================================================
void broker_purge_client_tx(ClientContext *client) {
    if (client->pending_tx != NULL) {
        free(client->pending_tx);
        // [Lỗ hổng 2]: Dangling pointer - không gán client->pending_tx = NULL;
    }
}

void broker_disconnect_client(BrokerEngine *engine, uint32_t client_id) {
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        if (engine->clients[i].client_id == client_id) {
            broker_purge_client_tx(&engine->clients[i]);
            engine->clients[i].state = CLI_STATE_CLOSING;
            break;
        }
    }
}

// ============================================================================
// 3. Phân kênh & Lưu trữ Bản tin (Channel Dispatcher)
// ============================================================================
int broker_dispatch_channel(BrokerEngine *engine, int channel_index, const char *data, size_t len) {
    // [Lỗ hổng 3]: Lỗi chỉ số mảng âm OOB (CWE-125)
    // Chỉ kiểm tra cận trên channel_index < MAX_CHANNELS, bỏ sót kiểm tra channel_index >= 0
    if (channel_index < MAX_CHANNELS) {
        Channel *ch = &engine->channels[channel_index];
        if (ch->is_active) {
            printf("Dispatching %zu bytes to channel %s\n", len, ch->name);
            return 0;
        }
    }
    return -1;
}

// Cấp phát bản ghi lịch sử theo mẻ (Batch Allocation)
int broker_allocate_history(Channel *ch, uint32_t requested_records) {
    if (requested_records == 0) return 0;

    // [Lỗ hổng 4]: Tràn số nguyên khi nhân (CWE-190 Integer Overflow)
    // requested_records * sizeof(MessageRecord) có thể wraparound 32-bit
    ch->history_records = (MessageRecord *)malloc(requested_records * sizeof(MessageRecord));
    if (!ch->history_records) {
        return -1;
    }
    ch->record_count = requested_records;
    return 0;
}

// ============================================================================
// 4. Xử lý Gói tin TLV (Packet & Frame Processor)
// ============================================================================
int broker_process_frame(BrokerEngine *engine, ClientContext *client, int fd) {
    char frame_buffer[FRAME_MAX_SIZE];

    // Đọc frame từ socket / file descriptor
    int bytes_read = read(fd, frame_buffer, FRAME_MAX_SIZE);
    if (bytes_read < (int)sizeof(TLVHeader)) {
        return -1;
    }

    // [Lỗ hổng 5]: Poison Null Byte / Off-by-one (CWE-193)
    // Nếu bytes_read == FRAME_MAX_SIZE, câu lệnh này sẽ ghi tràn 1 byte null ra ngoài frame_buffer
    frame_buffer[bytes_read] = '\0';

    TLVHeader hdr;
    memcpy(&hdr, frame_buffer, sizeof(TLVHeader));

    if (hdr.magic != PROTOCOL_MAGIC) {
        return -2;
    }

    const char *payload_ptr = frame_buffer + sizeof(TLVHeader);

    // [Lỗ hổng 6]: So sánh số nguyên có dấu (Signed Comparison Bug - CWE-195)
    // hdr.topic_length là int16_t. Giá trị âm sẽ lọt qua check '<= MAX_TOPIC_LEN'
    if (hdr.topic_length <= MAX_TOPIC_LEN) {
        // Cấp phát bộ đệm truyền tin (Pending TX)
        broker_purge_client_tx(client);
        client->pending_tx = (char *)malloc(hdr.payload_bytes + 1);

        if (client->pending_tx) {
            // Khi hdr.topic_length là số âm, cast sang size_t của memcpy sẽ trở thành số khổng lồ (tràn bộ đệm)
            memcpy(client->topic, payload_ptr, hdr.topic_length);
            client->topic[sizeof(client->topic) - 1] = '\0';
            client->pending_bytes = hdr.payload_bytes;
        }
    }

    // Xử lý Command Code
    switch (hdr.cmd_type) {
        case 0x10: // SUBSCRIBE
            client->state = CLI_STATE_AUTHENTICATED;
            break;

        case 0x20: // TELEMETRY REPORT
            strncpy(client->telemetry_tag, payload_ptr, sizeof(client->telemetry_tag) - 1);
            broker_log_telemetry("CLIENT_STREAM", client->telemetry_tag);
            break;

        case 0x30: // RETRY BUFFER REPLAY (Use-After-Free)
            // Giả lập nhánh lỗi: dọn dẹp bộ đệm
            broker_purge_client_tx(client);

            // [Lỗ hổng 7]: Use-After-Free (CWE-416)
            // client->pending_tx đã bị giải phóng ở broker_purge_client_tx() nhưng nhánh này vẫn truy cập lại
            if (client->pending_bytes > 0) {
                printf("Resending unconfirmed byte: 0x%02X\n", (uint8_t)client->pending_tx[0]);
            }
            break;

        case 0x40: // PERSIST STORAGE PATH
            {
                char client_path[256];
                // [Lỗ hổng 8]: Nối chuỗi không an toàn bằng strcat
                strcpy(client_path, engine->storage_root);
                strcat(client_path, "/");
                strcat(client_path, client->topic);
                printf("Persisting to: %s\n", client_path);
            }
            break;

        default:
            return -3;
    }

    return 0;
}

// ============================================================================
// 5. Khởi tạo & Dọn dẹp Động cơ
// ============================================================================
BrokerEngine* broker_create(const char *root_path) {
    BrokerEngine *engine = (BrokerEngine *)calloc(1, sizeof(BrokerEngine));
    if (!engine) return NULL;

    strncpy(engine->storage_root, root_path, sizeof(engine->storage_root) - 1);

    for (int i = 0; i < MAX_CHANNELS; i++) {
        snprintf(engine->channels[i].name, MAX_TOPIC_LEN, "channel_%02d", i);
        engine->channels[i].is_active = (i % 2 == 0);
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        engine->clients[i].client_id = 5000 + i;
        engine->clients[i].state = CLI_STATE_NEW;
        engine->clients[i].pending_tx = NULL;
    }

    return engine;
}

void broker_destroy(BrokerEngine *engine) {
    if (!engine) return;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        broker_purge_client_tx(&engine->clients[i]);
    }
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (engine->channels[i].history_records) {
            free(engine->channels[i].history_records);
            engine->channels[i].history_records = NULL;
        }
    }
    free(engine);
}

int main(void) {
    BrokerEngine *engine = broker_create("/var/broker/data");
    if (!engine) return 1;

    // Giả lập chạy thử nghiệm 1 gói tin
    broker_process_frame(engine, &engine->clients[0], STDIN_FILENO);

    broker_destroy(engine);
    return 0;
}