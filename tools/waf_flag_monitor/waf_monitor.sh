#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_FILE="$SCRIPT_DIR/app.py"
PID_FILE="$SCRIPT_DIR/.waf_monitor.pid"
LOG_FILE="$SCRIPT_DIR/.waf_monitor.log"

is_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid="$(cat "$PID_FILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

cleanup_stale_pid() {
    if [[ -f "$PID_FILE" ]] && ! is_running; then
        rm -f "$PID_FILE"
    fi
}

cmd_start() {
    cleanup_stale_pid
    if is_running; then
        echo "WAF Flag Monitor đang chạy sẵn (PID: $(cat "$PID_FILE"))."
        cmd_status
        return 0
    fi

    : > "$LOG_FILE"
    if command -v setsid >/dev/null 2>&1; then
        setsid python3 -u "$APP_FILE" "$@" </dev/null >> "$LOG_FILE" 2>&1 &
    else
        nohup python3 -u "$APP_FILE" "$@" </dev/null >> "$LOG_FILE" 2>&1 &
    fi
    local pid=$!
    echo "$pid" > "$PID_FILE"

    # Đợi tối đa 3 giây để server in thông tin khởi động
    local i=0
    while (( i < 30 )); do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "Khởi động thất bại. Xem log:"
            cat "$LOG_FILE"
            rm -f "$PID_FILE"
            return 1
        fi
        if grep -q "WebUI Password:" "$LOG_FILE" 2>/dev/null; then
            break
        fi
        sleep 0.1
        i=$((i + 1))
    done

    echo "Đã khởi động WAF Flag Monitor (PID: $pid)"
    grep -E "^\[\*\] (WAF Flag Monitor|WebUI Password|Target WAF)" "$LOG_FILE" || cat "$LOG_FILE"
}

cmd_stop() {
    cleanup_stale_pid
    if ! is_running; then
        echo "WAF Flag Monitor hiện không chạy."
        return 0
    fi

    local pid
    pid="$(cat "$PID_FILE")"
    kill "$pid" 2>/dev/null || true

    local i=0
    while kill -0 "$pid" 2>/dev/null && (( i < 30 )); do
        sleep 0.1
        i=$((i + 1))
    done

    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
    fi

    rm -f "$PID_FILE"
    echo "Đã dừng WAF Flag Monitor (PID: $pid)."
}

cmd_status() {
    cleanup_stale_pid
    if is_running; then
        local pid
        pid="$(cat "$PID_FILE")"
        echo "Trạng thái: ĐANG CHẠY (PID: $pid)"
        if [[ -f "$LOG_FILE" ]]; then
            grep -E "^\[\*\] (WAF Flag Monitor|WebUI Password|Target WAF)" "$LOG_FILE" || true
        fi
    else
        echo "Trạng thái: ĐÃ DỪNG"
    fi
}

cmd_logs() {
    if [[ ! -f "$LOG_FILE" ]]; then
        echo "Chưa có file log."
        return 0
    fi
    tail -n 50 "$@" "$LOG_FILE"
}

cmd_fg() {
    cleanup_stale_pid
    if is_running; then
        echo "WAF Flag Monitor đang chạy nền (PID: $(cat "$PID_FILE")). Hãy dừng trước khi chạy foreground."
        return 1
    fi
    exec python3 -u "$APP_FILE" "$@"
}

usage() {
    cat <<'EOF'
Cách dùng: ./waf_monitor.sh <lệnh> [tùy chọn]

Các lệnh:
  start [opts]    Chạy dịch vụ ở chế độ nền và in URL/Mật khẩu
  stop            Dừng dịch vụ đang chạy
  restart [opts]  Khởi động lại dịch vụ
  status          Kiểm tra trạng thái hiện tại
  logs [-f]       Xem log hoạt động (-f để theo dõi trực tiếp)
  fg [opts]       Chạy trực tiếp trên terminal hiện tại

Tùy chọn truyền thêm:
  --password <pw>       Mật khẩu truy cập WebUI (mặc định: tự sinh ngẫu nhiên)
  --port <port>         Cổng WebUI (mặc định: 9555)
  --host <ip>           Host bind WebUI (mặc định: 127.0.0.1, dùng 0.0.0.0 để mở LAN)
  --waf-url <url>       URL BunkerWeb UI (mặc định: http://localhost:9110)
  --waf-user <user>     Username BunkerWeb (mặc định: admin)
  --waf-pass <pw>       Password BunkerWeb (mặc định: ChangeMe_Bw_2026!)
  --mode <range|http|docker>  Nguồn đọc log (mặc định: range)
  --container <name>    Tên container Docker (khi dùng --mode docker)

Ví dụ:
  ./waf_monitor.sh start --password "123456"
  ./waf_monitor.sh start --host 0.0.0.0 --port 9555 --password "mysecret"
  ./waf_monitor.sh status
  ./waf_monitor.sh logs -f
  ./waf_monitor.sh stop
EOF
}

ACTION="${1:-help}"
if [[ $# -gt 0 ]]; then
    shift
fi

case "$ACTION" in
    start)   cmd_start "$@" ;;
    stop)    cmd_stop ;;
    restart) cmd_stop; cmd_start "$@" ;;
    status)  cmd_status ;;
    logs)    cmd_logs "$@" ;;
    fg)      cmd_fg "$@" ;;
    help|-h|--help) usage ;;
    *)
        echo "Lệnh không hợp lệ: $ACTION"
        usage
        exit 1
        ;;
esac
