#!/usr/bin/env bash
# =============================================================================
# capture.sh — Bắt traffic tấn công trên VULNBOX, STREAM pcap VỀ laptop.
# tcpdump chạy ở vulnbox, pcap chảy qua SSH về laptop  =>  0 đĩa trên vulnbox
# (không làm đầy 256MB). SSH exec, KHÔNG phải tunneling -> hợp lệ IBOH 2026.
#
# Dùng:
#   ./capture.sh <user@vulnbox> <port_dịch_vụ> [--bin <remote_tcpdump>] [--open]
# Ví dụ:
#   ./capture.sh user@10.10.1.10 9001 --open        # bắt cổng 9001, Ctrl+C rồi tự mở Wireshark
#   ./capture.sh user@10.10.1.10 9001 --bin /tmp/tcpdump   # dùng static tcpdump đã nạp (mục 3.1)
# =============================================================================
set -euo pipefail

usage() { echo "Dùng: $0 <user@host> <port> [--bin <remote_tcpdump>] [--open]"; exit 1; }
[ $# -ge 2 ] || usage
TARGET="$1"; PORT="$2"; shift 2
BIN="tcpdump"; OPEN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="${2:?thiếu đường dẫn tcpdump}"; shift 2 ;;
    --open) OPEN=1; shift ;;
    *) usage ;;
  esac
done

# Kiểm tham số (chặn chèn lệnh)
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
  || { echo "[!] Port không hợp lệ (1–65535): $PORT"; exit 1; }
[[ "$TARGET" =~ ^[A-Za-z0-9._@-]+$ ]] \
  || { echo "[!] Target không hợp lệ (chỉ A-Z a-z 0-9 . _ @ -): $TARGET"; exit 1; }
[[ "$BIN" =~ ^[A-Za-z0-9._/-]+$ ]] \
  || { echo "[!] --bin không hợp lệ: $BIN"; exit 1; }

OUT="cap_${PORT}_$(date +%Y%m%d-%H%M%S).pcap"
echo "[*] Bắt 'tcp port $PORT' trên $TARGET  →  $OUT"
echo "[*] tcpdump chạy Ở vulnbox, pcap chảy VỀ laptop (0 đĩa vulnbox). Ctrl+C để dừng."
echo "[*] (sudo trên vulnbox có thể hỏi mật khẩu; tcpdump cần root.)"

# Ctrl+C chỉ dừng ssh/tcpdump, script vẫn chạy tiếp để in tóm tắt + mở Wireshark.
trap 'true' INT
ssh "$TARGET" "sudo $BIN -i any -U -s0 -w - 'tcp port $PORT'" > "$OUT" || true
trap - INT

if [ ! -s "$OUT" ]; then
  echo "[!] pcap rỗng. Kiểm: SSH vào được chưa? tcpdump có trên box chưa (nạp static: mục 3.1)? có root chưa?"
  echo "    Không bắt được L2 thì dùng strace/log tầng app (TOOLKIT.md mục 5.1b)."
  exit 1
fi

SZ=$(du -h "$OUT" 2>/dev/null | cut -f1)
echo "[+] Xong. pcap: $OUT ($SZ)"
echo "    Mẹo Wireshark: Follow → TCP Stream (đỏ = payload attacker gửi). Tìm flag: frame contains \"BOH26_\""
if [ "$OPEN" = 1 ] && command -v wireshark >/dev/null 2>&1; then
  echo "[*] Mở Wireshark (lọc sẵn tcp.port==$PORT)…"
  wireshark -r "$OUT" -Y "tcp.port==$PORT" >/dev/null 2>&1 &
else
  echo "    Phân tích:  wireshark -r \"$OUT\" -Y 'tcp.port==$PORT'"
  echo "                tshark   -r \"$OUT\" -Y 'tcp.port==$PORT' -T fields -e tcp.payload"
fi
