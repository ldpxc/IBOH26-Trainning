#!/usr/bin/env bash
# spin.sh -- dựng/huỷ/xoay flag cho 1 (team, service) hoặc tất cả, phục vụ
# luyện A/D 2 team. Xem ROUND_GUIDE.md để biết cách dùng trong 1 buổi tập.
#
# Dùng:
#   ./spin.sh up    <team> <service>    Dựng 1 bản (app+WAF riêng) cho team đó
#   ./spin.sh down  <team> <service>    Dừng + xoá (giữ ảnh Docker để up lại nhanh)
#   ./spin.sh rotate <team> <service>   Sinh flag mới + restart app (mô phỏng đầu round)
#   ./spin.sh ps                        Liệt kê mọi stack đang chạy + cổng
#   ./spin.sh logs <team> <service>     Xem log traffic WAF realtime
#   ./spin.sh up-all / down-all         Dựng/huỷ TẤT CẢ (2 team x 3 service = 6 bộ, nặng máy)
#
# team:    a | b           (hoặc tên khác, chỉ cần nhất quán)
# service: notevault | pulseapi | socialhub

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

SERVICES=(notevault pulseapi socialhub)
# Cổng app/UI WAF tính theo (team, service) để không đụng nhau khi chạy song
# song -- xem bảng đầy đủ bằng `./spin.sh ps` hoặc `./spin.sh ports`.
declare -A SVC_INDEX=([notevault]=0 [pulseapi]=1 [socialhub]=2)

team_offset() {
  # team "a" -> 0, "b" -> 1, "c" -> 2... (ký tự đầu - 'a'); tên khác -> hash gọn
  local t="$1"
  case "$t" in
    [a-z]) printf '%d' "$(( $(printf '%d' "'${t}") - $(printf '%d' "'a") ))" ;;
    *) printf '%d' "$(( $(cksum <<<"$t" | cut -d' ' -f1) % 20 ))" ;;
  esac
}

ports_for() {
  local team="$1" svc="$2"
  local toff svoff
  toff=$(team_offset "$team")
  svoff=${SVC_INDEX[$svc]}
  BW_PORT=$(( 9000 + toff * 10 + svoff ))
  BW_UI_PORT=$(( 9100 + toff * 10 + svoff ))
}

check_args_team_svc() {
  local team="$1" svc="$2"
  if [[ ! " ${SERVICES[*]} " =~ " ${svc} " ]]; then
    echo "Service không hợp lệ: $svc (phải là: ${SERVICES[*]})" >&2
    exit 1
  fi
  if [[ -z "$team" ]]; then
    echo "Thiếu tên team" >&2
    exit 1
  fi
}

env_dir_for() {
  local team="$1" svc="$2"
  echo ".runtime/${team}_${svc}"
}

write_env() {
  local team="$1" svc="$2" dir
  dir=$(env_dir_for "$team" "$svc")
  mkdir -p "$dir"
  ports_for "$team" "$svc"
  local flag_secret
  if [[ -f "$dir/.env" ]] && grep -q '^FLAG_SECRET=' "$dir/.env"; then
    flag_secret=$(grep '^FLAG_SECRET=' "$dir/.env" | cut -d= -f2-)
  else
    flag_secret="${team}-${svc}-$(date +%s)-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
  # SEED_PASSWORD_SECRET: khác FLAG_SECRET ở chỗ KHÔNG đổi theo `rotate` --
  # dùng để sinh mật khẩu admin/alice riêng theo từng team (notevault), để
  # 1 team không biết trước mật khẩu app của team kia (chỉ dùng chung
  # ADMIN_PASSWORD của UI WAF, không liên quan tài khoản trong app). Sinh 1
  # lần lúc `up` đầu tiên, giữ nguyên mọi lần `up`/`rotate` sau để không làm
  # mất đăng nhập giữa round.
  local seed_pw_secret
  if [[ -f "$dir/.env" ]] && grep -q '^SEED_PASSWORD_SECRET=' "$dir/.env"; then
    seed_pw_secret=$(grep '^SEED_PASSWORD_SECRET=' "$dir/.env" | cut -d= -f2-)
  else
    seed_pw_secret="seed-${team}-${svc}-$(head -c12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
  cat > "$dir/.env" <<EOF
PROJECT_NAME=${team}_${svc}
BW_PORT=${BW_PORT}
BW_UI_PORT=${BW_UI_PORT}
WAF_DB_PASSWORD=waf_db_${team}_${svc}
ADMIN_USERNAME=admin
ADMIN_PASSWORD=ChangeMe_Bw_2026!
FLAG_SECRET=${flag_secret}
SEED_PASSWORD_SECRET=${seed_pw_secret}
EOF
  echo "$dir/.env"
}

# Tính đúng công thức seed.php dùng để sinh mật khẩu admin/alice từ
# SEED_PASSWORD_SECRET -- dùng để in ra cho người dùng xem (không phải để
# healthcheck gọi, Python tự tính lại bằng hmac).
seed_password() {
  local secret="$1" role="$2"
  printf '%s' "seed:${role}" | openssl dgst -sha256 -hmac "$secret" -r | awk '{print substr($1,1,16)}'
}

seed_detection_only() {
  # BunkerWeb mặc định gốc MODSECURITY_SEC_RULE_ENGINE=On (CHẶN NGAY) nếu
  # không có dòng nào trong bw_global_values -- khác hẳn DetectionOnly mà
  # 2026-waf-practice/BTC seed sẵn qua UI lúc thi thật. Tự chèn đúng dòng này
  # (method='ui', KHÔNG phải 'scheduler' nên UI vẫn đổi được bình thường sau
  # đó) rồi recreate fuap_bunkerweb để áp dụng -- mô phỏng đúng bước seed của
  # BTC mà không cần file seed độc quyền của họ.
  local svc="$1" envfile="$2"
  echo "    Chờ BunkerWeb scheduler đăng ký xong setting (cần cho khoá ngoại)..."
  # Chờ ĐÚNG tín hiệu: bw_settings có dòng MODSECURITY_SEC_RULE_ENGINE --
  # không phải chỉ "postgres chạy" (select 1 thành công rất sớm, trước khi
  # scheduler kịp nạp bảng bw_settings, khiến INSERT sau đó vi phạm khoá
  # ngoại và lỗi bị nuốt nếu không kiểm tra kỹ).
  local ok=
  for i in $(seq 1 90); do
    if (cd "$svc" && docker compose --env-file "../$envfile" -f compose.arena.yml exec -T postgres \
        psql -U bunkerweb -d bunkerweb -Atc \
        "select 1 from bw_settings where id='MODSECURITY_SEC_RULE_ENGINE'" 2>/dev/null | grep -q 1); then
      ok=1; break
    fi
    sleep 2
  done
  [[ -n "$ok" ]] || { echo "    Scheduler chưa sẵn sàng sau 180s, bỏ qua bước seed (tự vào UI đổi DetectionOnly thủ công)."; return 0; }

  local out
  out=$(cd "$svc" && docker compose --env-file "../$envfile" -f compose.arena.yml exec -T postgres \
    psql -U bunkerweb -d bunkerweb -v ON_ERROR_STOP=1 -c \
    "INSERT INTO bw_global_values (setting_id, value, suffix, method, is_draft)
     VALUES ('MODSECURITY_SEC_RULE_ENGINE', 'DetectionOnly', 0, 'ui', false)
     ON CONFLICT (setting_id, suffix) DO UPDATE SET value = 'DetectionOnly', method = 'ui';" 2>&1)
  if [[ $? -ne 0 ]]; then
    echo "    Seed DetectionOnly LỖI, cần tự vào UI đổi thủ công:"
    echo "$out" | sed 's/^/    /'
    return 0
  fi
  (cd "$svc" && docker compose --env-file "../$envfile" -f compose.arena.yml up -d --no-deps --force-recreate fuap_bunkerweb)
  echo "    Đã seed DetectionOnly (chỉ ghi log, chưa chặn) -- đúng mặc định lúc thi."
}

cmd_up() {
  local team="$1" svc="$2"
  check_args_team_svc "$team" "$svc"
  local envfile; envfile=$(write_env "$team" "$svc")
  echo "==> Dựng ${team}/${svc} (project ${team}_${svc})..."
  (cd "$svc" && docker compose --env-file "../$envfile" -f compose.arena.yml up -d --build)
  seed_detection_only "$svc" "$envfile"
  ports_for "$team" "$svc"
  echo "✅ ${team}/${svc}: app qua WAF http://127.0.0.1:${BW_PORT}/  |  WAF UI http://127.0.0.1:${BW_UI_PORT}/"
  echo "   Đăng nhập UI WAF: admin / ChangeMe_Bw_2026! (đổi trong .runtime/${team}_${svc}/.env nếu muốn)"
  if [[ "$svc" == "notevault" ]]; then
    local seed_secret; seed_secret=$(grep '^SEED_PASSWORD_SECRET=' "$envfile" | cut -d= -f2-)
    echo "   Tài khoản app (CHỈ team ${team} biết -- không chia sẻ cho team kia):"
    echo "     admin / $(seed_password "$seed_secret" admin)"
    echo "     alice / $(seed_password "$seed_secret" alice)"
  fi
  mark_round_event "$team" "$svc" "up"
}

cmd_down() {
  local team="$1" svc="$2"
  check_args_team_svc "$team" "$svc"
  local dir; dir=$(env_dir_for "$team" "$svc")
  if [[ ! -f "$dir/.env" ]]; then
    echo "Không thấy $dir/.env -- có vẻ chưa từng 'up' cặp (${team}, ${svc})"
    return 0
  fi
  (cd "$svc" && docker compose --env-file "../$dir/.env" -f compose.arena.yml down)
}

cmd_rotate() {
  local team="$1" svc="$2"
  check_args_team_svc "$team" "$svc"
  local dir; dir=$(env_dir_for "$team" "$svc")
  if [[ ! -f "$dir/.env" ]]; then
    echo "Chưa 'up' (${team}, ${svc}), không có gì để rotate" >&2
    exit 1
  fi
  local new_secret
  new_secret="${team}-${svc}-$(date +%s)-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  sed -i.bak "s/^FLAG_SECRET=.*/FLAG_SECRET=${new_secret}/" "$dir/.env"
  rm -f "$dir/.env.bak"
  echo "==> Rotate flag ${team}/${svc}, restart app..."
  (cd "$svc" && docker compose --env-file "../$dir/.env" -f compose.arena.yml up -d --force-recreate --no-deps app)
  echo "✅ Flag mới đã áp dụng (restart app xong)."
  mark_round_event "$team" "$svc" "rotate"
}

# Ghi 1 dòng JSON đánh dấu sự kiện (rotate = round mới, up = bắt đầu phiên)
# vào cùng file healthcheck_notevault.py --json-log mặc định dùng -- để
# dashboard.py vẽ được đường phân round trên biểu đồ. Không lỗi nếu thư mục
# chưa có (vd chưa từng chạy healthcheck) -- chỉ là bỏ qua, không bắt buộc.
mark_round_event() {
  local team="$1" svc="$2" event="$3" dir
  dir=$(env_dir_for "$team" "$svc")
  local ts; ts=$(date +%s.%N)
  local time_str; time_str=$(date '+%Y-%m-%d %H:%M:%S')
  printf '{"event":"%s","ts":%s,"time":"%s","team":"%s"}\n' "$event" "$ts" "$time_str" "$team" >> "$dir/healthcheck.jsonl"
}

cmd_ps() {
  echo "Team   Service      BW_PORT  BW_UI_PORT  Trạng thái"
  for team in a b; do
    for svc in "${SERVICES[@]}"; do
      local dir; dir=$(env_dir_for "$team" "$svc")
      ports_for "$team" "$svc"
      local status="chưa dựng"
      if [[ -f "$dir/.env" ]]; then
        running=$(cd "$svc" && docker compose --env-file "../$dir/.env" -f compose.arena.yml ps --status running -q 2>/dev/null | wc -l)
        [[ "$running" -gt 0 ]] && status="đang chạy ($running container)" || status="đã dựng nhưng dừng"
      fi
      printf "%-6s %-12s %-8s %-11s %s\n" "$team" "$svc" "$BW_PORT" "$BW_UI_PORT" "$status"
    done
  done
}

cmd_logs() {
  local team="$1" svc="$2"
  check_args_team_svc "$team" "$svc"
  local dir; dir=$(env_dir_for "$team" "$svc")
  (cd "$svc" && docker compose --env-file "../$dir/.env" -f compose.arena.yml logs -f fuap_bunkerweb)
}

cmd_up_all() {
  for team in a b; do
    for svc in "${SERVICES[@]}"; do
      cmd_up "$team" "$svc"
    done
  done
}

cmd_down_all() {
  for team in a b; do
    for svc in "${SERVICES[@]}"; do
      cmd_down "$team" "$svc" || true
    done
  done
}

case "${1:-}" in
  up)       cmd_up "${2:-}" "${3:-}" ;;
  down)     cmd_down "${2:-}" "${3:-}" ;;
  rotate)   cmd_rotate "${2:-}" "${3:-}" ;;
  ps)       cmd_ps ;;
  logs)     cmd_logs "${2:-}" "${3:-}" ;;
  up-all)   cmd_up_all ;;
  down-all) cmd_down_all ;;
  *)
    sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
