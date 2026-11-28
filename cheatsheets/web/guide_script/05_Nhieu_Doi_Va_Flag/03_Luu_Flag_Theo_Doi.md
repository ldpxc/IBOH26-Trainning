# Lưu flag theo đội

## Snippet copy-là-chạy

```python
from pathlib import Path

OUT = Path("results/flags.txt")
OWN_FLAGS = {"FHACKER2026{...}"}  # cờ đội nhà

def save_flags(team, flags):
    OUT.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    if OUT.exists():
        seen = {x.strip() for x in OUT.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()}
    with OUT.open("a", encoding="utf-8") as f:
        for flag in flags:
            if flag in OWN_FLAGS or flag in seen:
                continue
            f.write(flag + "\n")
            seen.add(flag)
            print(f"[+] {team} {flag}")

save_flags("http://10.0.2.1:8000", ["FHACKER2026{" + "a"*64 + "}"])
```

## Lưu ý nhanh
- Ghi nối (`append`) để không mất flag cũ; dedupe bằng `set`.
- Tách file kết quả ra `results/` và đừng commit cờ thật.
- Nếu cần trace đội nào, ghi thêm format `team,flag` hoặc log riêng.