# pulseapi — service luyện tập F-Hacker 2026 (CHỈ dùng nội bộ, nhiều lỗ hổng
# cố ý, xem README.md / plan ở services-practice/). Không deploy ra ngoài.
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/

EXPOSE 80
CMD ["python", "app.py"]
