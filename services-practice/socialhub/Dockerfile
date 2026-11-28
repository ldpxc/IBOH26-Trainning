# socialhub — service luyện tập F-Hacker 2026 (CHỈ dùng nội bộ, nhiều lỗ
# hổng cố ý, xem README.md / plan ở services-practice/). Không deploy ra ngoài.
FROM node:20-bookworm-slim

# Thư viện hệ thống Puppeteer/Chromium headless cần (admin bot thật).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates fonts-liberation libasound2 libatk-bridge2.0-0 libatk1.0-0 \
    libc6 libcairo2 libcups2 libdbus-1-3 libexpat1 libfontconfig1 libgbm1 \
    libglib2.0-0 libgtk-3-0 libnspr4 libnss3 libpango-1.0-0 libpangocairo-1.0-0 \
    libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 \
    libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxtst6 \
    wget xdg-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json .
RUN npm install

COPY app/ /app/app/

EXPOSE 80
CMD ["node", "app/server.js"]
