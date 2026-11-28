# notevault — service luyện tập F-Hacker 2026 (CHỈ dùng nội bộ, nhiều lỗ hổng
# cố ý, xem README.md / plan ở services-practice/). Không deploy ra ngoài.
FROM php:7.4-apache

# php:7.4-apache dựa trên Debian bullseye đã EOL, repo gốc không còn gói —
# trỏ sang archive.debian.org (lưu vĩnh viễn các bản EOL).
RUN sed -i \
      -e 's|deb.debian.org/debian-security|archive.debian.org/debian-security|g' \
      -e 's|deb.debian.org|archive.debian.org|g' \
      -e '/bullseye-updates/d' \
      /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends git \
    && docker-php-ext-install mysqli pdo_mysql \
    && rm -rf /var/lib/apt/lists/*

# DocumentRoot -> public/ (code web nằm trong public/, script seed/flag nằm
# ngoài để KHÔNG bị Apache serve trực tiếp qua HTTP).
RUN sed -ri -e 's!/var/www/html!/var/www/html/public!g' /etc/apache2/sites-available/*.conf

COPY public/ /var/www/html/public/
COPY app/seed.php /var/www/html/seed.php
COPY app/write_file_flags.php /var/www/html/write_file_flags.php

# LỖ HỔNG: Recon/Source Leak — .git/ nằm NGAY TRONG webroot (lỗi deploy cố ý).
# Lịch sử git có 1 commit chứa config.php.bak lộ "mật khẩu cũ" (chính là
# flag), bị xoá ở commit sau nhưng vẫn còn nguyên trong `git log`/`git show`.
# Ghi chú: flag này được NƯỚNG VÀO BUILD (không rotate theo FLAG_SECRET lúc
# chạy như các flag khác) — đúng bản chất thật của 1 secret đã lỡ commit vào
# lịch sử, đổi env không xoá được nó khỏi git log. Muốn đổi phải build lại.
ARG FLAG_SECRET_BUILD=dev-secret-change-me
RUN cd /var/www/html/public && \
    git init -q && \
    git config user.email dev@notevault.local && git config user.name dev && \
    RECON_FLAG=$(FLAG_SECRET="$FLAG_SECRET_BUILD" php -r "require '/var/www/html/public/inc/flag.php'; echo flag('recon');") && \
    printf '<?php\n// cau hinh cu, da thay bang bien moi truong tu docker-compose\ndefine("DB_PASSWORD_OLD", "%s");\n' "$RECON_FLAG" > config.php.bak && \
    git add -A && git commit -q -m "initial commit" && \
    rm -f config.php.bak && \
    git add -A && git commit -q -m "chuyen sang doc password tu bien moi truong, xoa config cu"

RUN mkdir -p /var/www/html/public/uploads \
    && chown -R www-data:www-data /var/www/html/public/uploads

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["apache2-foreground"]
