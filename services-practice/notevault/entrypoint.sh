#!/bin/sh
set -e

echo "Chờ MySQL sẵn sàng..."
until php -r "new PDO('mysql:host='.getenv('DB_HOST').';dbname='.getenv('DB_NAME'), getenv('DB_USER'), getenv('DB_PASS'));" >/dev/null 2>&1; do
  sleep 2
done

php /var/www/html/seed.php
php /var/www/html/write_file_flags.php

exec "$@"
