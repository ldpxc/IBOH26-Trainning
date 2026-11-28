<?php
// Sinh các flag dạng FILE (khác flag trong DB — xem seed.php) theo FLAG_SECRET
// hiện tại mỗi lần container khởi động, nên rotate flag chỉ cần đổi
// FLAG_SECRET trong .env rồi restart container, KHÔNG cần build lại image.
// Ngoại lệ: flag "recon" được build thẳng vào lịch sử git lúc build image
// (xem Dockerfile) nên KHÔNG rotate được theo cách này — cần build lại.
require '/var/www/html/public/inc/flag.php';

$targets = [
    '/tmp/flag_cmdi.txt'              => 'cmdi',
    '/var/www/html/flag_lfi.txt'      => 'lfi',
    '/var/www/html/flag_upload.txt'   => 'upload',
    '/etc/flag_xxe.txt'               => 'xxe',
    '/var/www/html/flag_deserialize.txt' => 'deserialize',
];

foreach ($targets as $path => $slug) {
    file_put_contents($path, flag($slug) . "\n");
    @chmod($path, 0644);
}

echo "Đã ghi " . count($targets) . " file flag.\n";
