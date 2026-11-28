<?php
// "Gadget" nội bộ app dùng cho tính năng share note (xuất note ra file tạm
// để gửi email). Lớp này tồn tại sẵn trong code — không phải thư viện ngoài —
// nhưng việc share.php unserialize() thẳng input người dùng mà không kiểm
// tra class nào được dựng chính là lỗ hổng (không phải lỗi của lớp này).
class NoteExporter {
    public $path = '/tmp/default_export.txt';
    public $content = '';

    public function __destruct() {
        @file_put_contents($this->path, $this->content);
    }
}
