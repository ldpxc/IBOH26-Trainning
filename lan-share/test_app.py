#!/usr/bin/env python3
import io
import tempfile
import unittest
from pathlib import Path

from app import create_app


class LanShareTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.storage = Path(self.tmp_dir.name)
        (self.storage / "hello.txt").write_bytes(b"hello world\r\n")
        sub = self.storage / "docs"
        sub.mkdir()
        (sub / "báo cáo.txt").write_text("nội dung tiếng Việt", encoding="utf-8")

        self.app = create_app(self.storage, password="secret-lan-password", secret_key="test-key")
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def login(self, password: str = "secret-lan-password"):
        return self.client.post("/login", data={"password": password}, follow_redirects=False)

    def test_requires_authentication(self) -> None:
        for method, url in [("get", "/"), ("get", "/download?path=hello.txt"), ("post", "/upload")]:
            resp = getattr(self.client, method)(url)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.headers["Location"])

    def test_login_flow(self) -> None:
        bad = self.login("wrong")
        self.assertEqual(bad.status_code, 200)
        self.assertIn("Mật khẩu không đúng", bad.get_data(as_text=True))

        ok = self.login("secret-lan-password")
        self.assertEqual(ok.status_code, 302)

        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn("hello.txt", html)
        self.assertIn("docs", html)

    def test_windows_upload_and_download(self) -> None:
        self.login()
        payload = b"\x00\x01\x02windows binary\r\n"
        resp = self.client.post(
            "/upload",
            data={
                "dir": "docs",
                "files": (io.BytesIO(payload), r"C:\Users\Alice\Desktop\tài liệu.bin"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        saved = self.storage / "docs" / "tài liệu.bin"
        self.assertTrue(saved.exists())
        self.assertEqual(saved.read_bytes(), payload)

        dl = self.client.get("/download?path=docs/tài liệu.bin")
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.data, payload)
        self.assertIn("attachment", dl.headers["Content-Disposition"])

    def test_path_traversal_blocked(self) -> None:
        self.login()
        self.assertEqual(self.client.get("/?path=../../etc").status_code, 403)
        self.assertEqual(self.client.get("/download?path=../../etc/passwd").status_code, 403)

    def test_mkdir_and_collision_rename(self) -> None:
        self.login()
        resp = self.client.post("/mkdir", data={"dir": "", "folder_name": "new_folder"}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue((self.storage / "new_folder").is_dir())

        self.client.post(
            "/upload",
            data={"dir": "", "files": (io.BytesIO(b"second"), "hello.txt")},
            content_type="multipart/form-data",
        )
        self.assertTrue((self.storage / "hello (1).txt").exists())

    def test_view_text_html_and_reject_binary(self) -> None:
        (self.storage / "page.html").write_text("<h1>Xin chào</h1>", encoding="utf-8")
        (self.storage / "prog_elf").write_bytes(b"\x7fELF\x02\x01\x01\x00binary")
        (self.storage / "setup.exe").write_bytes(b"MZ\x90\x00binary")

        # Unauthenticated /view redirects to login
        unauth = self.client.get("/view?path=hello.txt")
        self.assertEqual(unauth.status_code, 302)
        self.assertIn("/login", unauth.headers["Location"])

        self.login()
        index_html = self.client.get("/").get_data(as_text=True)
        self.assertIn("/view?path=hello.txt", index_html)
        self.assertIn("/view?path=page.html", index_html)
        self.assertNotIn("/view?path=prog_elf", index_html)
        self.assertNotIn("/view?path=setup.exe", index_html)

        txt_view = self.client.get("/view?path=hello.txt")
        self.assertEqual(txt_view.status_code, 200)
        self.assertIn("hello world", txt_view.get_data(as_text=True))

        html_view = self.client.get("/view?path=page.html")
        self.assertEqual(html_view.status_code, 200)
        html_body = html_view.get_data(as_text=True)
        self.assertIn('sandbox=""', html_body)
        self.assertIn("Xin chào", html_body)

        self.assertEqual(self.client.get("/view?path=prog_elf").status_code, 415)
        self.assertEqual(self.client.get("/view?path=setup.exe").status_code, 415)

    def test_delete_moves_to_hidden_trash(self) -> None:
        unauth = self.client.post("/delete", data={"path": "hello.txt"})
        self.assertEqual(unauth.status_code, 302)
        self.assertIn("/login", unauth.headers["Location"])

        self.login()
        resp = self.client.post("/delete", data={"path": "hello.txt"}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Đã chuyển &#39;hello.txt&#39; vào thư mục trash.", html)

        self.assertFalse((self.storage / "hello.txt").exists())
        self.assertTrue((self.storage / "trash" / "hello.txt").exists())

        # Trash folder must not appear in listing or be accessible via web
        self.assertNotIn(">trash<", html)
        self.assertEqual(self.client.get("/?path=trash").status_code, 403)
        self.assertEqual(self.client.get("/download?path=trash/hello.txt").status_code, 403)
        self.assertEqual(self.client.get("/view?path=trash/hello.txt").status_code, 403)


if __name__ == "__main__":
    unittest.main()
