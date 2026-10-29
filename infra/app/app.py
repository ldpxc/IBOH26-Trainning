"""App Flask dùng xuyên suốt HT1-HT6 (xem README mục 'Sổ tay lab HT1-HT7').

HT1 chỉ cần /health sống. /version cho HT3. /note/* để trống, nối Redis ở HT2.
"""
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

VERSION = os.environ.get("APP_VERSION", "v1")
FLAG_PATH = os.environ.get("FLAG_PATH", "/app/flag.txt")


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.get("/version")
def version():
    return VERSION


@app.get("/flag")
def flag():
    # Demo HT1: đọc 1 file flag giả để tập "app đọc file". Không phải endpoint thật của service AD.
    try:
        with open(FLAG_PATH) as f:
            return jsonify(flag=f.read().strip())
    except FileNotFoundError:
        return jsonify(error="flag not set"), 404


# ── HT2 sẽ thêm Redis + hai route dưới đây ──
@app.get("/note/<note_id>")
def get_note(note_id):
    return jsonify(error="not implemented until HT2"), 501


@app.post("/note")
def post_note():
    return jsonify(error="not implemented until HT2"), 501


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
