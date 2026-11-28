// Sinh flag đúng khuôn FHACKER2026{64 hex} từ 1 slug cố định mỗi lỗ hổng.
// Rotate flag: đổi biến môi trường FLAG_SECRET rồi restart container.
const crypto = require("crypto");

function flag(slug) {
  const secret = process.env.FLAG_SECRET || "dev-secret-change-me";
  const digest = crypto.createHmac("sha256", secret).update(slug).digest("hex");
  return `FHACKER2026{${digest}}`;
}

module.exports = { flag };
