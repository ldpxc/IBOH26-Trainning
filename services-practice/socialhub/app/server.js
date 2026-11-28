/*
 * socialhub -- service luyện tập F-Hacker 2026 (CHỈ dùng nội bộ, nhiều lỗ
 * hổng cố ý). Xem services-practice/README.md / plan để biết danh sách đầy
 * đủ. State lưu trong RAM cho gọn -- KHÔNG dùng pattern này cho app thật.
 */
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { graphql, buildSchema } = require("graphql");

const { flag } = require("./flagutil");
const { startBot, queueReport } = require("./bot");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PORT = 80;
const BASE_URL = process.env.BASE_URL || "http://127.0.0.1:80";

// LỖ HỔNG: JWT_SECRET yếu, đoán được/crack được bằng wordlist (jwt_tool -C
// hoặc hashcat -m 16500).
const JWT_SECRET = process.env.JWT_SECRET || "socialhub123";

// ============================================================
// "DATABASE" trong RAM
// ============================================================
const USERS = {
  alice: { password: "alice_demo_pw_2026", role: "user", email: "alice@socialhub.local", bio: "Xin chào, mình là Alice!" },
  admin: { password: "admin_super_secret_2026", role: "admin", email: "admin@socialhub.local", bio: "Quản trị viên SocialHub." },
};

const STOLEN_COOKIES = [];

// ============================================================
// Helper: query kiểu MongoDB trên object JS thuần (không cần MongoDB thật)
// -- mô phỏng ĐÚNG hành vi toán tử ($ne, $gt, $regex) để tái hiện NoSQLi.
// ============================================================
function matchesCond(value, cond) {
  if (cond !== null && typeof cond === "object" && !Array.isArray(cond)) {
    for (const [op, opVal] of Object.entries(cond)) {
      if (op === "$ne" && !(value !== opVal)) return false;
      else if (op === "$eq" && !(value === opVal)) return false;
      else if (op === "$gt" && !(value > opVal)) return false;
      else if (op === "$regex") {
        try { if (!new RegExp(opVal).test(value)) return false; } catch { return false; }
      } else if (!["$ne", "$eq", "$gt", "$regex"].includes(op)) return false;
    }
    return true;
  }
  return value === cond;
}

function findUser(filter) {
  for (const [username, u] of Object.entries(USERS)) {
    const full = { username, ...u };
    if (Object.entries(filter).every(([k, v]) => matchesCond(full[k], v))) {
      return { username, ...u };
    }
  }
  return null;
}

// ============================================================
// Auth: JWT -- LỖ HỔNG cho phép alg "none" (dev tự thêm vào allowlist
// algorithms vì nghĩ "cho chắc", quên mất đây chính là lỗ hổng kinh điển).
// ============================================================
function issueToken(username, role) {
  return jwt.sign({ username, role }, JWT_SECRET, { algorithm: "HS256" });
}

// Verify "tự chế" -- KHÔNG dùng jwt.verify() của thư viện (bản hiện đại tự
// chặn cứng alg:none dù app allowlist, không tái hiện được lỗ hổng kinh điển
// cho mục đích luyện tập). Đây là cách nhiều app THẬT viết tay vì cần custom
// logic rồi vô tình bỏ sót đúng bước kiểm tra này -- CỐ Ý.
function unsafeVerify(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("token sai định dạng");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());

  if (header.alg === "none") {
    // LỖ HỔNG: chấp nhận luôn, không bắt buộc signature phải rỗng/hợp lệ.
    return payload;
  }

  const data = parts[0] + "." + parts[1];
  const expectedSig = crypto.createHmac("sha256", JWT_SECRET).update(data).digest("base64url");
  if (expectedSig !== parts[2]) throw new Error("signature không khớp");
  return payload;
}

function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "chưa đăng nhập" });
  try {
    req.user = unsafeVerify(token);
    next();
  } catch (e) {
    res.status(401).json({ error: "token không hợp lệ: " + e.message });
  }
}

// ============================================================
// 1) LỖ HỔNG: NoSQL Injection -- password nhận object chứa toán tử Mongo
// thay vì chuỗi, bypass check mật khẩu hoàn toàn.
// ============================================================
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || password === undefined) {
    return res.status(400).json({ error: "thiếu username/password" });
  }
  const user = findUser({ username, password }); // password có thể là {"$ne": ""}
  if (!user) return res.status(401).json({ error: "sai username hoặc password" });

  const token = issueToken(user.username, user.role);
  res.cookie("token", token, { httpOnly: true, sameSite: "lax" });
  res.json({ status: "logged in", username: user.username, role: user.role });
});

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "thiếu username/password" });
  if (USERS[username]) return res.status(400).json({ error: "username đã tồn tại" });
  USERS[username] = { password, role: "user", email: `${username}@socialhub.local`, bio: "Chưa có giới thiệu." };
  res.json({ status: "registered" });
});

app.get("/api/me", authMiddleware, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

// ============================================================
// 2) LỖ HỔNG: XSS lưu trữ -- bio render thẳng ra HTML không escape.
// Dùng chung với admin bot (/report) để chiếm được cookie admin thật.
// ============================================================
app.post("/profile/bio", authMiddleware, (req, res) => {
  USERS[req.user.username].bio = req.body.bio || "";
  res.json({ status: "bio updated" });
});

app.get("/profile/:username", (req, res) => {
  const user = USERS[req.params.username];
  if (!user) return res.status(404).send("Not found");
  res.send(`<!doctype html><html><body>
    <h1>Hồ sơ của ${req.params.username}</h1>
    <div class="bio">${user.bio}</div>
  </body></html>`);
});

app.get("/api/profile/:username", (req, res) => {
  const user = USERS[req.params.username];
  if (!user) return res.status(404).json({ error: "not found" });
  res.json({ username: req.params.username, bio: user.bio });
});

// Nạn nhân (attacker) "báo cáo" 1 trang cho admin xem -- admin bot (cookie
// admin thật) sẽ mở link này bằng trình duyệt headless thật.
app.post("/report", authMiddleware, (req, res) => {
  const path = req.body.path || "";
  if (!path.startsWith("/")) return res.status(400).json({ error: "chỉ chấp nhận path cùng origin" });
  queueReport(BASE_URL + path);
  res.json({ status: "đã gửi report, admin sẽ xem sớm" });
});

// "Listener" nhận cookie bị đánh cắp -- trong thi thật đây là server RIÊNG
// của attacker (vd python -m http.server), ở đây gộp vào cùng app cho gọn
// khi tự kiểm vì bot chạy trong cùng container, không cần cấu hình mạng
// thêm. Dùng domain/IP ngoài thật khi thi đấu thật.
app.get("/exfil", (req, res) => {
  STOLEN_COOKIES.push({ cookie: req.query.c || "", at: Date.now() });
  res.status(204).end();
});

app.get("/admin/stolen", (req, res) => {
  const results = STOLEN_COOKIES.map((entry) => {
    let decoded = null;
    try {
      const m = entry.cookie.match(/token=([^;]+)/);
      if (m) decoded = unsafeVerify(m[1]);
    } catch { /* ignore */ }
    return { ...entry, decoded };
  });
  const gotAdmin = results.some((r) => r.decoded && r.decoded.role === "admin");
  res.json({ stolen: results, flag: gotAdmin ? flag("xss_adminbot") : undefined });
});

// ============================================================
// 3) LỖ HỔNG: Prototype Pollution -- merge đệ quy không lọc __proto__.
// ============================================================
function merge(target, source) {
  for (const key of Object.keys(source)) {
    const val = source[key];
    if (val !== null && typeof val === "object" && !Array.isArray(val)) {
      if (typeof target[key] !== "object" || target[key] === null) target[key] = {};
      merge(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}

app.post("/settings/update", authMiddleware, (req, res) => {
  const settings = {};
  merge(settings, req.body); // <-- không lọc "__proto__"
  res.json({ status: "settings updated", settings });
});

app.get("/admin/check", (req, res) => {
  const probe = {};
  if (probe.isAdmin === true) {
    return res.json({ polluted: true, flag: flag("prototype_pollution") });
  }
  res.json({ polluted: false });
});

// ============================================================
// 4) LỖ HỔNG: GraphQL -- introspection bật mặc định, field adminPanel
// không kiểm tra quyền.
// ============================================================
const schema = buildSchema(`
  type User { username: String, email: String, role: String }
  type Query {
    user(username: String!): User
    adminPanel: String
  }
`);

const root = {
  user: ({ username }) => {
    const u = USERS[username];
    if (!u) return null;
    return { username, email: u.email, role: u.role };
  },
  adminPanel: () => flag("graphql"), // <-- KHÔNG check quyền gì cả
};

app.post("/graphql", async (req, res) => {
  const { query, variables } = req.body || {};
  if (!query) return res.status(400).json({ error: "thiếu field 'query'" });
  const result = await graphql({ schema, source: query, rootValue: root, variableValues: variables });
  res.json(result);
});
app.get("/graphql", (req, res) => {
  res.send("<h1>GraphQL endpoint</h1><p>POST JSON {\"query\": \"...\"} tới đây.</p>");
});

// ============================================================
// 5) LỖ HỔNG: CORS Misconfiguration -- reflect Origin bất kỳ +
// Allow-Credentials true -> trang độc trên domain khác đọc được response có
// cookie của nạn nhân.
// ============================================================
app.use("/api", (req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin); // <-- reflect bất kỳ Origin nào
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

app.get("/api/secret-profile", authMiddleware, (req, res) => {
  res.json({
    username: req.user.username,
    role: req.user.role,
    note: "dữ liệu nhạy cảm -- lộ được qua CORS nếu Origin bị reflect",
    flag: flag("cors"),
  });
});

// ============================================================
// 6) LỖ HỔNG: CSRF -- đổi email chỉ dựa cookie session, không CSRF token,
// không kiểm tra Origin/Referer.
// ============================================================
app.post("/profile/email", authMiddleware, (req, res) => {
  const email = req.body.email || "";
  USERS[req.user.username].email = email;
  const resp = { status: "email updated", email };
  if (email.endsWith("@attacker.evil")) {
    resp.flag = flag("csrf"); // xác nhận đổi email thành công mà không cần token
  }
  res.json(resp);
});

// ============================================================
// 7) LỖ HỔNG: Session/Cookie Forging -- cookie "prefs" phụ, chỉ
// base64(JSON), KHÔNG có chữ ký/toàn vẹn gì -- sửa thẳng là xong.
// ============================================================
app.get("/prefs", (req, res) => {
  const raw = req.cookies.prefs;
  let prefs = { theme: "light", isStaff: false };
  if (raw) {
    try { prefs = JSON.parse(Buffer.from(raw, "base64").toString()); } catch { /* ignore */ }
  }
  res.json({ prefs });
});

app.post("/prefs/theme", (req, res) => {
  const prefs = { theme: req.body.theme || "light", isStaff: false };
  const cookie = Buffer.from(JSON.stringify(prefs)).toString("base64");
  res.cookie("prefs", cookie);
  res.json({ status: "saved" });
});

app.get("/staff/flag", (req, res) => {
  const raw = req.cookies.prefs;
  if (!raw) return res.status(401).json({ error: "chưa có cookie prefs, gọi /prefs/theme trước" });
  let prefs;
  try { prefs = JSON.parse(Buffer.from(raw, "base64").toString()); }
  catch { return res.status(400).json({ error: "cookie prefs hỏng" }); }
  if (prefs.isStaff !== true) return res.status(403).json({ error: "cần isStaff=true" });
  res.json({ flag: flag("session_cookie_forge") });
});

// ============================================================
// 8) LỖ HỔNG: OAuth redirect_uri bypass -- validate kiểu startsWith thay vì
// so khớp CHÍNH XÁC domain đã đăng ký.
// ============================================================
const REGISTERED_REDIRECT = "http://127.0.0.1:80/oauth/callback";

app.get("/oauth/authorize", authMiddleware, (req, res) => {
  const { redirect_uri, state } = req.query;
  if (!redirect_uri) return res.status(400).json({ error: "thiếu redirect_uri" });

  // LỖ HỔNG: chỉ kiểm tra PREFIX, không so khớp domain chính xác.
  if (!redirect_uri.startsWith("http://127.0.0.1:80")) {
    return res.status(400).json({ error: "redirect_uri không được đăng ký" });
  }
  const code = crypto.randomBytes(16).toString("hex");
  const sep = redirect_uri.includes("?") ? "&" : "?";
  res.redirect(`${redirect_uri}${sep}code=${code}${state ? "&state=" + state : ""}`);
});

app.get("/oauth/callback", (req, res) => {
  res.json({ status: "oauth callback nhận code (demo)", code: req.query.code });
});

// ============================================================
// Trang chủ
// ============================================================
app.get("/", (req, res) => {
  res.json({
    service: "socialhub",
    endpoints: [
      "/login", "/register", "/api/me",
      "/profile/:username", "/profile/bio", "/report", "/admin/stolen",
      "/settings/update", "/admin/check",
      "/graphql",
      "/api/secret-profile",
      "/profile/email",
      "/prefs", "/prefs/theme", "/staff/flag",
      "/oauth/authorize", "/oauth/callback",
    ],
  });
});

app.listen(PORT, "0.0.0.0", async () => {
  console.log(`socialhub listening on :${PORT}`);
  const adminToken = issueToken("admin", "admin");
  try {
    await startBot(BASE_URL, adminToken);
  } catch (e) {
    console.error("[bot] không khởi động được:", e.message);
  }
});
