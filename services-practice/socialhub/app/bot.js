// "Admin bot" giả lập — định kỳ mở report mới bằng trình duyệt headless thật
// (Puppeteer/Chromium), có cookie admin hợp lệ, y hệt cách BTC chấm XSS/report
// trong A/D thật. CHỈ visit URL người dùng tự báo cáo qua /report.
const puppeteer = require("puppeteer");

const QUEUE = [];

function queueReport(url) {
  QUEUE.push(url);
}

async function startBot(baseUrl, adminCookieValue) {
  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });

  setInterval(async () => {
    const url = QUEUE.shift();
    if (!url) return;
    let page;
    try {
      page = await browser.newPage();
      await page.setCookie({
        name: "token",
        value: adminCookieValue,
        url: baseUrl,
      });
      await page.goto(url, { waitUntil: "networkidle2", timeout: 8000 });
      await new Promise((r) => setTimeout(r, 1500)); // chờ JS trên trang kịp chạy
    } catch (e) {
      console.error("[bot] lỗi khi visit", url, e.message);
    } finally {
      if (page) await page.close().catch(() => {});
    }
  }, 2000);

  console.log("[bot] admin bot đã sẵn sàng, poll report mỗi 2s");
}

module.exports = { startBot, queueReport };
