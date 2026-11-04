const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");
require("dotenv").config();

const app = express();

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const UPI_ID = process.env.UPI_ID || "sainiatul041@okhdfcbank";

if (!DATABASE_URL || !JWT_SECRET || JWT_SECRET.length < 32 ||
    !ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === "false"
    ? false
    : { rejectUnauthorized: false }
});

const plans = [
  { id: "starter", name: "Starter", amount: 999, pages: 1, description: "1 landing page • 30 days" },
  { id: "growth", name: "Growth", amount: 1499, pages: 1, description: "1 landing page • 30 days" },
  { id: "pro", name: "Pro", amount: 1999, pages: 2, description: "2 landing pages • 30 days" }
];

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300
}));

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'customer',
      plan TEXT,
      subscription_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES ag_users(id) ON DELETE CASCADE,
      plan_id TEXT NOT NULL,
      amount INTEGER NOT NULL,
      utr TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ag_pages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES ag_users(id) ON DELETE CASCADE,
      slug TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL,
      headline TEXT,
      description TEXT,
      button_text TEXT DEFAULT 'Learn More',
      button_url TEXT,
      image_url TEXT,
      pixel_id TEXT,
      design_template TEXT DEFAULT 'classic',
      image_width INTEGER DEFAULT 100,
      bg_color TEXT DEFAULT '#0b1224',
      text_color TEXT DEFAULT '#ffffff',
      button_color TEXT DEFAULT '#16a34a',
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_click_events (
      id SERIAL PRIMARY KEY,
      page_id INTEGER REFERENCES ag_pages(id) ON DELETE CASCADE,
      event_type TEXT,
      visitor_id TEXT,
      suspicious BOOLEAN DEFAULT FALSE,
      reason TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  const admin = await pool.query(
    "SELECT id FROM ag_users WHERE LOWER(email)=LOWER($1)",
    [ADMIN_EMAIL]
  );

  if (admin.rowCount === 0) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query(
      `INSERT INTO ag_users(name,email,password,role)
       VALUES($1,$2,$3,'admin')`,
      ["Administrator", ADMIN_EMAIL, hash]
    );
  } else {
    await pool.query(
      "UPDATE ag_users SET role='admin' WHERE LOWER(email)=LOWER($1)",
      [ADMIN_EMAIL]
    );
  }

  console.log("Database initialized");
}

function makeToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) return res.status(401).json({ error: "Please login" });

    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query(
      "SELECT id,name,email,role,plan,subscription_expires FROM ag_users WHERE id=$1",
      [decoded.id]
    );

    if (!result.rowCount) {
      return res.status(401).json({ error: "Account not found" });
    }

    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: "Login expired. Please login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

function activeSubscription(user) {
  return user.role === "admin" ||
    (user.subscription_expires &&
     new Date(user.subscription_expires) > new Date());
}

function pageLimit(user) {
  if (user.role === "admin") return 999999;
  if (!activeSubscription(user)) return 0;
  const plan = plans.find(p => p.id === user.plan);
  return plan ? plan.pages : 0;
}

function safeUrl(value) {
  if (!value) return "";
  try {
    const u = new URL(value);
    return ["http:", "https:"].includes(u.protocol) ? u.href : "";
  } catch {
    return "";
  }
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch (err) {
    res.status(500).json({ ok: false, error: "Database unavailable" });
  }
});

app.get("/api/config", (req, res) => {
  res.json({
    upiId: UPI_ID,
    plans
  });
});

app.get("/api/plans", (req, res) => {
  res.json({ plans });
});

app.get("/api/payment-info", (req, res) => {
  res.json({ upiId: UPI_ID, payeeName: "ADS GROWTH AGENCY" });
});

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 8) {
      return res.status(400).json({ error: "Name, email and password of 8+ characters required" });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO ag_users(name,email,password)
       VALUES($1,LOWER($2),$3)
       RETURNING id,name,email,role,plan`,
      [name.trim(), email.trim(), hash]
    );

    const user = result.rows[0];
    res.json({ token: makeToken(user), user });
  } catch (err) {
    res.status(400).json({ error: "Email may already be registered" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query(
      "SELECT * FROM ag_users WHERE LOWER(email)=LOWER($1)",
      [email || ""]
    );

    if (!result.rowCount ||
        !(await bcrypt.compare(password || "", result.rows[0].password))) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = result.rows[0];
    res.json({
      token: makeToken(user),
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/me", auth, (req, res) => {
  res.json({ user: req.user });
});

app.post("/api/payments", auth, async (req, res) => {
  try {
    const { planId, utr } = req.body;
    const plan = plans.find(p => p.id === planId);

    if (!plan) return res.status(400).json({ error: "Invalid plan" });
    if (!utr || String(utr).trim().length < 6) {
      return res.status(400).json({ error: "Enter a valid UTR number" });
    }

    const existing = await pool.query(
      "SELECT id FROM ag_payments WHERE utr=$1",
      [String(utr).trim()]
    );
    if (existing.rowCount) {
      return res.status(409).json({ error: "This UTR has already been submitted" });
    }

    await pool.query(
      `INSERT INTO ag_payments(user_id,plan_id,amount,utr)
       VALUES($1,$2,$3,$4)`,
      [req.user.id, plan.id, plan.amount, String(utr).trim()]
    );

    res.json({ message: "Payment request submitted. Admin will verify your UTR." });
  } catch (err) {
    res.status(500).json({ error: "Could not submit payment request" });
  }
});

app.get("/api/payments/mine", auth, async (req, res) => {
  const result = await pool.query(
    `SELECT id,plan_id,amount,utr,status,created_at
     FROM ag_payments WHERE user_id=$1 ORDER BY id DESC`,
    [req.user.id]
  );
  res.json({ payments: result.rows });
});

app.get("/api/pages", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM ag_pages WHERE user_id=$1 ORDER BY id DESC",
    [req.user.id]
  );
  res.json({ pages: result.rows });
});

app.post("/api/pages", auth, async (req, res) => {
  try {
    const count = await pool.query(
      "SELECT COUNT(*)::int AS total FROM ag_pages WHERE user_id=$1",
      [req.user.id]
    );

    if (count.rows[0].total >= pageLimit(req.user)) {
      return res.status(403).json({ error: "Please get an active plan before creating a page" });
    }

    const b = req.body;
    if (!b.title || !b.title.trim()) {
      return res.status(400).json({ error: "Page title is required" });
    }

    const slug = crypto.randomBytes(5).toString("hex");
    const result = await pool.query(
      `INSERT INTO ag_pages
      (user_id,slug,title,headline,description,button_text,button_url,
       image_url,pixel_id,design_template,image_width,bg_color,text_color,button_color)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      RETURNING *`,
      [
        req.user.id, slug, b.title, b.headline || "", b.description || "",
        b.buttonText || "Learn More", safeUrl(b.buttonUrl),
        safeUrl(b.imageUrl), b.pixelId || "",
        b.designTemplate || "classic",
        Math.min(100, Math.max(20, Number(b.imageWidth) || 100)),
        b.bgColor || "#0b1224", b.textColor || "#ffffff",
        b.buttonColor || "#16a34a"
      ]
    );

    res.json({ page: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Could not save page" });
  }
});

app.put("/api/pages/:id", auth, async (req, res) => {
  try {
    const b = req.body;
    const result = await pool.query(
      `UPDATE ag_pages SET
       title=$1,headline=$2,description=$3,button_text=$4,button_url=$5,
       image_url=$6,pixel_id=$7,design_template=$8,image_width=$9,
       bg_color=$10,text_color=$11,button_color=$12,updated_at=NOW()
       WHERE id=$13 AND user_id=$14 RETURNING *`,
      [
        b.title, b.headline || "", b.description || "",
        b.buttonText || "Learn More", safeUrl(b.buttonUrl),
        safeUrl(b.imageUrl), b.pixelId || "",
        b.designTemplate || "classic",
        Math.min(100, Math.max(20, Number(b.imageWidth) || 100)),
        b.bgColor || "#0b1224", b.textColor || "#ffffff",
        b.buttonColor || "#16a34a", req.params.id, req.user.id
      ]
    );

    if (!result.rowCount) return res.status(404).json({ error: "Page not found" });
    res.json({ page: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Could not update page" });
  }
});

app.post("/api/pages/:id/publish", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE ag_pages SET published=NOT published,updated_at=NOW()
       WHERE id=$1 AND user_id=$2 RETURNING *`,
      [req.params.id, req.user.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Page not found" });

    const page = result.rows[0];
    res.json({
      page,
      url: page.published ? `/p/${page.slug}` : null
    });
  } catch (err) {
    res.status(500).json({ error: "Could not publish page" });
  }
});

app.delete("/api/pages/:id", auth, async (req, res) => {
  const result = await pool.query(
    "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2 RETURNING id",
    [req.params.id, req.user.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Page not found" });
  res.json({ success: true });
});

app.get("/api/admin/stats", auth, adminOnly, async (req, res) => {
  const [clients, clicks, payments] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS total FROM ag_users WHERE role='customer'"),
    pool.query(`SELECT
      COUNT(*) FILTER(WHERE suspicious=false)::int AS valid_clicks,
      COUNT(DISTINCT visitor_id)::int AS unique_visitors,
      COUNT(*) FILTER(WHERE suspicious=true)::int AS suspicious_events
      FROM ag_click_events`),
    pool.query(`SELECT
      COUNT(*) FILTER(WHERE status='pending')::int AS pending,
      COUNT(*) FILTER(WHERE status='approved')::int AS approved
      FROM ag_payments`)
  ]);

  res.json({
    clients: clients.rows[0],
    clicks: clicks.rows[0],
    payments: payments.rows[0]
  });
});

app.get("/api/admin/payments", auth, adminOnly, async (req, res) => {
  const result = await pool.query(
    `SELECT p.*,u.email FROM ag_payments p
     JOIN ag_users u ON u.id=p.user_id ORDER BY p.id DESC`
  );
  res.json({ payments: result.rows });
});

app.post("/api/admin/payments/:id/review", auth, adminOnly, async (req, res) => {
  const { status } = req.body;
  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid payment status" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const result = await client.query(
      "UPDATE ag_payments SET status=$1,reviewed_at=NOW() WHERE id=$2 AND status='pending' RETURNING *",
      [status, req.params.id]
    );

    if (!result.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Pending payment not found" });
    }

    const payment = result.rows[0];

    if (status === "approved") {
      await client.query(
        `UPDATE ag_users SET plan=$1,
         subscription_expires=GREATEST(COALESCE(subscription_expires,NOW()),NOW()) + INTERVAL '30 days'
         WHERE id=$2`,
        [payment.plan_id, payment.user_id]
      );
    }

    await client.query("COMMIT");
    res.json({ success: true, status });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: "Could not review payment" });
  } finally {
    client.release();
  }
});

app.get("/api/admin/clicks", auth, adminOnly, async (req, res) => {
  const result = await pool.query(
    `SELECT e.*,p.title FROM ag_click_events e
     LEFT JOIN ag_pages p ON p.id=e.page_id
     ORDER BY e.id DESC LIMIT 200`
  );
  res.json({ events: result.rows });
});

app.get("/p/:slug", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM ag_pages WHERE slug=$1 AND published=true",
      [req.params.slug]
    );
    if (!result.rowCount) return res.status(404).send("Page not found");

    const p = result.rows[0];
    const visitor = req.headers["x-forwarded-for"] || req.ip;

    await pool.query(
      `INSERT INTO ag_click_events(page_id,event_type,visitor_id)
       VALUES($1,'visit',$2)`,
      [p.id, crypto.createHash("sha256").update(String(visitor)).digest("hex")]
    );

    const pixel = /^\d+$/.test(p.pixel_id || "") ? `
      <script>
      !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){
      n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
      if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
      n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;
      s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}
      (window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
      fbq('init','${p.pixel_id}');fbq('track','PageView');
      </script>` : "";

    res.send(`<!doctype html>
    <html><head><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escapeHTML(p.title)}</title>${pixel}
    <style>
    body{margin:0;padding:30px 16px;background:${p.bg_color};color:${p.text_color};font-family:Arial;text-align:center}
    main{max-width:700px;margin:40px auto}
    h1{font-size:34px}
    p{line-height:1.7}
    img{width:${p.image_width}%;max-width:100%;height:auto;border-radius:14px;margin:20px auto}
    a{display:inline-block;padding:14px 24px;border-radius:9px;background:${p.button_color};color:white;text-decoration:none;font-weight:bold}
    </style></head><body><main>
    <h1>${escapeHTML(p.headline || p.title)}</h1>
    <p>${escapeHTML(p.description || "")}</p>
    ${p.image_url ? `<img src="${escapeHTML(p.image_url)}" alt="">` : ""}
    ${p.button_url ? `<a href="${escapeHTML(p.button_url)}" target="_blank" rel="noopener">${escapeHTML(p.button_text)}</a>` : ""}
    </main></body></html>`);
  } catch (err) {
    console.error("Public page:", err);
    res.status(500).send("Page could not be loaded");
  }
});

function escapeHTML(value) {
  return String(value || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  }[c]));
}

app.use((req, res) => {
  res.status(404).send("Page not found");
});

async function startServer() {
  try {
    await initDB();
    app.listen(PORT, "0.0.0.0", () => {
      console.log("ADS GROWTH AGENCY running on port " + PORT);
    });
  } catch (err) {
    console.error("Server startup failed:", err.message);
    process.exit(1);
  }
}

startServer();
      
