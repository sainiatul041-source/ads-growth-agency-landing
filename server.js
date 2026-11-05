require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const required = ["DATABASE_URL", "JWT_SECRET", "ADMIN_EMAIL", "ADMIN_PASSWORD"];
for (const key of required) {
  if (!process.env[key]) throw new Error("Missing environment variable: " + key);
}
if (process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters");
}

const app = express();
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === "false" ? false : { rejectUnauthorized: false }
});

const PORT = process.env.PORT || 3000;
const UPI_ID = process.env.UPI_ID || "sainiatul041@okhdfcbank";

const plans = {
  starter: { id: "starter", name: "Starter", price: 999, pages: 1, days: 30 },
  growth: { id: "growth", name: "Growth", price: 1499, pages: 1, days: 30 },
  pro: { id: "pro", name: "Pro", price: 1999, pages: 2, days: 30 }
};

const clean = (v, n = 500) => String(v ?? "").trim().slice(0, n);
const emailOk = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const colorOk = v => /^#[0-9a-fA-F]{6}$/.test(String(v || "")) ? v : "#2563eb";

function safeUrl(value) {
  const s = clean(value, 1000);
  if (!s) return "";
  try {
    const u = new URL(s);
    return ["http:", "https:"].includes(u.protocol) ? u.toString() : "";
  } catch {
    return "";
  }
}

function tokenFor(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  try {
    if (!token) throw new Error("Missing token");
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Please login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user && req.user.role === "admin") return next();
  return res.status(403).json({ error: "Admin access required." });
}

const asyncRoute = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(254) NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'customer',
      plan VARCHAR(30),
      subscription_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES ag_users(id) ON DELETE CASCADE,
      plan_id VARCHAR(30) NOT NULL,
      amount INTEGER NOT NULL,
      utr VARCHAR(100) NOT NULL UNIQUE,
      status VARCHAR(20) DEFAULT 'pending',
      admin_note TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ag_pages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES ag_users(id) ON DELETE CASCADE,
      slug VARCHAR(100) NOT NULL UNIQUE,
      title VARCHAR(160) NOT NULL,
      headline VARCHAR(220) NOT NULL,
      description TEXT DEFAULT '',
      button_text VARCHAR(40) DEFAULT 'Learn More',
      button_url TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      pixel_id VARCHAR(40) DEFAULT '',
      bg_color VARCHAR(7) DEFAULT '#0b1530',
      text_color VARCHAR(7) DEFAULT '#ffffff',
      button_color VARCHAR(7) DEFAULT '#2563eb',
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_events (
      id BIGSERIAL PRIMARY KEY,
      page_id BIGINT REFERENCES ag_pages(id) ON DELETE CASCADE,
      event_type VARCHAR(20) CHECK(event_type IN ('visit','click')),
      visitor_hash VARCHAR(64) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS ag_pages_user_idx ON ag_pages(user_id);
    CREATE INDEX IF NOT EXISTS ag_events_page_idx ON ag_events(page_id,created_at);
  `);

  const email = clean(process.env.ADMIN_EMAIL, 254).toLowerCase();
  const passwordHash = await bcrypt.hash(String(process.env.ADMIN_PASSWORD), 12);

  await pool.query(`
    INSERT INTO ag_users(name,email,password,role)
    VALUES($1,$2,$3,'admin')
    ON CONFLICT(email)
    DO UPDATE SET role='admin',password=EXCLUDED.password
  `, ["Administrator", email, passwordHash]);

  console.log("Admin account verified.");
}

app.get("/health", asyncRoute(async (req, res) => {
  await pool.query("SELECT 1");
  res.json({ ok: true, database: "connected" });
}));

app.get("/api/config", (req, res) => {
  res.json({ brand: "ADS GROWTH AGENCY PRO", upiId: UPI_ID });
});

app.get("/api/plans", (req, res) => {
  res.json(Object.values(plans));
});

app.get("/api/payment-info", (req, res) => {
  res.json({ upiId: UPI_ID, qrPath: "/scanner.png" });
});

app.post("/api/register", asyncRoute(async (req, res) => {
  const name = clean(req.body.name, 100);
  const email = clean(req.body.email, 254).toLowerCase();
  const password = String(req.body.password || "");

  if (name.length < 2 || !emailOk(email) || password.length < 8) {
    return res.status(400).json({ error: "Enter name, valid email and password of at least 8 characters." });
  }

  const hash = await bcrypt.hash(password, 12);
  try {
    const { rows } = await pool.query(
      `INSERT INTO ag_users(name,email,password)
       VALUES($1,$2,$3)
       RETURNING id,name,email,role,plan,subscription_expires`,
      [name, email, hash]
    );
    res.status(201).json({ token: tokenFor(rows[0]), user: rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Email already registered." });
    throw e;
  }
}));

// Login: password is always compared with the text hash from PostgreSQL.
app.post("/api/login", asyncRoute(async (req, res) => {
  const email = clean(req.body.email, 254).toLowerCase();
  const password = String(req.body.password || "");

  const { rows } = await pool.query(
    `SELECT id,name,email,password,role,plan,subscription_expires
     FROM ag_users WHERE LOWER(email)=$1 LIMIT 1`,
    [email]
  );

  const u = rows[0];
  if (!u || typeof u.password !== "string") {
    return res.status(401).json({ error: "Incorrect email or password." });
  }

  const valid = await bcrypt.compare(password, u.password);
  if (!valid) {
    return res.status(401).json({ error: "Incorrect email or password." });
  }

  const user = {
    id: u.id, name: u.name, email: u.email, role: u.role,
    plan: u.plan, subscription_expires: u.subscription_expires
  };
  res.json({ token: tokenFor(user), user });
}));

app.get("/api/me", auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id,name,email,role,plan,subscription_expires
     FROM ag_users WHERE id=$1`,
    [req.user.id]
  );
  if (!rows[0]) return res.status(404).json({ error: "Account not found." });
  res.json({ user: rows[0] });
}));

app.post("/api/payments", auth, asyncRoute(async (req, res) => {
  const plan = plans[clean(req.body.plan_id, 30)];
  const utr = clean(req.body.utr, 100).replace(/\s/g, "").toUpperCase();

  if (!plan || !/^[A-Z0-9-]{8,40}$/.test(utr)) {
    return res.status(400).json({ error: "Select a plan and enter a valid UTR." });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO ag_payments(user_id,plan_id,amount,utr)
       VALUES($1,$2,$3,$4)
       RETURNING id,plan_id,amount,utr,status,created_at`,
      [req.user.id, plan.id, plan.price, utr]
    );
    res.status(201).json({
      payment: rows[0],
      message: "Payment submitted for manual verification."
    });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "UTR already submitted." });
    throw e;
  }
}));

app.get("/api/payments/mine", auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id,plan_id,amount,utr,status,admin_note,created_at,reviewed_at
     FROM ag_payments WHERE user_id=$1 ORDER BY id DESC`,
    [req.user.id]
  );
  res.json({ payments: rows });
}));

function pagePayload(b) {
  const title = clean(b.title, 160);
  const headline = clean(b.headline, 220);
  if (title.length < 2 || headline.length < 2) {
    throw Object.assign(new Error("Page title and headline are required."), { status: 400 });
  }
  return {
    title,
    headline,
    description: clean(b.description, 4000),
    button_text: clean(b.button_text, 40) || "Learn More",
    button_url: safeUrl(b.button_url),
    image_url: safeUrl(b.image_url),
    pixel_id: clean(b.pixel_id, 40).replace(/[^0-9]/g, ""),
    bg_color: colorOk(b.bg_color),
    text_color: colorOk(b.text_color),
    button_color: colorOk(b.button_color)
  };
}

async function canCreate(user) {
  if (user.role === "admin") return { allowed: true, limit: 999999 };

  const { rows } = await pool.query(
    "SELECT plan,subscription_expires FROM ag_users WHERE id=$1",
    [user.id]
  );
  const u = rows[0];
  if (!u?.plan || !u.subscription_expires || new Date(u.subscription_expires) <= new Date()) {
    return { allowed: false, limit: 0 };
  }
  const plan = plans[u.plan];
  return { allowed: !!plan, limit: plan?.pages || 0 };
}

app.get("/api/pages", auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM ag_pages WHERE user_id=$1 ORDER BY id DESC`,
    [req.user.id]
  );
  res.json({ pages: rows });
}));

app.post("/api/pages", auth, asyncRoute(async (req, res) => {
  const access = await canCreate(req.user);
  const { rows: counts } = await pool.query(
    "SELECT COUNT(*)::int AS total FROM ag_pages WHERE user_id=$1",
    [req.user.id]
  );

  if (!access.allowed || counts[0].total >= access.limit) {
    return res.status(403).json({ error: "An active plan with an available page slot is required." });
  }

  const p = pagePayload(req.body);
  const slug = clean(req.body.slug, 80).toLowerCase()
    .replace(/[^a-z0-9-]/g, "-").replace(/-+/g, "-")
    .replace(/^-|-$/g, "") || crypto.randomBytes(5).toString("hex");

  try {
    const { rows } = await pool.query(
      `INSERT INTO ag_pages(
        user_id,slug,title,headline,description,button_text,
        button_url,image_url,pixel_id,bg_color,text_color,button_color
      ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING *`,
      [req.user.id, slug, ...Object.values(p)]
    );
    res.status(201).json({ page: rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "This page URL is already in use." });
    throw e;
  }
}));

app.put("/api/pages/:id", auth, asyncRoute(async (req, res) => {
  const p = pagePayload(req.body);
  const { rows } = await pool.query(
    `UPDATE ag_pages SET title=$1,headline=$2,description=$3,
      button_text=$4,button_url=$5,image_url=$6,pixel_id=$7,
      bg_color=$8,text_color=$9,button_color=$10,updated_at=NOW()
     WHERE id=$11 AND user_id=$12 RETURNING *`,
    [...Object.values(p), req.params.id, req.user.id]
  );
  if (!rows[0]) return res.status(404).json({ error: "Page not found." });
  res.json({ page: rows[0] });
}));

app.post("/api/pages/:id/publish", auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE ag_pages SET published=NOT published,updated_at=NOW()
     WHERE id=$1 AND user_id=$2 RETURNING id,slug,published`,
    [req.params.id, req.user.id]
  );
  if (!rows[0]) return res.status(404).json({ error: "Page not found." });
  res.json({ page: rows[0] });
}));

app.delete("/api/pages/:id", auth, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2",
    [req.params.id, req.user.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Page not found." });
  res.json({ ok: true });
}));

// Admin dashboard statistics
app.get("/api/admin/stats", auth, adminOnly, asyncRoute(async (req, res) => {
  const [clients, pages, published, pending, visits, clicks] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS total FROM ag_users WHERE role<>'admin'"),
    pool.query("SELECT COUNT(*)::int AS total FROM ag_pages"),
    pool.query("SELECT COUNT(*)::int AS total FROM ag_pages WHERE published=true"),
    pool.query("SELECT COUNT(*)::int AS total FROM ag_payments WHERE status='pending'"),
    pool.query("SELECT COUNT(*)::int AS total FROM ag_events WHERE event_type='visit'"),
    pool.query("SELECT COUNT(*)::int AS total FROM ag_events WHERE event_type='click'")
  ]);
  res.json({
    clients: clients.rows[0],
    pages: pages.rows[0],
    publishedPages: published.rows[0],
    payments: { pending: pending.rows[0].total },
    clicks: {
      visits: visits.rows[0].total,
      valid_clicks: clicks.rows[0].total
    }
  });
}));

app.get("/api/admin/payments", auth, adminOnly, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT p.*,u.name,u.email
    FROM ag_payments p JOIN ag_users u ON u.id=p.user_id
    ORDER BY p.created_at DESC
  `);
  res.json({ payments: rows });
}));

app.post("/api/admin/payments/:id/review", auth, adminOnly, asyncRoute(async (req, res) => {
  const status = clean(req.body.status, 20);
  const note = clean(req.body.note, 500);
  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid review status." });
  }

  const client = await pool.connect();
  let transactionOpen = false;

  try {
    await client.query("BEGIN");
    transactionOpen = true;

    const { rows } = await client.query(
      "SELECT * FROM ag_payments WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );
    const payment = rows[0];

    if (!payment) {
      await client.query("ROLLBACK");
      transactionOpen = false;
      return res.status(404).json({ error: "Payment not found." });
    }

    if (payment.status !== "pending") {
      await client.query("ROLLBACK");
      transactionOpen = false;
      return res.status(409).json({ error: "Payment already reviewed." });
    }

    if (status === "approved") {
      const plan = plans[payment.plan_id];
      if (!plan) throw new Error("Unknown plan");
      await client.query(
        `UPDATE ag_users SET plan=$1,
          subscription_expires=GREATEST(COALESCE(subscription_expires,NOW()),NOW())
          + ($2 || ' days')::interval
         WHERE id=$3`,
        [plan.id, plan.days, payment.user_id]
      );
    }

    await client.query(
      "UPDATE ag_payments SET status=$1,admin_note=$2,reviewed_at=NOW() WHERE id=$3",
      [status, note, req.params.id]
    );
    await client.query("COMMIT");
    transactionOpen = false;
    res.json({ ok: true, status });
  } catch (e) {
    if (transactionOpen) await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}));

app.get("/api/admin/clicks", auth, adminOnly, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT e.id,e.event_type,e.created_at,p.title,p.slug,u.email
    FROM ag_events e
    JOIN ag_pages p ON p.id=e.page_id
    JOIN ag_users u ON u.id=p.user_id
    ORDER BY e.created_at DESC LIMIT 500
  `);
  res.json({ events: rows });
}));

// Record genuine visits and CTA clicks; deduplicate for 30 minutes.
app.get("/api/track/:slug/:event", asyncRoute(async (req, res) => {
  const event = req.params.event;
  if (!["visit", "click"].includes(event)) {
    return res.status(400).json({ error: "Invalid event." });
  }

  const { rows } = await pool.query(
    "SELECT id FROM ag_pages WHERE slug=$1 AND published=true",
    [req.params.slug]
  );
  if (!rows[0]) return res.status(404).json({ error: "Page not found." });

  const visitor = crypto.createHash("sha256")
    .update((req.ip || "") + "|" + (req.get("user-agent") || ""))
    .digest("hex");

  const recent = await pool.query(
    `SELECT 1 FROM ag_events
     WHERE page_id=$1 AND event_type=$2 AND visitor_hash=$3
       AND created_at>NOW()-INTERVAL '30 minutes' LIMIT 1`,
    [rows[0].id, event, visitor]
  );

  if (!recent.rowCount) {
    await pool.query(
      "INSERT INTO ag_events(page_id,event_type,visitor_hash) VALUES($1,$2,$3)",
      [rows[0].id, event, visitor]
    );
  }
  res.json({ ok: true });
}));

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  }[c]));
}

// Public published landing page
app.get("/p/:slug", asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM ag_pages WHERE slug=$1 AND published=true",
    [req.params.slug]
  );
  const p = rows[0];
  if (!p) return res.status(404).send("Page not found or not published.");

  const image = p.image_url
    ? `<img class="heroimg" src="${esc(p.image_url)}" alt="${esc(p.title)}">`
    : "";

  const pixel = p.pixel_id ? `
    <script>
      !function(f,b,e,v,n,t,s){
        if(f.fbq)return;n=f.fbq=function(){
          n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)
        };
        if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
        n.queue=[];t=b.createElement(e);t.async=!0;
        t.src=v;s=b.getElementsByTagName(e)[0];
        s.parentNode.insertBefore(t,s)
      }(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
      fbq('init','${esc(p.pixel_id)}');fbq('track','PageView');
    </script>` : "";

  res.type("html").send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(p.title)}</title>
${pixel}
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:22px;
background:${esc(p.bg_color)};color:${esc(p.text_color)};font-family:Arial,sans-serif}
.card{width:min(760px,100%);text-align:center;padding:38px 24px;
border:1px solid #ffffff25;border-radius:24px;background:#ffffff0c}
.heroimg{max-width:100%;max-height:360px;object-fit:contain;border-radius:16px;margin:0 auto 24px}
h1{font-size:clamp(30px,6vw,54px);margin:12px 0}
p{font-size:18px;line-height:1.7;opacity:.9}
.cta{display:inline-block;margin-top:16px;padding:16px 28px;border-radius:12px;
background:${esc(p.button_color)};color:#fff;text-decoration:none;font-weight:bold}
</style>
</head>
<body>
<main class="card">
${image}
<h1>${esc(p.headline)}</h1>
<p>${esc(p.description)}</p>
${p.button_url ? `<a class="cta" id="cta" href="${esc(p.button_url)}" target="_blank" rel="noopener">${esc(p.button_text)}</a>` : ""}
</main>
<script>
fetch('/api/track/${encodeURIComponent(p.slug)}/visit').catch(()=>{});
const c=document.getElementById('cta');
if(c)c.addEventListener('click',()=>fetch('/api/track/${encodeURIComponent(p.slug)}/click').catch(()=>{}));
</script>
</body>
</html>`);
}));

// Static frontend and scanner image
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((err, req, res, next) => {
  console.error("Application error:", err);
  res.status(err.status || 500).json({
    error: err.status ? err.message : "Server error. Check Render logs."
  });
});

initDb().then(() => {
  app.listen(PORT, () => console.log("ADS GROWTH AGENCY PRO running on port " + PORT));
}).catch(err => {
  console.error("Database initialization failed:", err);
  process.exit(1);
});
