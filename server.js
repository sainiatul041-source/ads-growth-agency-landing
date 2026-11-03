const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const UPI_ID = process.env.UPI_ID || "sainiatul041@okhdfcbank";

if (!DATABASE_URL || !JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error("Missing DATABASE_URL, JWT_SECRET, ADMIN_EMAIL or ADMIN_PASSWORD");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false"
    ? false
    : { rejectUnauthorized: false }
});

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

const plans = {
  starter: { name: "Starter", price: 999, clicks: "All Click" },
  growth: { name: "Growth", price: 1499, clicks: "50% Click" },
  pro: { name: "Pro", price: 1999, clicks: "100% Click" }
};

function clean(value, max = 500) {
  return String(value ?? "").trim().slice(0, max);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validColor(value, fallback) {
  return /^#[0-9a-fA-F]{6}$/.test(value || "") ? value : fallback;
}

function validImageWidth(value) {
  const n = Number(value);
  return Number.isInteger(n) && n >= 20 && n <= 100 ? n : 100;
}

function makeToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  if (!token) return res.status(401).json({ error: "Please login first" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Session expired. Login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_pages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES ag_users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'My Landing Page',
      slug TEXT UNIQUE NOT NULL,
      headline TEXT DEFAULT '',
      description TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      button_text TEXT DEFAULT 'Join Now',
      button_url TEXT DEFAULT '',
      bg_color TEXT DEFAULT '#0f172a',
      text_color TEXT DEFAULT '#ffffff',
      button_color TEXT DEFAULT '#0088cc',
      design_template TEXT NOT NULL DEFAULT 'classic',
      image_width INTEGER NOT NULL DEFAULT 100,
      pixel_id TEXT DEFAULT '',
      published BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES ag_users(id) ON DELETE CASCADE,
      plan TEXT NOT NULL,
      amount INTEGER NOT NULL,
      utr TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ag_click_events (
      id SERIAL PRIMARY KEY,
      page_id INTEGER NOT NULL REFERENCES ag_pages(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS ag_pages_user_idx ON ag_pages(user_id);
    CREATE INDEX IF NOT EXISTS ag_click_page_idx ON ag_click_events(page_id);
    CREATE INDEX IF NOT EXISTS ag_payment_user_idx ON ag_payments(user_id);
  `);

  // Safe additions for existing installations.
  await pool.query(`
    ALTER TABLE ag_pages
    ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT 'My Landing Page';

    ALTER TABLE ag_pages
    ADD COLUMN IF NOT EXISTS design_template TEXT NOT NULL DEFAULT 'classic';

    ALTER TABLE ag_pages
    ADD COLUMN IF NOT EXISTS image_width INTEGER NOT NULL DEFAULT 100;

    ALTER TABLE ag_pages
    ADD COLUMN IF NOT EXISTS pixel_id TEXT DEFAULT '';

    ALTER TABLE ag_pages
    ADD COLUMN IF NOT EXISTS published BOOLEAN NOT NULL DEFAULT FALSE;
  `);

  const email = ADMIN_EMAIL.toLowerCase().trim();
  const existing = await pool.query(
    "SELECT id FROM ag_users WHERE email=$1",
    [email]
  );

  if (!existing.rowCount) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query(
      "INSERT INTO ag_users(name,email,password,role) VALUES($1,$2,$3,'admin')",
      ["Administrator", email, hash]
    );
  } else {
    await pool.query(
      "UPDATE ag_users SET role='admin' WHERE email=$1",
      [email]
    );
  }

  console.log("Database ready");
}

// Health check
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "ADS GROWTH AGENCY" });
});

// Plans
app.get("/api/plans", (req, res) => {
  res.json({ plans });
});

// Register
app.post("/api/register", async (req, res) => {
  try {
    const name = clean(req.body.name, 100);
    const email = clean(req.body.email, 200).toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !validEmail(email) || password.length < 6) {
      return res.status(400).json({
        error: "Enter valid name, email and password (minimum 6 characters)"
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO ag_users(name,email,password)
       VALUES($1,$2,$3)
       RETURNING id,name,email,role`,
      [name, email, hash]
    );

    const user = result.rows[0];
    res.status(201).json({ token: makeToken(user), user });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "An account with that email already exists" });
    }
    console.error("Register:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const email = clean(req.body.email, 200).toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM ag_users WHERE email=$1",
      [email]
    );

    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Incorrect email or password" });
    }

    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    };

    res.json({ token: makeToken(safeUser), user: safeUser });
  } catch (err) {
    console.error("Login:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Current user
app.get("/api/me", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT id,name,email,role,created_at FROM ag_users WHERE id=$1",
    [req.user.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "User not found" });
  res.json({ user: result.rows[0] });
});

// Submit payment
app.post("/api/payments", auth, async (req, res) => {
  try {
    const planKey = clean(req.body.plan, 30).toLowerCase();
    const utr = clean(req.body.utr, 100);
    const plan = plans[planKey];

    if (!plan) return res.status(400).json({ error: "Invalid plan" });
    if (utr.length < 6) return res.status(400).json({ error: "Enter a valid UTR number" });

    const duplicate = await pool.query(
      "SELECT id FROM ag_payments WHERE utr=$1",
      [utr]
    );
    if (duplicate.rowCount) {
      return res.status(409).json({ error: "This UTR has already been submitted" });
    }

    const result = await pool.query(
      `INSERT INTO ag_payments(user_id,plan,amount,utr)
       VALUES($1,$2,$3,$4)
       RETURNING id,plan,amount,utr,status,created_at`,
      [req.user.id, planKey, plan.price, utr]
    );

    res.status(201).json({
      message: "Payment submitted for verification",
      payment: result.rows[0]
    });
  } catch (err) {
    console.error("Payment:", err);
    res.status(500).json({ error: "Payment submission failed" });
  }
});

// User payment history
app.get("/api/payments", auth, async (req, res) => {
  const result = await pool.query(
    `SELECT id,plan,amount,utr,status,created_at,reviewed_at
     FROM ag_payments WHERE user_id=$1 ORDER BY id DESC`,
    [req.user.id]
  );
  res.json({ payments: result.rows });
});

// Create landing page
app.post("/api/pages", auth, async (req, res) => {
  try {
    const title = clean(req.body.title || req.body.headline || "My Landing Page", 120);
    const headline = clean(req.body.headline, 180);
    const description = clean(req.body.description, 3000);
    const imageUrl = clean(req.body.imageUrl || req.body.image_url, 1500);
    const buttonText = clean(req.body.buttonText || req.body.button_text || "Join Now", 60);
    const buttonUrl = clean(req.body.buttonUrl || req.body.button_url, 1500);
    const bg = validColor(req.body.bgColor || req.body.bg_color, "#0f172a");
    const text = validColor(req.body.textColor || req.body.text_color, "#ffffff");
    const button = validColor(req.body.buttonColor || req.body.button_color, "#0088cc");
    const design = clean(req.body.designTemplate || req.body.design_template || "classic", 30);
    const width = validImageWidth(req.body.imageWidth ?? req.body.image_width);
    const pixel = clean(req.body.pixelId || req.body.pixel_id, 30);

    const slug = "page-" + Date.now().toString(36) + "-" +
      Math.random().toString(36).slice(2, 8);

    const result = await pool.query(
      `INSERT INTO ag_pages
       (user_id,title,slug,headline,description,image_url,button_text,button_url,
        bg_color,text_color,button_color,design_template,image_width,pixel_id)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
       RETURNING *`,
      [req.user.id,title,slug,headline,description,imageUrl,buttonText,buttonUrl,
       bg,text,button,design,width,pixel]
    );

    res.status(201).json({ page: result.rows[0] });
  } catch (err) {
    console.error("Create page:", err);
    res.status(500).json({ error: "Could not create page" });
  }
});

// List user's pages
app.get("/api/pages", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM ag_pages WHERE user_id=$1 ORDER BY id DESC",
    [req.user.id]
  );
  res.json({ pages: result.rows });
});

// Edit page
app.put("/api/pages/:id", auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: "Invalid page ID" });

    const title = clean(req.body.title || req.body.headline || "My Landing Page", 120);
    const headline = clean(req.body.headline, 180);
    const description = clean(req.body.description, 3000);
    const imageUrl = clean(req.body.imageUrl || req.body.image_url, 1500);
    const buttonText = clean(req.body.buttonText || req.body.button_text || "Join Now", 60);
    const buttonUrl = clean(req.body.buttonUrl || req.body.button_url, 1500);
    const bg = validColor(req.body.bgColor || req.body.bg_color, "#0f172a");
    const text = validColor(req.body.textColor || req.body.text_color, "#ffffff");
    const button = validColor(req.body.buttonColor || req.body.button_color, "#0088cc");
    const design = clean(req.body.designTemplate || req.body.design_template || "classic", 30);
    const width = validImageWidth(req.body.imageWidth ?? req.body.image_width);
    const pixel = clean(req.body.pixelId || req.body.pixel_id, 30);

    const result = await pool.query(
      `UPDATE ag_pages SET
       title=$1,headline=$2,description=$3,image_url=$4,button_text=$5,
       button_url=$6,bg_color=$7,text_color=$8,button_color=$9,
       design_template=$10,image_width=$11,pixel_id=$12,updated_at=NOW()
       WHERE id=$13 AND user_id=$14 RETURNING *`,
      [title,headline,description,imageUrl,buttonText,buttonUrl,bg,text,
       button,design,width,pixel,id,req.user.id]
    );

    if (!result.rowCount) return res.status(404).json({ error: "Page not found" });
    res.json({ page: result.rows[0] });
  } catch (err) {
    console.error("Edit page:", err);
    res.status(500).json({ error: "Could not update page" });
  }
});

// Delete page
app.delete("/api/pages/:id", auth, async (req, res) => {
  const result = await pool.query(
    "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2 RETURNING id",
    [Number(req.params.id), req.user.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Page not found" });
  res.json({ message: "Page deleted" });
});

// Publish / unpublish
app.post("/api/pages/:id/publish", auth, async (req, res) => {
  const published = req.body.published !== false;
  const result = await pool.query(
    `UPDATE ag_pages SET published=$1,updated_at=NOW()
     WHERE id=$2 AND user_id=$3 RETURNING id,slug,published`,
    [published,Number(req.params.id),req.user.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Page not found" });

  res.json({
    page: result.rows[0],
    url: `${req.protocol}://${req.get("host")}/p/${result.rows[0].slug}`
  });
});

// Page click statistics
app.get("/api/pages/:id/stats", auth, async (req, res) => {
  const owner = await pool.query(
    "SELECT id FROM ag_pages WHERE id=$1 AND user_id=$2",
    [Number(req.params.id),req.user.id]
  );
  if (!owner.rowCount) return res.status(404).json({ error: "Page not found" });

  const result = await pool.query(
    `SELECT COUNT(*)::int AS total_clicks,
     COUNT(*) FILTER (WHERE created_at >= NOW()-INTERVAL '30 days')::int AS last30
     FROM ag_click_events WHERE page_id=$1`,
    [Number(req.params.id)]
  );
  res.json({ stats: result.rows[0] });
});

// Admin overview
app.get("/api/admin/stats", auth, adminOnly, async (req, res) => {
  const [users,pages,payments,clicks] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS total FROM ag_users WHERE role='user'"),
    pool.query("SELECT COUNT(*)::int AS total FROM ag_pages"),
    pool.query(`SELECT COUNT(*)::int AS total,
      COUNT(*) FILTER(WHERE status='pending')::int AS pending,
      COUNT(*) FILTER(WHERE status='approved')::int AS approved,
      COALESCE(SUM(amount) FILTER(WHERE status='approved'),0)::int AS revenue
      FROM ag_payments`),
    pool.query("SELECT COUNT(*)::int AS total FROM ag_click_events")
  ]);

  res.json({
    clients: users.rows[0],
    pages: pages.rows[0],
    payments: payments.rows[0],
    clicks: clicks.rows[0]
  });
});

// Admin: list payments
app.get("/api/admin/payments", auth, adminOnly, async (req, res) => {
  const result = await pool.query(
    `SELECT p.*,u.name,u.email
     FROM ag_payments p JOIN ag_users u ON u.id=p.user_id
     ORDER BY p.id DESC LIMIT 300`
  );
  res.json({ payments: result.rows });
});

// Admin: approve or reject payment
app.put("/api/admin/payments/:id", auth, adminOnly, async (req, res) => {
  const status = clean(req.body.status, 20).toLowerCase();
  if (!["approved","rejected"].includes(status)) {
    return res.status(400).json({ error: "Status must be approved or rejected" });
  }

  const result = await pool.query(
    `UPDATE ag_payments SET status=$1,reviewed_at=NOW()
     WHERE id=$2 AND status='pending' RETURNING *`,
    [status,Number(req.params.id)]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Pending payment not found" });
  res.json({ payment: result.rows[0] });
});

// Admin: list customers
app.get("/api/admin/users", auth, adminOnly, async (req, res) => {
  const result = await pool.query(
    `SELECT u.id,u.name,u.email,u.created_at,
     (SELECT COUNT(*)::int FROM ag_pages p WHERE p.user_id=u.id) AS pages
     FROM ag_users u WHERE u.role='user' ORDER BY u.id DESC LIMIT 500`
  );
  res.json({ users: result.rows });
});

// Admin: list pages
app.get("/api/admin/pages", auth, adminOnly, async (req, res) => {
  const result = await pool.query(
    `SELECT p.*,u.name AS user_name,u.email
     FROM ag_pages p JOIN ag_users u ON u.id=p.user_id
     ORDER BY p.id DESC LIMIT 500`
  );
  res.json({ pages: result.rows });
});

// Public landing page
app.get("/p/:slug", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM ag_pages WHERE slug=$1 AND published=TRUE",
      [clean(req.params.slug, 100)]
    );

    if (!result.rowCount) return res.status(404).send("Landing page not found");

    const p = result.rows[0];

    // Track page view as a click event.
    await pool.query(
      "INSERT INTO ag_click_events(page_id) VALUES($1)",
      [p.id]
    );

    const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
    }[c]));

    const safeLink = value => {
      try {
        const u = new URL(value);
        return ["http:","https:"].includes(u.protocol) ? esc(u.href) : "#";
      } catch {
        return "#";
      }
    };

    const width = validImageWidth(p.image_width);
    const image = p.image_url
      ? `<img src="${safeLink(p.image_url)}" alt=""
          style="display:block;width:${width}%;max-width:100%;max-height:350px;
          object-fit:contain;margin:20px auto;border-radius:12px">`
      : "";

    const pixel = /^\d{5,20}$/.test(p.pixel_id || "")
      ? `<script>
          !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){
          n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
          if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
          n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;
          s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}
          (window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
          fbq('init','${esc(p.pixel_id)}');fbq('track','PageView');
        </script>`
      : "";

    res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(p.title)}</title>
${pixel}
<style>
*{box-sizing:border-box}
body{margin:0;padding:24px 14px;min-height:100vh;
background:${validColor(p.bg_color,"#0f172a")};
color:${validColor(p.text_color,"#ffffff")};
font-family:Arial,sans-serif;display:flex;align-items:center;justify-content:center}
main{width:100%;max-width:520px;text-align:center;padding:25px;
border-radius:18px;background:rgba(255,255,255,.07)}
h1{font-size:30px;line-height:1.25}
p{font-size:17px;line-height:1.6;white-space:pre-wrap}
a{display:inline-block;margin-top:18px;padding:14px 25px;
border-radius:10px;text-decoration:none;font-weight:bold;
background:${validColor(p.button_color,"#0088cc")};color:#fff}
</style>
</head>
<body>
<main>
<h1>${esc(p.headline || p.title)}</h1>
${image}
<p>${esc(p.description)}</p>
<a href="${safeLink(p.button_url)}" target="_blank" rel="noopener noreferrer">
${esc(p.button_text || "Join Now")}
</a>
</main>
</body>
</html>`);
  } catch (err) {
    console.error("Public page:", err);
    res.status(500).send("Page could not be loaded");
  }
});

// UPI details
app.get("/api/payment-info", (req, res) => {
  res.json({ upiId: UPI_ID, payeeName: "ADS GROWTH AGENCY" });
});

// 404 for AP
