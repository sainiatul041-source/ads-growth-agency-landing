require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL || !JWT_SECRET) {
  console.error("DATABASE_URL aur JWT_SECRET Render me set karein.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false"
    ? false
    : { rejectUnauthorized: false }
});

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

const PLANS = [
  { id: "starter", name: "Starter", amount: 499, label: "All Click" },
  { id: "growth", name: "Growth", amount: 999, label: "50% Click" },
  { id: "pro", name: "Pro", amount: 1499, label: "100% Click" }
];

const UPI_ID = process.env.UPI_ID || "sainiatul041@okhdfcbank";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

function clean(value, max = 500) {
  return String(value || "").trim().slice(0, max);
}

function validUrl(value) {
  if (!value) return "";
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

function safeColor(value, fallback) {
  const color = String(value || "").trim();
  return /^#[0-9a-fA-F]{6}$/.test(color) ? color : fallback;
}

function slugify(value) {
  return clean(value, 80).toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "") || "my-page";
}

function escapeHtml(value) {
  return String(value || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  })[c]);
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

  if (!token) return res.status(401).json({ error: "Login required" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Session expired. Login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

function paidOnly(req, res, next) {
  if (req.user.role === "admin") return next();

  pool.query(
    `SELECT id FROM ag2_payments
     WHERE user_id=$1 AND status='approved'
     ORDER BY created_at DESC LIMIT 1`,
    [req.user.id]
  ).then(result => {
    if (!result.rowCount) {
      return res.status(403).json({ error: "Payment approval required" });
    }
    next();
  }).catch(next);
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag2_users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag2_payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES ag2_users(id),
      plan_id TEXT NOT NULL,
      amount NUMERIC(10,2) NOT NULL,
      utr TEXT NOT NULL,
      screenshot_url TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ag2_pages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES ag2_users(id),
      title TEXT NOT NULL,
      headline TEXT NOT NULL,
      description TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      button_text TEXT DEFAULT 'Join Now',
      button_url TEXT DEFAULT '',
      pixel_id TEXT DEFAULT '',
      slug TEXT UNIQUE NOT NULL,
      is_published BOOLEAN DEFAULT FALSE,
      bg_color TEXT DEFAULT '#081225',
      text_color TEXT DEFAULT '#ffffff',
      button_color TEXT DEFAULT '#0891b2',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    ALTER TABLE ag2_pages ADD COLUMN IF NOT EXISTS bg_color TEXT DEFAULT '#081225';
    ALTER TABLE ag2_pages ADD COLUMN IF NOT EXISTS text_color TEXT DEFAULT '#ffffff';
    ALTER TABLE ag2_pages ADD COLUMN IF NOT EXISTS button_color TEXT DEFAULT '#0891b2';
    ALTER TABLE ag2_payments ADD COLUMN IF NOT EXISTS amount NUMERIC(10,2);
    ALTER TABLE ag2_payments ADD COLUMN IF NOT EXISTS screenshot_url TEXT DEFAULT '';
    ALTER TABLE ag2_payments ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
  `);

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query(
      `INSERT INTO ag2_users (name,email,password_hash,role)
       VALUES ($1,$2,$3,'admin')
       ON CONFLICT (email) DO UPDATE SET role='admin'`,
      ["Administrator", ADMIN_EMAIL, hash]
    );
  }

  console.log("Database ready");
}

app.get("/api/config", (req, res) => {
  res.json({ plans: PLANS, upiId: UPI_ID });
});

app.post("/api/register", async (req, res, next) => {
  try {
    const name = clean(req.body.name, 100);
    const email = clean(req.body.email, 150).toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email.includes("@") || password.length < 8) {
      return res.status(400).json({
        error: "Name, valid email aur minimum 8 character password zaroori hai."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO ag2_users (name,email,password_hash)
       VALUES ($1,$2,$3)
       RETURNING id,name,email,role`,
      [name, email, hash]
    );

    res.json({
      token: makeToken(result.rows[0]),
      user: result.rows[0]
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Email already registered" });
    }
    next(err);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const email = clean(req.body.email, 150).toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      `SELECT id,name,email,password_hash,role
       FROM ag2_users WHERE email=$1`,
      [email]
    );

    if (!result.rowCount ||
        !(await bcrypt.compare(password, result.rows[0].password_hash))) {
      return res.status(401).json({ error: "Email ya password galat hai" });
    }

    const user = result.rows[0];
    delete user.password_hash;

    res.json({ token: makeToken(user), user });
  } catch (err) {
    next(err);
  }
});

app.get("/api/me", auth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id,name,email,role FROM ag2_users WHERE id=$1`,
      [req.user.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "User not found" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

app.post("/api/payments", auth, async (req, res, next) => {
  try {
    const plan = PLANS.find(p => p.id === req.body.planId);
    const utr = clean(req.body.utr, 80);
    const screenshot = validUrl(req.body.screenshotUrl);

    if (!plan || utr.length < 6) {
      return res.status(400).json({ error: "Plan aur valid UTR number daalein" });
    }

    const result = await pool.query(
      `INSERT INTO ag2_payments
       (user_id,plan_id,amount,utr,screenshot_url)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id,plan_id,amount,utr,status,created_at`,
      [req.user.id, plan.id, plan.amount, utr, screenshot]
    );

    res.json({ payment: result.rows[0], message: "Payment request submitted" });
  } catch (err) {
    next(err);
  }
});

app.get("/api/payments/mine", auth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id,plan_id,amount,utr,status,created_at
       FROM ag2_payments WHERE user_id=$1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ payments: result.rows });
  } catch (err) {
    next(err);
  }
});

app.get("/api/admin/payments", auth, adminOnly, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT p.id,p.plan_id,p.amount,p.utr,p.screenshot_url,p.status,
              p.created_at,u.name,u.email
       FROM ag2_payments p
       JOIN ag2_users u ON u.id=p.user_id
       ORDER BY p.created_at DESC`
    );
    res.json({ payments: result.rows });
  } catch (err) {
    next(err);
  }
});

app.post("/api/admin/payments/:id/review", auth, adminOnly, async (req, res, next) => {
  try {
    const status = req.body.status;
    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    const result = await pool.query(
      `UPDATE ag2_payments SET status=$1,reviewed_at=NOW()
       WHERE id=$2 AND status='pending'
       RETURNING id,status`,
      [status, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Pending payment not found" });
    }

    res.json({ payment: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

app.get("/api/pages", auth, paidOnly, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT * FROM ag2_pages WHERE user_id=$1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ pages: result.rows });
  } catch (err) {
    next(err);
  }
});

app.post("/api/pages", auth, paidOnly, async (req, res, next) => {
  try {
    const title = clean(req.body.title, 120);
    const headline = clean(req.body.headline, 180);

    if (!title || !headline) {
      return res.status(400).json({ error: "Title aur headline zaroori hain" });
    }

    const slug = slugify(title) + "-" + crypto.randomBytes(3).toString("hex");

    const result = await pool.query(
      `INSERT INTO ag2_pages
       (user_id,title,headline,description,image_url,button_text,
        button_url,pixel_id,slug,bg_color,text_color,button_color)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING *`,
      [
        req.user.id,
        title,
        headline,
        clean(req.body.description, 3000),
        validUrl(req.body.imageUrl),
        clean(req.body.buttonText, 60) || "Join Now",
        validUrl(req.body.buttonUrl),
        clean(req.body.pixelId, 30).replace(/\D/g, ""),
        slug,
        safeColor(req.body.bgColor, "#081225"),
        safeColor(req.body.textColor, "#ffffff"),
        safeColor(req.body.buttonColor, "#0891b2")
      ]
    );

    res.json({ page: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

app.put("/api/pages/:id", auth, paidOnly, async (req, res, next) => {
  try {
    const result = await pool.query(
      `UPDATE ag2_pages SET
       title=$1,headline=$2,description=$3,image_url=$4,
       button_text=$5,button_url=$6,pixel_id=$7,
       bg_color=$8,text_color=$9,button_color=$10,updated_at=NOW()
       WHERE id=$11 AND user_id=$12 RETURNING *`,
      [
        clean(req.body.title, 120),
        clean(req.body.headline, 180),
        clean(req.body.description, 3000),
        validUrl(req.body.imageUrl),
        clean(req.body.buttonText, 60) || "Join Now",
        validUrl(req.body.buttonUrl),
        clean(req.body.pixelId, 30).replace(/\D/g, ""),
        safeColor(req.body.bgColor, "#081225"),
        safeColor(req.body.textColor, "#ffffff"),
        safeColor(req.body.buttonColor, "#0891b2"),
        req.params.id,
        req.user.id
      ]
    );

    if (!result.rowCount) return res.status(404).json({ error: "Page not found" });
    res.json({ page: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

app.post("/api/pages/:id/publish", auth, paidOnly, async (req, res, next) => {
  try {
    const result = await pool.query(
      `UPDATE ag2_pages SET is_published=TRUE,updated_at=NOW()
       WHERE id=$1 AND user_id=$2 RETURNING *`,
      [req.params.id, req.user.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Page not found" });
    res.json({ page: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

app.post("/api/pages/:id/unpublish", auth, paidOnly, async (req, res, next) => {
  try {
    const result = await pool.query(
      `UPDATE ag2_pages SET is_published=FALSE,updated_at=NOW()
       WHERE id=$1 AND user_id=$2 RETURNING *`,
      [req.params.id, req.user.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Page not found" });
    res.json({ page: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

app.delete("/api/pages/:id", auth, paidOnly, async (req, res, next) => {
  try {
    const result = await pool.query(
      `DELETE FROM ag2_pages WHERE id=$1 AND user_id=$2 RETURNING id`,
      [req.params.id, req.user.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Page not found" });
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

app.get("/p/:slug", async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT * FROM ag2_pages WHERE slug=$1 AND is_published=TRUE`,
      [req.params.slug]
    );

    if (!result.rowCount) return res.status(404).send("Page not found or unpublished");

    const p = result.rows[0];
    const bgColor = safeColor(p.bg_color, "#081225");
    const textColor = safeColor(p.text_color, "#ffffff");
    const buttonColor = safeColor(p.button_color, "#0891b2");
    const pixel = /^\d+$/.test(p.pixel_id || "") ? p.pixel_id : "";

    const image = validUrl(p.image_url)
      ? `<img class="hero-img" src="${escapeHtml(p.image_url)}" alt="">`
      : "";

    const button = validUrl(p.button_url)
      ? `<a class="cta" href="${escapeHtml(p.button_url)}" target="_blank" rel="noopener">${escapeHtml(p.button_text)}</a>`
      : "";

    res.type("html").send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(p.title)}</title>
${pixel ? `<script>
!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){
n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;
s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}
(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
fbq('init','${pixel}');fbq('track','PageView');
</script>` : ""}
<style>
*{box-sizing:border-box}
body{margin:0;background:${bgColor};color:${textColor};font-family:Arial,sans-serif}
main{max-width:760px;margin:35px auto;padding:24px;text-align:center}
h1{font-size:34px;line-height:1.25}
p{font-size:18px;line-height:1.7;color:${textColor}}
.hero-img{width:100%;max-height:380px;object-fit:cover;border-radius:18px;margin:20px 0}
.cta{display:inline-block;margin-top:20px;background:${buttonColor};color:white;
padding:15px 28px;border-radius:10px;text-decoration:none;font-weight:bold}
</style>
</head>
<body><main>
<h1>${escapeHtml(p.headline)}</h1>
${image}
<p>${escapeHtml(p.description).replace(/\n/g, "<br>")}</p>
${button}
</main></body></html>`);
  } catch (err) {
    next(err);
  }
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Server error. Render Logs check karein." });
});

initDB()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log("ADS GROWTH server running on port " + PORT);
    });
  })
  .catch(err => {
    console.error("Database startup failed:", err);
    process.exit(1);
  });
