
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const UPI_ID = process.env.UPI_ID || "sainiatul041@okhdfcbank";

if (!DATABASE_URL || !JWT_SECRET) {
  console.error("DATABASE_URL and JWT_SECRET are required.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === "false"
    ? false
    : { rejectUnauthorized: false }
});

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const PLANS = {
  starter: { name: "Starter", amount: 499, label: "All Click" },
  growth: { name: "Growth", amount: 999, label: "50% Click" },
  pro: { name: "Pro", amount: 1499, label: "100% Click" }
};

const emailOf = value => String(value || "").trim().toLowerCase();

function slugify(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 50) || "landing-page";
}

function validPixel(value) {
  return !value || /^\d{5,25}$/.test(String(value).trim());
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) throw new Error();
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Please login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }
  next();
}

async function hasPaid(userId) {
  const result = await pool.query(
    "SELECT id FROM ag_payments WHERE user_id=$1 AND status='approved' LIMIT 1",
    [userId]
  );
  return result.rowCount > 0;
}

function paidOnly(req, res, next) {
  hasPaid(req.user.id)
    .then(ok => {
      if (!ok) {
        return res.status(403).json({
          error: "Payment approval required before using Page Builder."
        });
      }
      next();
    })
    .catch(() => {
      res.status(500).json({ error: "Payment verification failed." });
    });
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_pages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES ag_users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      headline TEXT DEFAULT '',
      description TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      button_text TEXT DEFAULT 'Join Now',
      button_url TEXT DEFAULT '',
      pixel_id TEXT DEFAULT '',
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES ag_users(id) ON DELETE CASCADE,
      plan TEXT NOT NULL,
      amount INTEGER NOT NULL,
      utr TEXT NOT NULL,
      screenshot_url TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      admin_note TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      approved_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS ag_payments_user_status_idx
    ON ag_payments(user_id, status);
  `);

  await pool.query(`
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS headline TEXT DEFAULT '';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS image_url TEXT DEFAULT '';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_text TEXT DEFAULT 'Join Now';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_url TEXT DEFAULT '';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS pixel_id TEXT DEFAULT '';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

    ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS screenshot_url TEXT DEFAULT '';
    ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS admin_note TEXT DEFAULT '';
    ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
  `);

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const existing = await pool.query(
      "SELECT id FROM ag_users WHERE email=$1",
      [ADMIN_EMAIL]
    );

    if (!existing.rowCount) {
      const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);

      await pool.query(
        `INSERT INTO ag_users(name,email,password_hash,role)
         VALUES($1,$2,$3,'admin')`,
        ["Administrator", ADMIN_EMAIL, hash]
      );
    } else {
      await pool.query(
        "UPDATE ag_users SET role='admin' WHERE email=$1",
        [ADMIN_EMAIL]
      );
    }
  }
}

app.get("/api/config", (req, res) => {
  res.json({ upiId: UPI_ID, plans: PLANS });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim().slice(0, 80);
    const email = emailOf(req.body.email);
    const password = String(req.body.password || "");

    if (
      !name ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 8
    ) {
      return res.status(400).json({
        error: "Enter name, valid email and password of at least 8 characters."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO ag_users(name,email,password_hash,role)
       VALUES($1,$2,$3,'user')
       RETURNING id,name,email,role`,
      [name, email, hash]
    );

    res.json({
      token: signToken(result.rows[0]),
      user: result.rows[0]
    });
  } catch (error) {
    res.status(400).json({
      error: error.code === "23505"
        ? "Email already registered."
        : "Registration failed."
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM ag_users WHERE email=$1",
      [emailOf(req.body.email)]
    );

    if (
      !result.rowCount ||
      !(await bcrypt.compare(
        String(req.body.password || ""),
        result.rows[0].password_hash
      ))
    ) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const user = result.rows[0];

    res.json({
      token: signToken(user),
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch {
    res.status(500).json({ error: "Login failed." });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT id,name,email,role FROM ag_users WHERE id=$1",
    [req.user.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "Account not found." });
  }

  res.json({
    user: result.rows[0],
    paid: await hasPaid(req.user.id)
  });
});

app.get("/api/payments", auth, async (req, res) => {
  const result = await pool.query(
    `SELECT id,plan,amount,utr,screenshot_url,status,
     admin_note,created_at,approved_at
     FROM ag_payments WHERE user_id=$1 ORDER BY id DESC`,
    [req.user.id]
  );

  res.json(result.rows);
});

app.post("/api/payments", auth, async (req, res) => {
  try {
    const plan = String(req.body.plan || "");
    const utr = String(req.body.utr || "").trim().slice(0, 100);
    const screenshot = String(req.body.screenshot_url || "").trim().slice(0, 1000);

    if (!PLANS[plan]) {
      return res.status(400).json({ error: "Select a valid plan." });
    }

    if (utr.length < 6) {
      return res.status(400).json({ error: "Enter your UTR number." });
    }

    if (screenshot && !/^https:\/\/\S+$/i.test(screenshot)) {
      return res.status(400).json({
        error: "Screenshot link must be a valid HTTPS URL."
      });
    }

    const pending = await pool.query(
      "SELECT id FROM ag_payments WHERE user_id=$1 AND status='pending'",
      [req.user.id]
    );

    if (pending.rowCount) {
      return res.status(409).json({
        error: "Your previous payment is still waiting for approval."
      });
    }

    const selected = PLANS[plan];

    const result = await pool.query(
      `INSERT INTO ag_payments(user_id,plan,amount,utr,screenshot_url)
       VALUES($1,$2,$3,$4,$5) RETURNING id,status`,
      [req.user.id, plan, selected.amount, utr, screenshot]
    );

    res.json({
      message: "Payment request submitted. Wait for admin approval.",
      payment: result.rows[0]
    });
  } catch {
    res.status(500).json({ error: "Could not submit payment." });
  }
});

app.get("/api/pages", auth, paidOnly, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM ag_pages WHERE user_id=$1 ORDER BY id DESC",
    [req.user.id]
  );
  res.json(result.rows);
});

app.post("/api/pages", auth, paidOnly, async (req, res) => {
  try {
    const b = req.body || {};
    const title = String(b.title || "").trim().slice(0, 100);

    if (!title) {
      return res.status(400).json({ error: "Page title is required." });
    }

    if (!validPixel(b.pixel_id)) {
      return res.status(400).json({
        error: "Meta Pixel ID must contain 5–25 digits."
      });
    }

    const base = slugify(title);
    let slug = base;
    let number = 2;

    while (
      (await pool.query("SELECT id FROM ag_pages WHERE slug=$1", [slug])).rowCount
    ) {
      slug = base + "-" + number++;
    }

    const result = await pool.query(
      `INSERT INTO ag_pages
       (user_id,title,slug,headline,description,image_url,
        button_text,button_url,pixel_id)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [
        req.user.id,
        title,
        slug,
        String(b.headline || "").slice(0, 180),
        String(b.description || "").slice(0, 2000),
        String(b.image_url || "").slice(0, 1000),
        String(b.button_text || "Join Now").slice(0, 50),
        String(b.button_url || "").slice(0, 1000),
        String(b.pixel_id || "").trim()
      ]
    );

    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Could not create page." });
  }
});

app.put("/api/pages/:id", auth, paidOnly, async (req, res) => {
  try {
    const b = req.body || {};

    if (!validPixel(b.pixel_id)) {
      return res.status(400).json({
        error: "Meta Pixel ID must contain 5–25 digits."
      });
    }

    const result = await pool.query(
      `UPDATE ag_pages SET
       title=$1,headline=$2,description=$3,image_url=$4,
       button_text=$5,button_url=$6,pixel_id=$7,updated_at=NOW()
       WHERE id=$8 AND user_id=$9 RETURNING *`,
      [
        String(b.title || "").trim().slice(0, 100),
        String(b.headline || "").slice(0, 180),
        String(b.description || "").slice(0, 2000),
        String(b.image_url || "").slice(0, 1000),
        String(b.button_text || "Join Now").slice(0, 50),
        String(b.button_url || "").slice(0, 1000),
        String(b.pixel_id || "").trim(),
        req.params.id,
        req.user.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Page not found." });
    }

    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Could not update page." });
  }
});

app.post("/api/pages/:id/publish", auth, paidOnly, async (req, res) => {
  const result = await pool.query(
    `UPDATE ag_pages SET published=NOT published,updated_at=NOW()
     WHERE id=$1 AND user_id=$2 RETURNING *`,
    [req.params.id, req.user.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "Page not found." });
  }

  res.json(result.rows[0]);
});

app.delete("/api/pages/:id", auth, paidOnly, async (req, res) => {
  const result = await pool.query(
    "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2",
    [req.params.id, req.user.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "Page not found." });
  }

  res.json({ message: "Page deleted." });
});

app.get("/api/admin/stats", auth, adminOnly, async (req, res) => {
  const [users, pages, pending, approved] = await Promise.all([
    pool.query("SELECT COUNT(*)::int count FROM ag_users"),
    pool.query("SELECT COUNT(*)::int count FROM ag_pages"),
    pool.query("SELECT COUNT(*)::int count FROM ag_payments WHERE status='pending'"),
    pool.query("SELECT COALESCE(SUM(amount),0)::int total FROM ag_payments WHERE status='approved'")
  ]);

  res.json({
    users: users.rows[0].count,
    pages: pages.rows[0].count,
    pending: pending.rows[0].count,
    approvedAmount: approved.rows[0].total
  });
});

app.get("/api/admin/payments", auth, adminOnly, async (req, res) => {
  const result = await pool.query(
    `SELECT p.*,u.name,u.email
     FROM ag_payments p
     JOIN ag_users u ON u.id=p.user_id
     ORDER BY CASE WHEN p.status='pending' THEN 0 ELSE 1 END,p.id DESC`
  );

  res.json(result.rows);
});

app.post("/api/admin/payments/:id/status", auth, adminOnly, async (req, res) => {
  const status = String(req.body.status || "");

  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid payment status." });
  }

  const result = await pool.query(
    `UPDATE ag_payments
     SET status=$1,admin_note=$2,
     approved_at=CASE WHEN $1='approved' THEN NOW() ELSE NULL END
     WHERE id=$3 RETURNING *`,
    [status, String(req.body.admin_note || "").slice(0, 500), req.params.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "Payment not found." });
  }

  res.json(result.rows[0]);
});

app.get("/p/:slug", async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM ag_pages WHERE slug=$1 AND published=true",
    [req.params.slug]
  );

  if (!result.rowCount) {
    return res.status(404).send("Landing page not found.");
  }

  const page = result.rows[0];

  const esc = value => String(value || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));

  const pixel = /^\d{5,25}$/.test(page.pixel_id || "")
    ? `<script>
      !function(f,b,e,v,n,t,s){
        if(f.fbq)return;n=f.fbq=function(){
        n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
        if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
        n.queue=[];t=b.createElement(e);t.async=!0;
        t.src=v;s=b.getElementsByTagName(e)[0];
        s.parentNode.insertBefore(t,s)
      }(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
      fbq('init','${page.pixel_id}');
      fbq('track','PageView');
    </script>
    <noscript><img height="1" width="1" style="display:none"
    src="https://www.facebook.com/tr?id=${page.pixel_id}&ev=PageView&noscript=1"/></noscript>`
    : "";

  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(page.title)}</title>
${pixel}
<style>
*{box-sizing:border-box}
body{margin:0;background:#081226;color:#fff;font-family:Arial,sans-serif}
.wrap{max-width:680px;margin:35px auto;padding:24px;text-align:center}
.panel{background:#111e36;border:1px solid #263958;border-radius:18px;padding:24px}
h1{color:#45df91}
p{line-height:1.6;color:#d5deed}
.hero{width:100%;max-height:360px;object-fit:cover;border-radius:14px;margin:16px 0}
.cta{display:inline-block;background:#08a66a;color:#fff;padding:15px 28px;border-radius:10px;text-decoration:none;font-weight:bold;margin-top:18px}
</style>
</head>
<body>
<main class="wrap">
<section class="panel">
<h1>${esc(page.headline || page.title)}</h1>
${page.image_url ? `<img class="hero" src="${esc(page.image_url)}" alt="">` : ""}
<p>${esc(page.description)}</p>
${page.button_url ? `<a class="cta" href="${esc(page.button_url)}" target="_blank" rel="noopener">${esc(page.button_text || "Join Now")}</a>` : ""}
</section>
</main>
</body>
</html>`);
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDB()
  .then(() => {
    app.listen(PORT, () => console.log("ADS GROWTH running on " + PORT));
  })
  .catch(error => {
    console.error("Database startup failed:", error.message);
    process.exit(1);
  });
  
