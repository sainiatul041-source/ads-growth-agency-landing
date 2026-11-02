const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const UPI_ID = process.env.UPI_ID || "sainiatul041@okhdfcbank";

if (!DATABASE_URL || ! JWT_SECRET) {
  console.error("Missing DATABASE_URL or JWT_SECRET.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === "false" ? false : { rejectUnauthorized: false }
});

const plans = {
  starter: { name: "Starter", amount: 499, label: "All Click" },
  growth: { name: "Growth", amount: 999, label: "50% Click" },
  pro: { name: "Pro", amount: 1499, label: "100% Click" }
};

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id BIGSERIAL PRIMARY KEY,
      full_name TEXT NOT NULL DEFAULT '',
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT,
      plan TEXT NOT NULL DEFAULT 'starter',
      amount NUMERIC(10,2) NOT NULL DEFAULT 0,
      utr TEXT NOT NULL DEFAULT '',
      screenshot_url TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ag_pages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT,
      title TEXT NOT NULL DEFAULT '',
      headline TEXT NOT NULL DEFAULT '',
      description TEXT NOT NULL DEFAULT '',
      image_url TEXT NOT NULL DEFAULT '',
      button_text TEXT NOT NULL DEFAULT 'Learn More',
      button_url TEXT NOT NULL DEFAULT '#',
      pixel_id TEXT NOT NULL DEFAULT '',
      slug TEXT UNIQUE,
      is_published BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const migrations = [
    "ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS full_name TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS email TEXT",
    "ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS password_hash TEXT",
    "ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'",
    "ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",

    "ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS user_id BIGINT",
    "ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'starter'",
    "ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS amount NUMERIC(10,2) NOT NULL DEFAULT 0",
    "ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS utr TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS screenshot_url TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'",
    "ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
    "ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ",

    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS user_id BIGINT",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS headline TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS image_url TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_text TEXT NOT NULL DEFAULT 'Learn More'",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_url TEXT NOT NULL DEFAULT '#'",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS pixel_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS slug TEXT",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS is_published BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
    "ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
  ];

  for (const sql of migrations) await pool.query(sql);

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const existing = await pool.query(
      "SELECT id FROM ag_users WHERE LOWER(email)=LOWER($1)",
      [ADMIN_EMAIL]
    );

    if (existing.rowCount) {
      await pool.query(
        "UPDATE ag_users SET role='admin' WHERE LOWER(email)=LOWER($1)",
        [ADMIN_EMAIL]
      );
    } else {
      const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
      await pool.query(
        "INSERT INTO ag_users(full_name,email,password_hash,role) VALUES($1,$2,$3,'admin')",
        ["Administrator", ADMIN_EMAIL, hash]
      );
    }
  }
}

function signToken(user) {
  return jwt.sign(
    { id: String(user.id), email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "14d" }
  );
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";

    if (!token) {
      return res.status(401).json({ error: "Please login first." });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query(
      "SELECT id,full_name,email,role FROM ag_users WHERE id=$1",
      [decoded.id]
    );

    if (!result.rowCount) {
      return res.status(401).json({ error: "Account not found." });
    }

    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: "Session expired. Please login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin only." });
  }
  next();
}

async function paidOnly(req, res, next) {
  if (req.user.role === "admin") return next();

  try {
    const result = await pool.query(
      "SELECT id FROM ag_payments WHERE user_id=$1 AND status='approved' LIMIT 1",
      [req.user.id]
    );

    if (!result.rowCount) {
      return res.status(403).json({
        error: "Payment approval is required before using the Page Builder."
      });
    }

    next();
  } catch (err) {
    next(err);
  }
}

function makeSlug() {
  return crypto.randomBytes(6).toString("hex");
}

function cleanText(value, max = 5000) {
  return String(value ?? "").trim().slice(0, max);
}

function validHttpUrl(value, allowBlank = true) {
  if (!value && allowBlank) return true;
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

app.get("/api/config", (req, res) => {
  res.json({ upiId: UPI_ID, plans });
});

app.post("/api/register", async (req, res, next) => {
  try {
    const fullName = cleanText(req.body.fullName, 120);
    const email = cleanText(req.body.email, 200).toLowerCase();
    const password = String(req.body.password || "");

    if (!fullName || !email.includes("@") || password.length < 8) {
      return res.status(400).json({
        error: "Name, valid email and password (minimum 8 characters) are required."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO ag_users(full_name,email,password_hash,role) VALUES($1,$2,$3,'user') RETURNING id,full_name,email,role",
      [fullName, email, hash]
    );

    const user = result.rows[0];
    res.json({ token: signToken(user), user });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "This email is already registered. Please login."
      });
    }
    next(err);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const email = cleanText(req.body.email, 200).toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM ag_users WHERE LOWER(email)=LOWER($1)",
      [email]
    );

    if (
      !result.rowCount ||
      !(await bcrypt.compare(password, result.rows[0].password_hash))
    ) {
      return res.status(401).json({ error: "Incorrect email or password." });
    }

    const user = result.rows[0];
    res.json({
      token: signToken(user),
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    next(err);
  }
});

app.get("/api/me", auth, async (req, res, next) => {
  try {
    const paid = req.user.role === "admin" ||
      (await pool.query(
        "SELECT id FROM ag_payments WHERE user_id=$1 AND status='approved' LIMIT 1",
        [req.user.id]
      )).rowCount > 0;

    res.json({ user: req.user, paid });
  } catch (err) {
    next(err);
  }
});

app.get("/api/payments", auth, async (req, res, next) => {
  try {
    const result = await pool.query(
      "SELECT id,plan,amount,utr,screenshot_url,status,created_at,reviewed_at FROM ag_payments WHERE user_id=$1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

app.post("/api/payments", auth, async (req, res, next) => {
  try {
    if (req.user.role === "admin") {
      return res.status(400).json({
        error: "Admin account does not need payment approval."
      });
    }

    const planKey = cleanText(req.body.plan, 30).toLowerCase();
    const plan = plans[planKey];
    const utr = cleanText(req.body.utr, 100);
    const screenshotUrl = cleanText(req.body.screenshotUrl, 1000);

    if (!plan) {
      return res.status(400).json({ error: "Please select a valid plan." });
    }
    if (utr.length < 6) {
      return res.status(400).json({
        error: "Please enter your UTR / transaction reference."
      });
    }
    if (!validHttpUrl(screenshotUrl)) {
      return res.status(400).json({
        error: "Screenshot URL must be a valid http/https link."
      });
    }

    const pending = await pool.query(
      "SELECT id FROM ag_payments WHERE user_id=$1 AND status='pending' LIMIT 1",
      [req.user.id]
    );

    if (pending.rowCount) {
      return res.status(409).json({
        error: "You already have a payment waiting for admin review."
      });
    }

    const result = await pool.query(
      "INSERT INTO ag_payments(user_id,plan,amount,utr,screenshot_url,status) VALUES($1,$2,$3,$4,$5,'pending') RETURNING id",
      [req.user.id, planKey, plan.amount, utr, screenshotUrl]
    );

    res.json({
      message: "Payment submitted. Admin will verify it.",
      id: result.rows[0].id
    });
  } catch (err) {
    next(err);
  }
});

app.get("/api/pages", auth, paidOnly, async (req, res, next) => {
  try {
    const result = req.user.role === "admin"
      ? await pool.query("SELECT * FROM ag_pages ORDER BY created_at DESC")
      : await pool.query(
          "SELECT * FROM ag_pages WHERE user_id=$1 ORDER BY created_at DESC",
          [req.user.id]
        );

    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

app.post("/api/pages", auth, paidOnly, async (req, res, next) => {
  try {
    const title = cleanText(req.body.title, 160);
    const headline = cleanText(req.body.headline, 250);
    const description = cleanText(req.body.description, 5000);
    const imageUrl = cleanText(req.body.imageUrl, 1000);
    const buttonText = cleanText(req.body.buttonText, 80) || "Learn More";
    const buttonUrl = cleanText(req.body.buttonUrl, 1000) || "#";
    const pixelId = cleanText(req.body.pixelId, 40);

    if (!title || !headline) {
      return res.status(400).json({
        error: "Page title and headline are required."
      });
    }

    if (!validHttpUrl(imageUrl) ||
        (!validHttpUrl(buttonUrl, false) && buttonUrl !== "#")) {
      return res.status(400).json({
        error: "Image and button links must be valid http/https URLs."
      });
    }

    const result = await pool.query(
      `INSERT INTO ag_pages
       (user_id,title,headline,description,image_url,button_text,button_url,pixel_id,slug)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [
        req.user.id, title, headline, description, imageUrl,
        buttonText, buttonUrl, pixelId, makeSlug()
      ]
    );

    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

app.put("/api/pages/:id", auth, paidOnly, async (req, res, next) => {
  try {
    const title = cleanText(req.body.title, 160);
    const headline = cleanText(req.body.headline, 250);
    const description = cleanText(req.body.description, 5000);
    const imageUrl = cleanText(req.body.imageUrl, 1000);
    const buttonText = cleanText(req.body.buttonText, 80) || "Learn More";
    const buttonUrl = cleanText(req.body.buttonUrl, 1000) || "#";
    const pixelId = cleanText(req.body.pixelId, 40);

    if (!title || !headline) {
      return res.status(400).json({
        error: "Page title and headline are required."
      });
    }

    if (!validHttpUrl(imageUrl) ||
        (!validHttpUrl(buttonUrl, false) && buttonUrl !== "#")) {
      return res.status(400).json({
        error: "Image and button links must be valid http/https URLs."
      });
    }

    const values = [
      title, headline, description, imageUrl,
      buttonText, buttonUrl, pixelId, req.params.id
    ];

    const result = req.user.role === "admin"
      ? await pool.query(
          `UPDATE ag_pages SET title=$1,headline=$2,description=$3,
           image_url=$4,button_text=$5,button_url=$6,pixel_id=$7,
           updated_at=NOW() WHERE id=$8 RETURNING *`,
          values
        )
      : await pool.query(
          `UPDATE ag_pages SET title=$1,headline=$2,description=$3,
           image_url=$4,button_text=$5,button_url=$6,pixel_id=$7,
           updated_at=NOW() WHERE id=$8 AND user_id=$9 RETURNING *`,
          [...values, req.user.id]
        );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Page not found." });
    }

    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

app.post("/api/pages/:id/publish", auth, paidOnly, async (req, res, next) => {
  try {
    const published = Boolean(req.body.published);

    const result = req.user.role === "admin"
      ? await pool.query(
          "UPDATE ag_pages SET is_published=$1,updated_at=NOW() WHERE id=$2 RETURNING *",
          [published, req.params.id]
        )
      : await pool.query(
          "UPDATE ag_pages SET is_published=$1,updated_at=NOW() WHERE id=$2 AND user_id=$3 RETURNING *",
          [published, req.params.id, req.user.id]
        );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Page not found." });
    }

    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

app.delete("/api/pages/:id", auth, paidOnly, async (req, res, next) => {
  try {
    const result = req.user.role === "admin"
      ? await pool.query(
          "DELETE FROM ag_pages WHERE id=$1 RETURNING id",
          [req.params.id]
        )
      : await pool.query(
          "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2 RETURNING id",
          [req.params.id, req.user.id]
        );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Page not found." });
    }

    res.json({ message: "Page deleted." });
  } catch (err) {
    next(err);
  }
});

app.get("/api/admin/stats", auth, adminOnly, async (req, res, next) => {
  try {
    const [users, payments, pages] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS count FROM ag_users"),
      pool.query("SELECT COUNT(*)::int AS count FROM ag_payments WHERE status='pending'"),
      pool.query("SELECT COUNT(*)::int AS count FROM ag_pages")
    ]);

    res.json({
      users: users.rows[0].count,
      pendingPayments: payments.rows[0].count,
      pages: pages.rows[0].count
    });
  } catch (err) {
    next(err);
  }
});

app.get("/api/admin/payments", auth, adminOnly, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT p.id,p.plan,p.amount,p.utr,p.screenshot_url,p.status,
       p.created_at,u.full_name,u.email
       FROM ag_payments p LEFT JOIN ag_users u ON u.id=p.user_id
       ORDER BY p.created_at DESC LIMIT 200`
    );

    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

app.post("/api/admin/payments/:id/status", auth, adminOnly, async (req, res, next) => {
  try {
    const status = cleanText(req.body.status, 20);

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid payment status." });
    }

    const result = await pool.query(
      "UPDATE ag_payments SET status=$1,reviewed_at=NOW() WHERE id=$2 RETURNING id,status",
      [status, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Payment not found." });
    }

    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
}

app.get("/p/:slug", async (req, res, next) => {
  try {
    const result = await pool.query(
      "SELECT * FROM ag_pages WHERE slug=$1 AND is_published=TRUE",
      [req.params.slug]
    );

    if (!result.rowCount) {
      return res.status(404).send("Page not found or not published.");
    }

    const p = result.rows[0];
    const pixel = /^\d+$/.test(p.pixel_id || "") ? p.pixel_id : "";

    const image = p.image_url
      ? `<img class="hero-img" src="${escapeHtml(p.image_url)}" alt="">`
      : "";

    const button = p.button_url && p.button_url !== "#"
      ? `<a class="cta" href="${escapeHtml(p.button_url)}" target="_blank" rel="noopener">${escapeHtml(p.button_text)}</a>`
      : "";

    res.type("html").send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(p.title)}</title>
${pixel ? `<script>
!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){
n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];
t=b.createElement(e);t.async=!0;t.src=v;
s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}
(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
fbq('init','${pixel}');fbq('track','PageView');
</script>
<noscript><img height="1" width="1" style="display:none"
src="https://www.facebook.com/tr?id=${pixel}&ev=PageView&noscript=1"/></noscript>` : ""}
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1224;color:#fff;font-family:Arial,sans-serif}
.wrap{max-width:760px;margin:40px auto;padding:28px;text-align:center}
.hero-img{max-width:100%;max-height:380px;object-fit:cover;border-radius:18px;margin:20px 0}
h1{font-size:clamp(30px,6vw,48px)}
p{font-size:19px;line-height:1.6;color:#cbd5e1}
.cta{display:inline-block;background:#0891b2;color:white;padding:15px 28px;border-radius:10px;text-decoration:none;font-weight:bold;margin-top:16px}
</style>
</head>
<body>
<main class="wrap">
<h1>${escapeHtml(p.headline)}</h1>
${image}
<p>${escapeHtml(p.description).replace(/\n/g, "<br>")}</p>
${button}
</main>
</body>
</html>`);
  } catch (err) {
    next(err);
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index
