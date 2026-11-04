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
app.set("trust proxy", 1);

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
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
    : { rejectUnauthorized: false },
  connectionTimeoutMillis: 15000
});

pool.on("error", err => console.error("DB pool error:", err.message));

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
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

function safeUrl(value) {
  try {
    const u = new URL(String(value || ""));
    return ["http:", "https:"].includes(u.protocol) ? u.href : "";
  } catch {
    return "";
  }
}

function escapeHTML(value) {
  return String(value || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  }[c]));
}

function validColor(value, fallback) {
  return /^#[0-9a-fA-F]{6}$/.test(value || "") ? value : fallback;
}

function makeToken(user) {
  return jwt.sign({
    id: user.id,
    email: user.email,
    role: user.role
  }, JWT_SECRET, { expiresIn: "7d" });
}

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
      plan_id TEXT,
      amount INTEGER NOT NULL DEFAULT 0,
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

  // Add missing columns to older installations.
  await pool.query(`
    ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS name TEXT;
    ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS email TEXT;
    ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS password TEXT;
    ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'customer';
    ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS plan TEXT;
    ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS subscription_expires TIMESTAMPTZ;
    ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();

    ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS user_id INTEGER;
    ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS plan_id TEXT;
    ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS amount INTEGER DEFAULT 0;
    ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS utr TEXT;
    ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending';
    ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
    ALTER TABLE ag_payments ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS user_id INTEGER;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS slug TEXT;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS title TEXT;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS headline TEXT;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS description TEXT;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_text TEXT DEFAULT 'Learn More';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_url TEXT;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS image_url TEXT;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS pixel_id TEXT;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS design_template TEXT DEFAULT 'classic';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS image_width INTEGER DEFAULT 100;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS bg_color TEXT DEFAULT '#0b1224';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS text_color TEXT DEFAULT '#ffffff';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_color TEXT DEFAULT '#16a34a';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS published BOOLEAN DEFAULT FALSE;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

    ALTER TABLE ag_click_events ADD COLUMN IF NOT EXISTS page_id INTEGER;
    ALTER TABLE ag_click_events ADD COLUMN IF NOT EXISTS event_type TEXT;
    ALTER TABLE ag_click_events ADD COLUMN IF NOT EXISTS visitor_id TEXT;
    ALTER TABLE ag_click_events ADD COLUMN IF NOT EXISTS suspicious BOOLEAN DEFAULT FALSE;
    ALTER TABLE ag_click_events ADD COLUMN IF NOT EXISTS reason TEXT;
    ALTER TABLE ag_click_events ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
  `);

  // Copy old payment plan column if it exists.
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public'
          AND table_name='ag_payments'
          AND column_name='plan'
      ) THEN
        EXECUTE 'UPDATE public.ag_payments
                 SET plan_id = plan WHERE plan_id IS NULL';
      END IF;
    END $$;
  `);

  // Backfill old pages that may not have a slug.
  await pool.query(`
    UPDATE ag_pages
    SET slug = 'old-' || id::text
    WHERE slug IS NULL OR slug = '';
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS ag_users_email_lower_idx
      ON ag_users (LOWER(email));
    CREATE UNIQUE INDEX IF NOT EXISTS ag_payments_utr_unique_idx
      ON ag_payments (utr) WHERE utr IS NOT NULL AND utr <> '';
    CREATE UNIQUE INDEX IF NOT EXISTS ag_pages_slug_unique_idx
      ON ag_pages (slug) WHERE slug IS NOT NULL;
    CREATE INDEX IF NOT EXISTS ag_pages_user_idx ON ag_pages(user_id);
    CREATE INDEX IF NOT EXISTS ag_events_page_idx ON ag_click_events(page_id);
  `);

  // IMPORTANT: update existing admin password from Render environment.
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  const admin = await pool.query(
    "SELECT id FROM ag_users WHERE LOWER(email)=LOWER($1) LIMIT 1",
    [ADMIN_EMAIL]
  );

  if (!admin.rowCount) {
    await pool.query(
      `INSERT INTO ag_users(name,email,password,role)
       VALUES($1,$2,$3,'admin')`,
      ["Administrator", ADMIN_EMAIL, hash]
    );
    console.log("Admin account created.");
  } else {
    await pool.query(
      `UPDATE ag_users SET role='admin', password=$1
       WHERE LOWER(email)=LOWER($2)`,
      [hash, ADMIN_EMAIL]
    );
    console.log("Existing admin password updated.");
  }

  console.log("Database initialized.");
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) return res.status(401).json({ error: "Please login." });

    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query(
      `SELECT id,name,email,role,plan,subscription_expires
       FROM ag_users WHERE id=$1`,
      [decoded.id]
    );

    if (!result.rowCount) {
      return res.status(401).json({ error: "Account not found." });
    }

    req.user = result.rows[0];
    next();
  } catch {
    return res.status(401).json({ error: "Login expired. Please login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
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

function visitorHash(req) {
  return crypto.createHash("sha256")
    .update(String(req.ip || "unknown"))
    .digest("hex");
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch (err) {
    console.error("Health error:", err.message);
    res.status(500).json({ ok: false, error: "Database unavailable" });
  }
});

app.get("/api/config", (req, res) => res.json({ upiId: UPI_ID, plans }));
app.get("/api/plans", (req, res) => res.json({ plans }));
app.get("/api/payment-info", (req, res) => {
  res.json({ upiId: UPI_ID, payeeName: "ADS GROWTH AGENCY" });
});

// Register
app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        password.length < 8) {
      return res.status(400).json({
        error: "Enter name, valid email and password (minimum 8 characters)."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO ag_users(name,email,password)
       VALUES($1,$2,$3)
       RETURNING id,name,email,role,plan`,
      [name, email, hash]
    );

    res.status(201).json({
      token: makeToken(result.rows[0]),
      user: result.rows[0]
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "An account with this email already exists. Please log in."
      });
    }
    console.error("Register error:", err.message);
    res.status(500).json({ error: "Registration failed." });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!email || !password) {
      return res.status(400).json({ error: "Enter email and password." });
    }

    const result = await pool.query(
      `SELECT id,name,email,password,role,plan,subscription_expires
       FROM ag_users
       WHERE LOWER(TRIM(email))=LOWER(TRIM($1))
       LIMIT 1`,
      [email]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "No account found with this email. Please register first."
      });
    }

    const user = result.rows[0];
    let matches = false;
    try {
      matches = await bcrypt.compare(password, user.password || "");
    } catch (err) {
      console.error("Password check error:", err.message);
    }

    if (!matches) {
      return res.status(401).json({
        error: "Incorrect password. Please check your password."
      });
    }

    res.json({
      token: makeToken(user),
      user: {
        id: user.id, name: user.name, email: user.email,
        role: user.role, plan: user.plan,
        subscription_expires: user.subscription_expires
      }
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Login service error." });
  }
});

app.get("/api/me", auth, (req, res) => res.json({ user: req.user }));

// Submit UPI payment UTR. Admin must verify payment in bank/UPI app.
app.post("/api/payments", auth, async (req, res) => {
  try {
    const plan = plans.find(p => p.id === String(req.body.planId || ""));
    const utr = String(req.body.utr || "").trim();

    if (!plan) return res.status(400).json({ error: "Invalid plan." });
    if (utr.length < 6 || utr.length > 100) {
      return res.status(400).json({ error: "Enter a valid UTR number." });
    }

    const existing = await pool.query(
      "SELECT id FROM ag_payments WHERE utr=$1 LIMIT 1",
      [utr]
    );
    if (existing.rowCount) {
      return res.status(409).json({ error: "This UTR was already submitted." });
    }

    await pool.query(
      `INSERT INTO ag_payments(user_id,plan_id,amount,utr,status)
       VALUES($1,$2,$3,$4,'pending')`,
      [req.user.id, plan.id, plan.amount, utr]
    );

    res.json({ message: "Payment submitted for admin verification." });
  } catch (err) {
    console.error("Payment error:", err.message);
    res.status(500).json({ error: "Could not submit payment." });
  }
});

app.get("/api/payments/mine", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,plan_id,amount,utr,status,created_at,reviewed_at
       FROM ag_payments WHERE user_id=$1 ORDER BY id DESC`,
      [req.user.id]
    );
    res.json({ payments: result.rows });
  } catch (err) {
    console.error("My payments:", err.message);
    res.status(500).json({ error: "Could not load payments." });
  }
});

// Customer pages
app.get("/api/pages", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM ag_pages WHERE user_id=$1 ORDER BY id DESC",
      [req.user.id]
    );
    res.json({ pages: result.rows });
  } catch (err) {
    console.error("Pages:", err.message);
    res.status(500).json({ error: "Could not load pages." });
  }
});

app.post("/api/pages", auth, async (req, res) => {
  try {
    const count = await pool.query(
      "SELECT COUNT(*)::int AS total FROM ag_pages WHERE user_id=$1",
      [req.user.id]
    );
    if (count.rows[0].total >= pageLimit(req.user)) {
      return res.status(403).json({
        error: "Please get an active plan before creating a page."
      });
    }

    const b = req.body;
    const title = String(b.title || "").trim();
    if (!title) return res.status(400).json({ error: "Page title is required." });

    const slug = crypto.randomBytes(8).toString("hex");
    const result = await pool.query(
      `INSERT INTO ag_pages
       (user_id,slug,title,headline,description,button_text,button_url,
        image_url,pixel_id,design_template,image_width,bg_color,text_color,button_color)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
       RETURNING *`,
      [
        req.user.id, slug, title,
        String(b.headline || ""), String(b.description || ""),
        String(b.buttonText || "Learn More").slice(0, 80),
        safeUrl(b.buttonUrl), safeUrl(b.imageUrl),
        String(b.pixelId || "").replace(/[^\d]/g, "").slice(0, 30),
        String(b.designTemplate || "classic").slice(0, 50),
        Math.min(100, Math.max(20, Number(b.imageWidth) || 100)),
        validColor(b.bgColor, "#0b1224"),
        validColor(b.textColor, "#ffffff"),
        validColor(b.buttonColor, "#16a34a")
      ]
    );
    res.status(201).json({ page: result.rows[0] });
  } catch (err) {
    console.error("Create page:", err.message);
    res.status(500).json({ error: "Could not save page." });
  }
});

app.put("/api/pages/:id", auth, async (req, res) => {
  try {
    const b = req.body;
    const title = String(b.title || "").trim();
    if (!title) return res.status(400).json({ error: "Page title is required." });

    const result = await pool.query(
      `UPDATE ag_pages SET
       title=$1,headline=$2,description=$3,button_text=$4,
       button_url=$5,image_url=$6,pixel_id=$7,design_template=$8,
       image_width=$9,bg_color=$10,text_color=$11,button_color=$12,
       updated_at=NOW()
       WHERE id=$13 AND user_id=$14 RETURNING *`,
      [
        title, String(b.headline || ""), String(b.description || ""),
        String(b.buttonText || "Learn More").slice(0, 80),
        safeUrl(b.buttonUrl), safeUrl(b.imageUrl),
        String(b.pixelId || "").replace(/[^\d]/g, "").slice(0, 30),
        String(b.designTemplate || "classic").slice(0, 50),
        Math.min(100, Math.max(20, Number(b.imageWidth) || 100)),
        validColor(b.bgColor, "#0b1224"),
        validColor(b.textColor, "#ffffff"),
        validColor(b.buttonColor, "#16a34a"),
        req.params.id, req.user.id
      ]
    );

    if (!result.rowCount) return res.status(404).json({ error: "Page not found." });
    res.json({ page: result.rows[0] });
  } catch (err) {
    console.error("Update page:", err.message);
    res.status(500).json({ error: "Could not update page." });
  }
});

app.post("/api/pages/:id/publish", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE ag_pages SET published=NOT published,updated_at=NOW()
       WHERE id=$1 AND user_id=$2 RETURNING *`,
      [req.params.id, req.user.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Page not found." });

    const page = result.rows[0];
    res.json({
      page,
      url: page.published ? `/p/${page.slug}` : null
    });
  } catch (err) {
    console.error("Publish:", err.message);
    res.status(500).json({ error: "Could not publish page." });
  }
});

app.delete("/api/pages/:id", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2 RETURNING id",
      [req.params.id, req.user.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Page not found." });
    res.json({ success: true });
  } catch (err) {
    console.error("Delete page:", err.message);
    res.status(500).json({ error: "Could not delete page." });
  }
});

// Admin statistics
app.get("/api/admin/stats", auth, adminOnly, async (req, res) => {
  try {
    const [clients, events, pending, pages] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS total FROM ag_users WHERE role='customer'"),
      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE event_type='click' AND suspicious=FALSE)::int AS valid_clicks,
          COUNT(*) FILTER (WHERE event_type='visit')::int AS visits
        FROM ag_click_events
      `),
      pool.query("SELECT COUNT(*)::int AS total FROM ag_payments WHERE status='pending'"),
      pool.query("SELECT COUNT(*)::int AS total FROM ag_pages")
    ]);
          clients: clients.rows[0].total,
      validClicks: events.rows[0].valid_clicks,
      visits: events.rows[0].visits,
      pendingPayments: pending.rows[0].total,
      pages: pages.rows[0].total
    });
  } catch (err) {
    console.error("Admin stats:", err.message);
    res.status(500).json({ error: "Could not load admin statistics." });
  }
});

// Admin: list payment requests
app.get("/api/admin/payments", auth, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.id, p.user_id, p.plan_id, p.amount, p.utr,
             p.status, p.created_at, u.name, u.email
      FROM ag_payments p
      LEFT JOIN ag_users u ON u.id = p.user_id
      ORDER BY p.id DESC
    `);
    res.json({ payments: result.rows });
  } catch (err) {
    console.error("Admin payments:", err.message);
    res.status(500).json({ error: "Could not load payments." });
  }
});

// Admin: approve or reject payment
app.post("/api/admin/payments/:id/review", auth, adminOnly, async (req, res) => {
  const client = await pool.connect();

  try {
    const status = String(req.body.status || "").toLowerCase();
    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid payment status." });
    }

    await client.query("BEGIN");

    const paymentResult = await client.query(
      `SELECT * FROM ag_payments WHERE id=$1 FOR UPDATE`,
      [req.params.id]
    );

    if (!paymentResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Payment not found." });
    }

    const payment = paymentResult.rows[0];

    if (payment.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Payment already reviewed." });
    }

    await client.query(
      `UPDATE ag_payments
       SET status=$1, reviewed_at=NOW()
       WHERE id=$2`,
      [status, payment.id]
    );

    if (status === "approved") {
      const plan = plans.find(p => p.id === payment.plan_id);

      if (!plan) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Payment plan not found." });
      }

      await client.query(
        `UPDATE ag_users
         SET plan=$1, subscription_expires=NOW() + INTERVAL '30 days'
         WHERE id=$2`,
        [plan.id, payment.user_id]
      );
    }

    await client.query("COMMIT");
    res.json({ success: true, status });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Payment review:", err.message);
    res.status(500).json({ error: "Could not review payment." });
  } finally {
    client.release();
  }
});

// Admin: event report
app.get("/api/admin/clicks", auth, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT e.id, e.page_id, e.event_type, e.visitor_id,
             e.suspicious, e.reason, e.created_at,
             p.title, p.slug
      FROM ag_click_events e
      LEFT JOIN ag_pages p ON p.id=e.page_id
      ORDER BY e.id DESC
      LIMIT 500
    `);
    res.json({ events: result.rows });
  } catch (err) {
    console.error("Admin events:", err.message);
    res.status(500).json({ error: "Could not load events." });
  }
});

// Public landing page
app.get("/p/:slug", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM ag_pages
       WHERE slug=$1 AND published=TRUE
       LIMIT 1`,
      [req.params.slug]
    );

    if (!result.rowCount) {
      return res.status(404).send("Landing page not found.");
    }

    const page = result.rows[0];
    const visitor = visitorHash(req);

    await pool.query(
      `INSERT INTO ag_click_events(page_id,event_type,visitor_id)
       VALUES($1,'visit',$2)`,
      [page.id, visitor]
    );

    const pixel = String(page.pixel_id || "").replace(/[^\d]/g, "");
    const buttonUrl = safeUrl(page.button_url);
    const imageUrl = safeUrl(page.image_url);

    res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHTML(page.title)}</title>
${pixel ? `
<script>
!function(f,b,e,v,n,t,s){
if(f.fbq)return;n=f.fbq=function(){n.callMethod?
n.callMethod.apply(n,arguments):n.queue.push(arguments)};
if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;
s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)
}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
fbq('init','${pixel}');fbq('track','PageView');
</script>` : ""}
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;
justify-content:center;padding:24px;background:${validColor(page.bg_color, "#0b1224")};
color:${validColor(page.text_color, "#ffffff")};font-family:Arial,sans-serif}
main{width:100%;max-width:720px;text-align:center}
h1{font-size:clamp(28px,6vw,46px)}
p{font-size:18px;line-height:1.6}
img{width:${Math.min(100,Math.max(20,Number(page.image_width)||100))}%;
max-height:480px;object-fit:cover;border-radius:16px}
a{display:inline-block;margin-top:20px;padding:15px 28px;border-radius:10px;
background:${validColor(page.button_color, "#16a34a")};
color:#fff;text-decoration:none;font-weight:bold}
</style>
</head>
<body>
<main>
<h1>${escapeHTML(page.headline || page.title)}</h1>
${imageUrl ? `<img src="${escapeHTML(imageUrl)}" alt="">` : ""}
<p>${escapeHTML(page.description || "")}</p>
${buttonUrl ? `<a href="${escapeHTML(buttonUrl)}" target="_blank"
rel="noopener noreferrer">${escapeHTML(page.button_text || "Learn More")}</a>` : ""}
</main>
</body>
</html>`);
  } catch (err) {
    console.error("Public page:", err.message);
    res.status(500).send("Could not load this landing page.");
  }
});

// Record a real CTA click. The public page above records visits only.
app.post("/api/events/click/:slug", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id FROM ag_pages WHERE slug=$1 AND published=TRUE",
      [req.params.slug]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Page not found." });
    }

    await pool.query(
      `INSERT INTO ag_click_events(page_id,event_type,visitor_id)
       VALUES($1,'click',$2)`,
      [result.rows[0].id, visitorHash(req)]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Click event:", err.message);
    res.status(500).json({ error: "Could not record click." });
  }
});

// Home page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start server after database initialization
async function startServer() {
  try {
    await initDB();
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`ADS GROWTH AGENCY running on port ${PORT}`);
    });
  } catch (err) {
    console.error("Startup failed:", err);
    process.exit(1);
  }
}

startServer();
