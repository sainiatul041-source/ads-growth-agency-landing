// ADS GROWTH AGENCY PRO
// Complete Node.js + Express + PostgreSQL backend

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");

const rateLimitModule = require("express-rate-limit");
const rateLimit = rateLimitModule.rateLimit || rateLimitModule;

const app = express();
app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const RECEIVE_ADDRESS = (process.env.USDT_TRC20_ADDRESS || "").trim();

const PLANS = {
  basic: { name: "Basic", price: 5, days: 30 },
  prime_pro: { name: "Prime & Pro", price: 12, days: 30 },
  basic_prime: { name: "Basic & Prime", price: 15, days: 30 }
};

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
  process.exit(1);
}

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === "true"
    ? { rejectUnauthorized: false }
    : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

function cleanText(value, max = 500) {
  return String(value || "").trim().slice(0, max);
}

function makeSlug(value) {
  const base = cleanText(value, 70)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

  return (base || "my-page") + "-" +
    crypto.randomBytes(3).toString("hex");
}

function escapeHtml(value) {
  return String(value || "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
}

function makeToken(user) {
  return jwt.sign({
    id: user.id,
    email: user.email,
    role: user.role
  }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({ error: "Please log in first." });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({ error: "Session expired. Log in again." });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }
  next();
}

// DATABASE SETUP
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL DEFAULT '',
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL DEFAULT '',
      role TEXT NOT NULL DEFAULT 'user',
      plan TEXT,
      subscription_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user',
      ADD COLUMN IF NOT EXISTS plan TEXT,
      ADD COLUMN IF NOT EXISTS subscription_expires TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT '',
      headline TEXT NOT NULL DEFAULT '',
      description TEXT NOT NULL DEFAULT '',
      image_url TEXT NOT NULL DEFAULT '',
      button_text TEXT NOT NULL DEFAULT 'Join Now',
      button_url TEXT NOT NULL DEFAULT '',
      whatsapp TEXT NOT NULL DEFAULT '',
      pixel_id TEXT NOT NULL DEFAULT '',
      background_color TEXT NOT NULL DEFAULT '#0f172a',
      heading_color TEXT NOT NULL DEFAULT '#22c55e',
      button_color TEXT NOT NULL DEFAULT '#0088cc',
      image_size TEXT NOT NULL DEFAULT 'medium',
      slug TEXT,
      published BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE pages
      ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS headline TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS image_url TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS button_text TEXT NOT NULL DEFAULT 'Join Now',
      ADD COLUMN IF NOT EXISTS button_url TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS whatsapp TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS pixel_id TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS background_color TEXT NOT NULL DEFAULT '#0f172a',
      ADD COLUMN IF NOT EXISTS heading_color TEXT NOT NULL DEFAULT '#22c55e',
      ADD COLUMN IF NOT EXISTS button_color TEXT NOT NULL DEFAULT '#0088cc',
      ADD COLUMN IF NOT EXISTS image_size TEXT NOT NULL DEFAULT 'medium',
      ADD COLUMN IF NOT EXISTS slug TEXT,
      ADD COLUMN IF NOT EXISTS published BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  await pool.query(`
    UPDATE pages
    SET slug = 'old-page-' || id
    WHERE slug IS NULL OR slug = ''
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS pages_slug_unique_idx
    ON pages(slug)
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      page_id INTEGER REFERENCES pages(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      plan_key TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      network TEXT NOT NULL DEFAULT 'TRC20',
      token TEXT NOT NULL DEFAULT 'USDT',
      tx_hash TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      admin_note TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS payments_user_id_idx
    ON payments(user_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS payments_status_idx
    ON payments(status)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS pages_user_id_idx
    ON pages(user_id)
  `);

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const hashed = await bcrypt.hash(ADMIN_PASSWORD, 12);

    await pool.query(`
      INSERT INTO users (name, email, password_hash, role)
      VALUES ('Admin', $1, $2, 'admin')
      ON CONFLICT (email)
      DO UPDATE SET role = 'admin'
    `, [ADMIN_EMAIL, hashed]);
  }

  console.log("Database setup complete.");
}

// HEALTH CHECK
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      service: "ADS GROWTH AGENCY PRO",
      database: "connected"
    });
  } catch (error) {
    res.status(500).json({ ok: false, database: "error" });
  }
});

// PLANS
app.get("/api/plans", (req, res) => {
  res.json(Object.entries(PLANS).map(([key, plan]) => ({
    key,
    ...plan,
    currency: "USDT",
    network: "TRC20"
  })));
});

// PAYMENT INFORMATION
app.get("/api/payment-info", (req, res) => {
  res.json({
    address: RECEIVE_ADDRESS,
    payment_enabled: Boolean(RECEIVE_ADDRESS),
    network: "TRON (TRC20)",
    token: "USDT",
    plans: Object.entries(PLANS).map(([key, plan]) => ({
      key,
      ...plan
    }))
  });
});

// REGISTER
app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const name = cleanText(req.body.name, 80);
    const email = cleanText(req.body.email, 150).toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        password.length < 8) {
      return res.status(400).json({
        error: "Enter a name, valid email and password of at least 8 characters."
      });
    }

    const hashed = await bcrypt.hash(password, 12);

    const result = await pool.query(`
      INSERT INTO users (name, email, password_hash)
      VALUES ($1, $2, $3)
      RETURNING id, name, email, role, plan, subscription_expires
    `, [name, email, hashed]);

    const user = result.rows[0];

    res.status(201).json({
      message: "Account created successfully.",
      token: makeToken(user),
      user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Email already registered." });
    }
    console.error("Register error:", error);
    res.status(500).json({ error: "Could not create account." });
  }
});

// LOGIN
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const email = cleanText(req.body.email, 150).toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(`
      SELECT id, name, email, password_hash, role, plan, subscription_expires
      FROM users WHERE email = $1
    `, [email]);

    const user = result.rows[0];

    if (!user || !user.password_hash ||
        !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Incorrect email or password." });
    }

    res.json({
      message: "Login successful.",
      token: makeToken(user),
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        plan: user.plan,
        subscription_expires: user.subscription_expires
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Could not log in." });
  }
});

// CURRENT USER
app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, email, role, plan, subscription_expires, created_at
      FROM users WHERE id = $1
    `, [req.user.id]);

    if (!result.rows[0]) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: "Could not load account." });
  }
});

// SUBMIT PAYMENT REQUEST
app.post("/api/payments", auth, async (req, res) => {
  try {
    if (!RECEIVE_ADDRESS) {
      return res.status(503).json({
        error: "USDT payment is not connected yet."
      });
    }

    const planKey = cleanText(req.body.plan, 40);
    const txHash = cleanText(req.body.tx_hash, 100).toLowerCase();
    const plan = PLANS[planKey];

    if (!plan) {
      return res.status(400).json({ error: "Select a valid plan." });
    }

    if (!/^[a-f0-9]{64}$/.test(txHash)) {
      return res.status(400).json({ error: "Enter a valid 64-character TXID." });
    }

    const result = await pool.query(`
      INSERT INTO payments (user_id, plan_key, amount, tx_hash)
      VALUES ($1, $2, $3, $4)
      RETURNING id, plan_key, amount, tx_hash, status, created_at
    `, [req.user.id, planKey, plan.price, txHash]);

    res.status(201).json({
      message: "Payment submitted for manual verification. Plan is not active yet.",
      payment: result.rows[0]
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "This transaction hash has already been submitted."
      });
    }
    console.error("Payment submit error:", error);
    res.status(500).json({ error: "Could not submit payment." });
  }
});

// USER PAYMENT HISTORY
app.get("/api/payments", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, plan_key, amount, network, token, tx_hash,
             status, admin_note, created_at, reviewed_at
      FROM payments
      WHERE user_id = $1
      ORDER BY created_at DESC
    `, [req.user.id]);

    res.json({ payments: result.rows });
  } catch (error) {
    res.status(500).json({ error: "Could not load payment history." });
  }
});

// ADMIN OVERVIEW
app.get("/api/admin/overview", auth, adminOnly, async (req, res) => {
  try {
    const [users, pages, payments] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS count FROM users"),
      pool.query("SELECT COUNT(*)::int AS count FROM pages"),
      pool.query(`
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE status = 'pending')::int AS pending,
          COUNT(*) FILTER (WHERE status = 'approved')::int AS approved,
          COUNT(*) FILTER (WHERE status = 'rejected')::int AS rejected
        FROM payments
      `)
    ]);

    res.json({
      users: users.rows[0].count,
      pages: pages.rows[0].count,
      payments: payments.rows[0]
    });
  } catch (error) {
    console.error("Admin overview error:", error);
    res.status(500).json({ error: "Could not load admin overview." });
  }
});

// ADMIN PAYMENT LIST
app.get("/api/admin/payments", auth, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.id, p.user_id, u.name, u.email, p.plan_key,
             p.amount, p.network, p.token, p.tx_hash,
             p.status, p.admin_note, p.created_at, p.reviewed_at
      FROM payments p
      JOIN users u ON u.id = p.user_id
      ORDER BY
        CASE WHEN p.status = 'pending' THEN 0 ELSE 1 END,
        p.created_at DESC
    `);

    res.json({ payments: result.rows });
  } catch (error) {
    console.error("Admin payments error:", error);
    res.status(500).json({ error: "Could not load payment requests." });
  }
});

// ADMIN REVIEW PAYMENT
app.post("/api/admin/payments/:id/review", auth, adminOnly, async (req, res) => {
  const paymentId = Number(req.params.id);
  const action = cleanText(req.body.action, 20).toLowerCase();
  const note = cleanText(req.body.note, 500);

  if (!Number.isInteger(paymentId) || paymentId < 1) {
    return res.status(400).json({ error: "Invalid payment ID." });
  }

  if (!["approve", "reject"].includes(action)) {
    return res.status(400).json({ error: "Action must be approve or reject." });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const found = await client.query(
      "SELECT * FROM payments WHERE id = $1 FOR UPDATE",
      [paymentId]
    );

    const payment = found.rows[0];

    if (!payment) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Payment not found." });
    }

    if (payment.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Payment already reviewed." });
    }

    if (action === "approve") {
      const plan = PLANS[payment.plan_key];

      if (!plan || Number(payment.amount) !== plan.price) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Plan or amount does not match." });
      }

      await client.query(`
        UPDATE payments
        SET status = 'approved', admin_note = $2, reviewed_at = NOW()
        WHERE id = $1
      `, [paymentId, note]);

      await client.query(`
        UPDATE users
        SET plan = $2,
            subscription_expires =
              GREATEST(COALESCE(subscription_expires, NOW()), NOW())
              + ($3 * INTERVAL '1 day')
        WHERE id = $1
      `, [payment.user_id, payment.plan_key, plan.days]);
    } else {
      await client.query(`
        UPDATE payments
        SET status = 'rejected', admin_note = $2, reviewed_at = NOW()
        WHERE id = $1
      `, [paymentId, note]);
    }

    await client.query("COMMIT");

    res.json({
      message: action === "approve"
        ? "Payment approved and subscription activated."
        : "Payment rejected.",
      status: action === "approve" ? "approved" : "rejected"
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Payment review error:", error);
    res.status(500).json({ error: "Could not review payment." });
  } finally {
    client.release();
  }
});

// GET USER PAGES
app.get("/api/pages", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM pages
      WHERE user_id = $1
      ORDER BY created_at DESC
    `, [req.user.id]);

    res.json({ pages: result.rows });
  } catch (error) {
    res.status(500).json({ error: "Could not load pages." });
  }
});

// CREATE PAGE
app.post("/api/pages", auth, async (req, res) => {
  try {
    const userResult = await pool.query(`
      SELECT plan, subscription_expires
      FROM users WHERE id = $1
    `, [req.user.id]);

    const user = userResult.rows[0];
    const active = user && user.plan &&
      user.subscription_expires &&
      new Date(user.subscription_expires) > new Date();

    if (!active) {
      return res.status(403).json({
        error: "An active subscription is required."
      });
    }

    const body = req.body || {};
    const title = cleanText(body.title, 120);

    if (!title) {
      return res.status(400).json({ error: "Page title is required." });
    }

    const slug = makeSlug(title);

    const result = await pool.query(`
      INSERT INTO pages (
        user_id, title, headline, description, image_url,
        button_text, button_url, whatsapp, pixel_id,
        background_color, heading_color, button_color,
        image_size, slug
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      RETURNING *
    `, [
      req.user.id,
      title,
      cleanText(body.headline, 250),
      cleanText(body.description, 3000),
      cleanText(body.image_url, 1000),
      cleanText(body.button_text, 80) || "Join Now",
      cleanText(body.button_url, 1000),
      cleanText(body.whatsapp, 40),
      cleanText(body.pixel_id, 40),
      cleanText(body.background_color, 30) || "#0f172a",
      cleanText(body.heading_color, 30) || "#22c55e",
      cleanText(body.button_color, 30) || "#0088cc",
      cleanText(body.image_size, 20) || "medium",
      slug
    ]);

    res.status(201).json({
      message: "Page created.",
      page: result.rows[0]
    });
  } catch (error) {
    console.error("Create page error:", error);
    res.status(500).json({ error: "Could not create page." });
  }
});

// UPDATE PAGE
app.put("/api/pages/:id", auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "Invalid page ID." });
    }

    const body = req.body || {};

    const result = await pool.query(`
      UPDATE pages SET
        title = $3,
        headline = $4,
        description = $5,
        image_url = $6,
        button_text = $7,
        button_url = $8,
        whatsapp = $9,
        pixel_id = $10,
        background_color = $11,
        heading_color = $12,
        button_color = $13,
        image_size = $14,
        updated_at = NOW()
      WHERE id = $1 AND user_id = $2
      RETURNING *
    `, [
      id,
      req.user.id,
      cleanText(body.title, 120),
      cleanText(body.headline, 250),
      cleanText(body.description, 3000),
      cleanText(body.image_url, 1000),
      cleanText(body.button_text, 80),
      cleanText(body.button_url, 1000),
      cleanText(body.whatsapp, 40),
      cleanText(body.pixel_id, 40),
      cleanText(body.background_color, 30),
      cleanText(body.heading_color, 30),
      cleanText(body.button_color, 30),
      cleanText(body.image_size, 20)
    ]);

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Page not found." });
    }

    res.json({ message: "Page updated.", page: result.rows[0] });
  } catch (error) {
    console.error("Update page error:", error);
    res.status(500).json({ error: "Could not update page." });
  }
});

// PUBLISH / UNPUBLISH PAGE
app.post("/api/pages/:id/publish", auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const published = req.body.published !== false;

    const result = await pool.query(`
      UPDATE pages
      SET published = $3, updated_at = NOW()
      WHERE id = $1 AND user_id = $2
      RETURNING id, slug, published
    `, [id, req.user.id, published]);

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Page not found." });
    }

    res.json({
      message: published ? "Page published." : "Page unpublished.",
      page: result.rows[0],
      url: "/p/" + result.rows[0].slug
    });
  } catch (error) {
    console.error("Publish error:", error);
    res.status(500).json({ error: "Could not publish page." });
  }
});

// DELETE PAGE
app.delete("/api/pages/:id", auth, async (req, res) => {
  try {
    const id = Number(req.params.id);

    const result = await pool.query(`
      DELETE FROM pages
      WHERE id = $1 AND user_id = $2
      RETURNING id
    `, [id, req.user.id]);

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Page not found." });
    }

    res.json({ message: "Page deleted." });
  } catch (error) {
    console.error("Delete page error:", error);
    res.status(500).json({ error: "Could not delete page." });
  }
});

// PAGE ANALYTICS
app.post("/api/events", async (req, res) => {
  try {
    const pageId = Number(req.body.page_id);
    const eventType = cleanText(req.body.event_type, 40);

    if (!Number.isInteger(pageId) || pageId < 1 || !eventType) {
      return res.status(400).json({ error: "Invalid event." });
    }

    const page = await pool.query(
      "SELECT id FROM pages WHERE id = $1 AND published = TRUE",
      [pageId]
    );

    if (!page.rows[0]) {
      return res.status(404).json({ error: "Page not found." });
    }

    await pool.query(
      "INSERT INTO events (page_id, event_type) VALUES ($1, $2)",
      [pageId, eventType]
    );

    res.json({ success: true });
  } catch (error) {
    console.error("Analytics error:", error);
    res.status(500).json({ error: "Could not record event." });
  }
});

// PUBLIC PAGE
app.get("/p/:slug", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM pages WHERE slug = $1 AND published = TRUE",
      [cleanText(req.params.slug, 100)]
    );

    const page = result.rows[0];

    if (!page) {
      return res.status(404).send("Page not found or unpublished.");
    }

    await pool.query(
      "INSERT INTO events (page_id, event_type) VALUES ($1, 'view')",
      [page.id]
    );

    const title = escapeHtml(page.title);
    const headline = escapeHtml(page.headline);
    const description = escapeHtml(page.description);
    const image = escapeHtml(page.image_url);
    const buttonText = escapeHtml(page.button_text || "Join Now");
    const buttonUrl = escapeHtml(page.button_url || "#");

    const bg = /^#[0-9a-fA-F]{6}$/.test(page.background_color)
      ? page.background_color : "#0f172a";
    const heading = /^#[0-9a-fA-F]{6}$/.test(page.heading_color)
      ? page.heading_color : "#22c55e";
    const button = /^#[0-9a-fA-F]{6}$/.test(page.button_color)
      ? page.button_color : "#0088cc";

    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
*{box-sizing:border-box}
body{margin:0;padding:20px;font-family:Arial,sans-serif;
background:${bg};color:white;text-align:center}
main{max-width:480px;margin:35px auto;padding:25px;
border-radius:18px;background:rgba(255,255,255,.06)}
h1{color:${heading}}
img{max-width:100%;height:auto;border-radius:14px}
a.cta{display:inline-block;background:${button};color:white;
padding:15px 28px;border-radius:12px;text-decoration:none;
font-weight:bold;margin-top:18px}
p{line-height:1.6}
</style>
</head>
<body>
<main>
<h1>${headline || title}</h1>
${image ? `<img src="${image}" alt="${title}">` : ""}
<p>${description}</p>
<a class="cta" href="${buttonUrl}" rel="noopener">${buttonText}</a>
</main>
</body>
</html>`);
  } catch (error) {
    console.error("Public page error:", error);
    res.status(500).send("Could not load page.");
  }
});

// STATIC WEBSITE
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.sendFile(require("path").join(__dirname, "public", "index.html"));
});

// UNKNOWN API ROUTES
app.use("/api", (req, res) => {
  res.status(404).json({ error: "API route not found." });
});

// START SERVER
async function startServer() {
  try {
    await initDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("ADS GROWTH AGENCY PRO running on port " + PORT);
    });
  } catch (error) {
    console.error("Server startup failed:", error);
    process.exit(1);
  }
}

startServer();
  
