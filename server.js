require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const RECEIVE_ADDRESS = (process.env.USDT_TRC20_ADDRESS || "").trim();

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must contain at least 32 characters.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === "true"
    ? { rejectUnauthorized: false }
    : undefined
});

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/api/auth", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30
}));

function cleanText(value, max = 500) {
  return String(value || "").trim().slice(0, max);
}

function makeSlug(value) {
  return cleanText(value, 120)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "") +
    "-" + Date.now().toString(36);
}

function tokenFor(user) {
  return jwt.sign({
    id: user.id,
    email: user.email,
    role: user.role
  }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({ error: "Login required." });
    }

    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired login." });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }
  next();
}

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

  // Compatibility with older database schemas.
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'users'
          AND column_name = 'password'
      ) THEN
        ALTER TABLE public.users
        ALTER COLUMN password SET DEFAULT '';
      END IF;
    END $$;
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
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      plan TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      txid TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      page_id INTEGER REFERENCES pages(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Seed admin only when both credentials are configured.
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);

    await pool.query(`
      INSERT INTO users (name, email, password_hash, role)
      VALUES ('Admin', $1, $2, 'admin')
      ON CONFLICT (email)
      DO UPDATE SET role = 'admin'
    `, [ADMIN_EMAIL, hash]);
  }

  console.log("Database initialized.");
}

const PLANS = {
  basic: { amount: 5, days: 30 },
  prime_pro: { amount: 12, days: 30 },
  basic_prime: { amount: 15, days: 30 }
};

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch {
    res.status(503).json({ ok: false, database: "error" });
  }
});

app.get("/api/config", (req, res) => {
  res.json({
    receiveAddress: RECEIVE_ADDRESS,
    plans: PLANS
  });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = cleanText(req.body.name, 100);
    const email = cleanText(req.body.email, 200).toLowerCase();
    const password = String(req.body.password || "");

    if (!email.includes("@") || password.length < 8) {
      return res.status(400).json({
        error: "Valid email and password of at least 8 characters required."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(`
      INSERT INTO users (name, email, password_hash)
      VALUES ($1, $2, $3)
      RETURNING id, name, email, role
    `, [name, email, hash]);

    const user = result.rows[0];

    res.status(201).json({
      token: tokenFor(user),
      user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Email already registered." });
    }
    console.error(error);
    res.status(500).json({ error: "Registration failed." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = cleanText(req.body.email, 200).toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    const user = result.rows[0];

    if (!user || !user.password_hash ||
        !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    res.json({
      token: tokenFor(user),
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
    console.error(error);
    res.status(500).json({ error: "Login failed." });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const result = await pool.query(`
    SELECT id, name, email, role, plan, subscription_expires
    FROM users WHERE id = $1
  `, [req.user.id]);

  if (!result.rows[0]) {
    return res.status(404).json({ error: "User not found." });
  }

  res.json({ user: result.rows[0] });
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
      makeSlug(title)
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

// LIST PAGES
app.get("/api/pages", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM pages WHERE user_id = $1 ORDER BY id DESC",
    [req.user.id]
  );
  res.json({ pages: result.rows });
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
        title = $3, headline = $4, description = $5,
        image_url = $6, button_text = $7, button_url = $8,
        whatsapp = $9, pixel_id = $10, background_color = $11,
        heading_color = $12, button_color = $13,
        image_size = $14, updated_at = NOW()
      WHERE id = $1 AND user_id = $2
      RETURNING *
    `, [
      id, req.user.id,
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
    console.error(error);
    res.status(500).json({ error: "Could not update page." });
  }
});

// PUBLISH PAGE
app.post("/api/pages/:id/publish", auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const published = req.body.published !== false;

    const result = await pool.query(`
      UPDATE pages SET published = $3, updated_at = NOW()
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
    console.error(error);
    res.status(500).json({ error: "Could not publish page." });
  }
});

// DELETE PAGE
app.delete("/api/pages/:id", auth, async (req, res) => {
  try {
    const id = Number(req.params.id);

    const result = await pool.query(`
      DELETE FROM pages WHERE id = $1 AND user_id = $2
      RETURNING id
    `, [id, req.user.id]);

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Page not found." });
    }

    res.json({ message: "Page deleted." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not delete page." });
  }
});

// SUBMIT PAYMENT REQUEST
app.post("/api/payments", auth, async (req, res) => {
  try {
    const plan = cleanText(req.body.plan, 40);
    const txid = cleanText(req.body.txid, 150);

    if (!PLANS[plan] || !txid) {
      return res.status(400).json({ error: "Valid plan and TXID required." });
    }

    const result = await pool.query(`
      INSERT INTO payments (user_id, plan, amount, txid)
      VALUES ($1, $2, $3, $4)
      RETURNING id, plan, amount, txid, status, created_at
    `, [req.user.id, plan, PLANS[plan].amount, txid]);

    res.status(201).json({ payment: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "TXID already submitted." });
    }
    console.error(error);
    res.status(500).json({ error: "Payment submission failed." });
  }
});

app.get("/api/payments", auth, async (req, res) => {
  const result = await pool.query(`
    SELECT id, plan, amount, txid, status, created_at
    FROM payments WHERE user_id = $1 ORDER BY id DESC
  `, [req.user.id]);

  res.json({ payments: result.rows });
});

// ADMIN: LIST PAYMENTS
app.get("/api/admin/payments", auth, adminOnly, async (req, res) => {
  const result = await pool.query(`
    SELECT p.*, u.email
    FROM payments p JOIN users u ON u.id = p.user_id
    ORDER BY p.id DESC
  `);

  res.json({ payments: result.rows });
});

// ADMIN: APPROVE OR REJECT PAYMENT
app.post("/api/admin/payments/:id/review", auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const status = req.body.status;

  if (!Number.isInteger(id) || !["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid review request." });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const found = await client.query(
      "SELECT * FROM payments WHERE id = $1 FOR UPDATE",
      [id]
    );

    const payment = found.rows[0];

    if (!payment || payment.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Pending payment not found." });
    }

    await client.query(
      "UPDATE payments SET status = $1 WHERE id = $2",
      [status, id]
    );

    if (status === "approved") {
      const plan = PLANS[payment.plan];

      if (!plan) throw new Error("Unknown plan.");

      await client.query(`
        UPDATE users
        SET plan = $1,
            subscription_expires = GREATEST(
              COALESCE(subscription_expires, NOW()), NOW()
            ) + ($2 * INTERVAL '1 day')
        WHERE id = $3
      `, [payment.plan, plan.days, payment.user_id]);
    }

    await client.query("COMMIT");
    res.json({ message: "Payment " + status + "." });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ error: "Payment review failed." });
  } finally {
    client.release();
  }
});

// PUBLIC PAGE
app.get("/p/:slug", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM pages
      WHERE slug = $1 AND published = TRUE
    `, [req.params.slug]);

    const page = result.rows[0];

    if (!page) return res.status(404).send("Page not found.");

    const escape = value => String(value || "").replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;",
      '"': "&quot;", "'": "&#39;"
    })[c]);

    res.type("html").send(`
      <!doctype html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>${escape(page.title)}</title>
      </head>
      <body style="margin:0;padding:30px;background:${escape(page.background_color)};color:white;font-family:Arial;text-align:center">
        <h1 style="color:${escape(page.heading_color)}">${escape(page.headline || page.title)}</h1>
        <p>${escape(page.description)}</p>
        ${page.image_url ? `<img src="${escape(page.image_url)}" alt="" style="max-width:100%;max-height:500px;object-fit:contain">` : ""}
        <p><a href="${escape(page.button_url)}" style="display:inline-block;background:${escape(page.button_color)};color:white;padding:14px 25px;border-radius:10px;text-decoration:none">${escape(page.button_text)}</a></p>
      </body>
      </html>
    `);
  } catch (error) {
    console.error(error);
    res.status(500).send("Page error.");
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((req, res) => {
  res.status(404).json({ error: "Not found." });
});

async function startServer() {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log("Server running on port " + PORT);
    });
  } catch (error) {
    console.error("Server startup failed:", error);
    process.exit(1);
  }
}

startServer();
                  
