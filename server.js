
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").toLowerCase().trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

if (!DATABASE_URL || !JWT_SECRET) {
  console.error("DATABASE_URL and JWT_SECRET environment variables are required.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === "false" ? false : { rejectUnauthorized: false }
});

app.use(express.static(path.join(__dirname, "public")));

function slugify(text) {
  const base = String(text || "landing-page")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 45) || "landing-page";

  return base + "-" + crypto.randomBytes(3).toString("hex");
}

function signToken(user) {
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
    if (!token) return res.status(401).json({ error: "Please login first." });

    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired login. Please login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }
  next();
}

function cleanPage(body) {
  return {
    title: String(body.title || "").trim().slice(0, 120),
    headline: String(body.headline || "").trim().slice(0, 180),
    description: String(body.description || "").trim().slice(0, 3000),
    buttonText: String(body.buttonText || "Join Now").trim().slice(0, 60),
    buttonLink: String(body.buttonLink || "").trim().slice(0, 1000),
    background: /^#[0-9a-fA-F]{6}$/.test(body.background || "")
      ? body.background
      : "#0b1730"
  };
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_pages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES ag_users(id) ON DELETE CASCADE,
      title VARCHAR(120) NOT NULL,
      headline VARCHAR(180) NOT NULL,
      description TEXT DEFAULT '',
      button_text VARCHAR(60) DEFAULT 'Join Now',
      button_link TEXT DEFAULT '',
      background VARCHAR(7) DEFAULT '#0b1730',
      slug VARCHAR(100) UNIQUE NOT NULL,
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES ag_users(id) ON DELETE CASCADE,
      plan VARCHAR(40) NOT NULL,
      amount NUMERIC(10,2) NOT NULL,
      txid VARCHAR(200) NOT NULL,
      status VARCHAR(20) DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Add fields for an older installation where these columns are missing.
  await pool.query(`
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_text VARCHAR(60) DEFAULT 'Join Now';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_link TEXT DEFAULT '';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS background VARCHAR(7) DEFAULT '#0b1730';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS published BOOLEAN DEFAULT FALSE;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
  `);

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query(
      `INSERT INTO ag_users (name,email,password_hash,role)
       VALUES ($1,$2,$3,'admin')
       ON CONFLICT (email) DO UPDATE SET role='admin'`,
      ["Admin", ADMIN_EMAIL, hash]
    );
  }

  console.log("Database tables ready.");
}

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || password.length < 6) {
      return res.status(400).json({ error: "Name, valid email and password of at least 6 characters are required." });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO ag_users (name,email,password_hash)
       VALUES ($1,$2,$3)
       RETURNING id,name,email,role`,
      [name, email, hash]
    );

    const user = result.rows[0];
    res.status(201).json({ token: signToken(user), user });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "This email is already registered." });
    }
    console.error(error);
    res.status(500).json({ error: "Registration failed." });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM ag_users WHERE email=$1",
      [email]
    );
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Incorrect email or password." });
    }

    res.json({
      token: signToken(user),
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed." });
  }
});

// Current user
app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id,name,email,role FROM ag_users WHERE id=$1",
      [req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "User not found." });
    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load account." });
  }
});

// List user's pages
app.get("/api/pages", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,title,headline,description,
              button_text AS "buttonText",
              button_link AS "buttonLink",
              background,slug,published,created_at,updated_at
       FROM ag_pages WHERE user_id=$1 ORDER BY id DESC`,
      [req.user.id]
    );
    res.json({ pages: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load pages." });
  }
});

// Create page
app.post("/api/pages", auth, async (req, res) => {
  try {
    const page = cleanPage(req.body);
    if (!page.title || !page.headline) {
      return res.status(400).json({ error: "Title and headline are required." });
    }

    const result = await pool.query(
      `INSERT INTO ag_pages
       (user_id,title,headline,description,button_text,button_link,background,slug)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id,title,headline,description,
       button_text AS "buttonText",button_link AS "buttonLink",
       background,slug,published`,
      [
        req.user.id, page.title, page.headline, page.description,
        page.buttonText, page.buttonLink, page.background, slugify(page.title)
      ]
    );

    res.status(201).json({ page: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not create page." });
  }
});

// Edit page
app.put("/api/pages/:id", auth, async (req, res) => {
  try {
    const page = cleanPage(req.body);
    if (!page.title || !page.headline) {
      return res.status(400).json({ error: "Title and headline are required." });
    }

    const result = await pool.query(
      `UPDATE ag_pages SET
       title=$1,headline=$2,description=$3,button_text=$4,
       button_link=$5,background=$6,updated_at=NOW()
       WHERE id=$7 AND user_id=$8
       RETURNING id,title,headline,description,
       button_text AS "buttonText",button_link AS "buttonLink",
       background,slug,published`,
      [
        page.title,page.headline,page.description,page.buttonText,
        page.buttonLink,page.background,req.params.id,req.user.id
      ]
    );

    if (!result.rows.length) return res.status(404).json({ error: "Page not found." });
    res.json({ page: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not update page." });
  }
});

// Delete page
app.delete("/api/pages/:id", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2 RETURNING id",
      [req.params.id, req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Page not found." });
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not delete page." });
  }
});

// Publish / Unpublish
app.post("/api/pages/:id/publish", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE ag_pages SET published=NOT published,updated_at=NOW()
       WHERE id=$1 AND user_id=$2 RETURNING id,published,slug`,
      [req.params.id, req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Page not found." });
    res.json({ success: true, page: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not change page status." });
  }
});

// Public landing page
app.get("/p/:slug", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT title,headline,description,button_text,button_link,background
       FROM ag_pages WHERE slug=$1 AND published=TRUE`,
      [req.params.slug]
    );

    if (!result.rows.length) return res.status(404).send("Page not found or not published.");

    const p = result.rows[0];
    const safe = value => String(value || "").replace(/[&<>"']/g, c => ({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
    })[c]);

    const link = /^https?:\/\//i.test(p.button_link || "") ? safe(p.button_link) : "#";
    const color = /^#[0-9a-fA-F]{6}$/.test(p.background || "") ? p.background : "#0b1730";

    res.send(`<!DOCTYPE html>
<html lang="hi"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${safe(p.title)}</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:${color};color:white;font-family:Arial}
main{max-width:650px;padding:35px;text-align:center}
h1{font-size:38px}p{line-height:1.7;color:#d4dfed}
a{display:inline-block;padding:14px 25px;background:#20c982;color:#071b12;text-decoration:none;border-radius:8px;font-weight:bold}
</style></head><body><main>
<h1>${safe(p.headline)}</h1>
<h2>${safe(p.title)}</h2>
<p>${safe(p.description)}</p>
<a href="${link}" target="_blank" rel="noopener noreferrer">${safe(p.button_text || "Join Now")}</a>
</main></body></html>`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Could not display this page.");
  }
});

// Submit payment details
app.post("/api/payments", auth, async (req, res) => {
  try {
    const plan = String(req.body.plan || "");
    const amount = Number(req.body.amount);
    const txid = String(req.body.txid || "").trim();

    const prices = { Starter: 499, Growth: 999, Pro: 1499 };
    if (!prices[plan] || amount !== prices[plan] || !txid || txid.length > 200) {
      return res.status(400).json({ error: "Please select a valid plan, amount and transaction ID." });
    }

    const result = await pool.query(
      `INSERT INTO ag_payments (user_id,plan,amount,txid)
       VALUES ($1,$2,$3,$4)
       RETURNING id,plan,amount,txid,status,created_at`,
      [req.user.id,plan,amount,txid]
    );
    res.status(201).json({ payment: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not submit payment details." });
  }
});

// User payment history
app.get("/api/payments", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,plan,amount,txid,status,created_at
       FROM ag_payments WHERE user_id=$1 ORDER BY id DESC`,
      [req.user.id]
    );
    res.json({ payments: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load payments." });
  }
});

// Admin statistics
app.get("/api/admin/stats", auth, adminOnly, async (req, res) => {
  try {
    const [users,pages,payments] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS count FROM ag_users"),
      pool.query("SELECT COUNT(*)::int AS count FROM ag_pages"),
      pool.query("SELECT COUNT(*)::int AS count FROM ag_payments")
    ]);
    res.json({
      users:users.rows[0].count,
      pages:pages.rows[0].count,
      payments:payments.rows[0].count
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load admin stats." });
  }
});

// Admin payment list
app.get("/api/admin/payments", auth, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.id,p.plan,p.amount,p.txid,p.status,p.created_at,
              u.email
       FROM ag_payments p JOIN ag_users u ON u.id=p.user_id
       ORDER BY p.id DESC LIMIT 200`
    );
    res.json({ payments: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load admin payments." });
  }
});

// Approve or reject payment after checking it independently
app.post("/api/admin/payments/:id/status", auth, adminOnly, async (req, res) => {
  try {
    const status = String(req.body.status || "");
    if (!["approved","rejected"].includes(status)) {
      return res.status(400).json({ error: "Status must be approved or rejected." });
    }

    const result = await pool.query(
      `UPDATE ag_payments SET status=$1 WHERE id=$2
       RETURNING id,status,plan,amount`,
      [status,req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Payment not found." });
    res.json({ success:true,payment:result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not update payment." });
  }
});

// Health check
app.get("/health", (req,res) => res.json({ status:"ok" }));

app.get("/", (req,res) => {
  res.sendFile(path.join(__dirname,"public","index.html"));
});

initDatabase()
  .then(() => {
    app.listen(PORT,"0.0.0.0",() => {
      console.log("ADS GROWTH server running on port "+PORT);
    });
  })
  .catch(error => {
    console.error("Database initialization failed:",error);
    process.exit(1);
  });
                                         
