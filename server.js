
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must contain at least 32 characters");
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
  throw new Error("ADMIN_EMAIL and ADMIN_PASSWORD are required");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === "true"
    ? { rejectUnauthorized: false }
    : undefined
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 250
}));

const plans = {
  basic: { name: "Basic", price: 5, pages: 1 },
  prime: { name: "Prime & Pro", price: 12, pages: 1 },
  premium: { name: "Basic & Prime", price: 15, pages: 2 }
};

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer',
      plan TEXT,
      subscription_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      headline TEXT DEFAULT '',
      description TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      button_text TEXT DEFAULT 'Learn More',
      button_url TEXT DEFAULT '',
      whatsapp TEXT DEFAULT '',
      pixel_id TEXT DEFAULT '',
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      page_id INTEGER REFERENCES pages(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS pages_user_idx ON pages(user_id);
    CREATE INDEX IF NOT EXISTS events_page_idx ON events(page_id);
  `);

  const email = process.env.ADMIN_EMAIL.toLowerCase().trim();
  const password = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);

  await pool.query(`
    INSERT INTO users (name, email, password, role)
    VALUES ('Administrator', $1, $2, 'admin')
    ON CONFLICT (email) DO UPDATE
    SET role = 'admin'
  `, [email, password]);

  console.log("Database ready. Admin account checked.");
}

function createToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({ error: "Please login first" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query(
      "SELECT id, name, email, role, plan, subscription_expires FROM users WHERE id=$1",
      [decoded.id]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "Account not found" });
    }

    req.user = result.rows[0];
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired login" });
  }
}

function isAdmin(user) {
  return user.role === "admin";
}

function hasActiveSubscription(user) {
  return user.subscription_expires &&
    new Date(user.subscription_expires).getTime() > Date.now();
}

async function canCreatePage(user) {
  if (isAdmin(user)) return true;
  if (!hasActiveSubscription(user)) return false;

  const plan = plans[user.plan];
  if (!plan) return false;

  const count = await pool.query(
    "SELECT COUNT(*)::int AS total FROM pages WHERE user_id=$1",
    [user.id]
  );

  return count.rows[0].total < plan.pages;
}

function makeSlug() {
  return crypto.randomBytes(6).toString("hex");
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch {
    res.status(503).json({ status: "error", database: "disconnected" });
  }
});

app.get("/api/plans", (req, res) => {
  res.json(plans);
});

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password || password.length < 8) {
      return res.status(400).json({
        error: "Name, valid email and password of at least 8 characters required"
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    if (normalizedEmail === process.env.ADMIN_EMAIL.toLowerCase().trim()) {
      return res.status(403).json({ error: "This email is reserved for admin" });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (name,email,password)
       VALUES ($1,$2,$3)
       RETURNING id,name,email,role,plan,subscription_expires`,
      [name.trim(), normalizedEmail, hash]
    );

    const user = result.rows[0];
    res.status(201).json({ user, token: createToken(user) });
  } catch (error) {
    res.status(400).json({
      error: error.code === "23505" ? "Email already registered" : "Registration failed"
    });
  }
});

app.post("/api/login", async (req, res) => {
  const email = String(req.body.email || "").toLowerCase().trim();
  const password = String(req.body.password || "");

  const result = await pool.query(
    "SELECT * FROM users WHERE email=$1",
    [email]
  );

  if (!result.rows.length ||
      !(await bcrypt.compare(password, result.rows[0].password))) {
    return res.status(401).json({ error: "Incorrect email or password" });
  }

  const user = result.rows[0];
  delete user.password;

  res.json({ user, token: createToken(user) });
});

app.get("/api/me", auth, (req, res) => {
  res.json({
    user: req.user,
    isAdmin: isAdmin(req.user),
    subscriptionActive: isAdmin(req.user) || hasActiveSubscription(req.user)
  });
});

app.get("/api/pages", auth, async (req, res) => {
  const result = await pool.query(
    `SELECT * FROM pages
     WHERE user_id=$1 ORDER BY created_at DESC`,
    [req.user.id]
  );
  res.json(result.rows);
});

app.post("/api/pages", auth, async (req, res) => {
  try {
    if (!(await canCreatePage(req.user))) {
      return res.status(403).json({
        error: "Active subscription required or page limit reached"
      });
    }

    const {
      title, headline, description, image_url,
      button_text, button_url, whatsapp, pixel_id
    } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({ error: "Page title is required" });
    }

    const result = await pool.query(
      `INSERT INTO pages
       (user_id,title,slug,headline,description,image_url,
        button_text,button_url,whatsapp,pixel_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING *`,
      [
        req.user.id,
        title.trim(),
        makeSlug(),
        headline || "",
        description || "",
        image_url || "",
        button_text || "Learn More",
        button_url || "",
        whatsapp || "",
        pixel_id || ""
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not save page" });
  }
});

app.put("/api/pages/:id", auth, async (req, res) => {
  const result = await pool.query(
    `UPDATE pages SET
      title=$1, headline=$2, description=$3, image_url=$4,
      button_text=$5, button_url=$6, whatsapp=$7, pixel_id=$8
     WHERE id=$9 AND user_id=$10 RETURNING *`,
    [
      req.body.title || "",
      req.body.headline || "",
      req.body.description || "",
      req.body.image_url || "",
      req.body.button_text || "Learn More",
      req.body.button_url || "",
      req.body.whatsapp || "",
      req.body.pixel_id || "",
      req.params.id,
      req.user.id
    ]
  );

  if (!result.rows.length) {
    return res.status(404).json({ error: "Page not found" });
  }

  res.json(result.rows[0]);
});

app.post("/api/pages/:id/publish", auth, async (req, res) => {
  const result = await pool.query(
    `UPDATE pages SET published=TRUE
     WHERE id=$1 AND user_id=$2 RETURNING *`,
    [req.params.id, req.user.id]
  );

  if (!result.rows.length) {
    return res.status(404).json({ error: "Page not found" });
  }

  res.json({
    message: "Page published",
    url: `/p/${result.rows[0].slug}`,
    page: result.rows[0]
  });
});

app.delete("/api/pages/:id", auth, async (req, res) => {
  const result = await pool.query(
    "DELETE FROM pages WHERE id=$1 AND user_id=$2 RETURNING id",
    [req.params.id, req.user.id]
  );

  if (!result.rows.length) {
    return res.status(404).json({ error: "Page not found" });
  }

  res.json({ message: "Page deleted" });
});

app.get("/api/admin/overview", auth, async (req, res) => {
  if (!isAdmin(req.user)) {
    return res.status(403).json({ error: "Admin only" });
  }

  const [users, pages, published, events] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS total FROM users"),
    pool.query("SELECT COUNT(*)::int AS total FROM pages"),
    pool.query("SELECT COUNT(*)::int AS total FROM pages WHERE published=TRUE"),
    pool.query("SELECT COUNT(*)::int AS total FROM events")
  ]);

  res.json({
    users: users.rows[0].total,
    pages: pages.rows[0].total,
    publishedPages: published.rows[0].total,
    events: events.rows[0].total
  });
});

app.post("/api/events/:id/:type", async (req, res) => {
  const allowed = ["visit", "click"];

  if (!allowed.includes(req.params.type)) {
    return res.status(400).json({ error: "Invalid event" });
  }

  const page = await pool.query(
    "SELECT id FROM pages WHERE id=$1 AND published=TRUE",
    [req.params.id]
  );

  if (!page.rows.length) {
    return res.status(404).json({ error: "Page not found" });
  }

  await pool.query(
    "INSERT INTO events (page_id,event_type) VALUES ($1,$2)",
    [req.params.id, req.params.type]
  );

  res.json({ ok: true });
});

app.get("/api/pages/:id/analytics", auth, async (req, res) => {
  const page = await pool.query(
    "SELECT id FROM pages WHERE id=$1 AND user_id=$2",
    [req.params.id, req.user.id]
  );

  if (!page.rows.length) {
    return res.status(404).json({ error: "Page not found" });
  }

  const result = await pool.query(
    `SELECT event_type, COUNT(*)::int AS total
     FROM events WHERE page_id=$1 GROUP BY event_type`,
    [req.params.id]
  );

  res.json(result.rows);
});

app.get("/p/:slug", async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM pages WHERE slug=$1 AND published=TRUE",
    [req.params.slug]
  );

  if (!result.rows.length) {
    return res.status(404).send("Page not found");
  }

  const p = result.rows[0];

  await pool.query(
    "INSERT INTO events (page_id,event_type) VALUES ($1,'visit')",
    [p.id]
  );

  const safe = value => String(value || "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  })[char]);

  const image = p.image_url
    ? `<img src="${safe(p.image_url)}" alt="" style="max-width:100%;border-radius:16px">`
    : "";

  const buttonUrl = p.whatsapp
    ? `https://wa.me/${safe(p.whatsapp.replace(/\D/g, ""))}`
    : safe(p.button_url || "#");

  const pixel = /^\d+$/.test(p.pixel_id || "")
    ? `<script>!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');fbq('init','${p.pixel_id}');fbq('track','PageView');</script>`
    : "";

  res.send(`<!doctype html>
  <html><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${safe(p.title)}</title>${pixel}
  <style>
  body{margin:0;background:#080b18;color:white;font-family:Arial,sans-serif}
  main{max-width:760px;margin:50px auto;padding:30px;text-align:center}
  h1{font-size:clamp(30px,6vw,52px);color:#a78bfa}
  p{line-height:1.7;color:#d1d5db}
  a{display:inline-block;background:#a3e635;color:#111827;padding:15px 28px;border-radius:12px;text-decoration:none;font-weight:bold;margin-top:20px}
  </style></head><body><main>
  ${image}<h1>${safe(p.headline || p.title)}</h1>
  <p>${safe(p.description)}</p>
  <a href="${buttonUrl}" onclick="fetch('/api/events/${p.id}/click',{method:'POST'}).catch(()=>{})">${safe(p.button_text)}</a>
  </main></body></html>`);
});

app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on ${PORT}`));
  })
  .catch(error => {
    console.error("Startup failed:", error);
    process.exit(1);
  });
