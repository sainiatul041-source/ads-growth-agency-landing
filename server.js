require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const required = [
  "DATABASE_URL",
  "JWT_SECRET",
  "ADMIN_EMAIL",
  "ADMIN_PASSWORD"
];

for (const key of required) {
  if (!process.env[key]) {
    console.error("Missing environment variable:", key);
    process.exit(1);
  }
}

if (process.env.JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: String(process.env.DB_SSL || "").toLowerCase() === "true"
    ? { rejectUnauthorized: false }
    : undefined
});

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 250
}));

app.use(express.static(path.join(__dirname, "public")));

const plans = {
  starter: { name: "Starter", price: 999, pages: 1, days: 30 },
  growth: { name: "Growth", price: 1499, pages: 1, days: 30 },
  pro: { name: "Pro", price: 1999, pages: 2, days: 30 }
};

const asyncRoute = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function makeToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({ error: "Please log in." });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Session expired. Login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }
  next();
}

function slugify(value) {
  return String(value || "landing-page")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 55) || "landing-page";
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer',
      plan TEXT,
      subscription_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES ag_users(id) ON DELETE CASCADE,
      plan_key TEXT NOT NULL,
      amount INTEGER NOT NULL,
      utr TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ag_pages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES ag_users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      headline TEXT NOT NULL,
      description TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      button_text TEXT DEFAULT 'Learn More',
      button_url TEXT DEFAULT '',
      whatsapp TEXT DEFAULT '',
      pixel_id TEXT DEFAULT '',
      background_color TEXT DEFAULT '#0b1730',
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_events (
      id BIGSERIAL PRIMARY KEY,
      page_id BIGINT REFERENCES ag_pages(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      visitor_key TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);

  await pool.query(`
    INSERT INTO ag_users(name,email,password_hash,role)
    VALUES($1,$2,$3,'admin')
    ON CONFLICT(email) DO UPDATE SET
      password_hash=EXCLUDED.password_hash,
      role='admin'
  `, [
    "Administrator",
    process.env.ADMIN_EMAIL.toLowerCase().trim(),
    hash
  ]);
}

app.get("/api/health", asyncRoute(async (req, res) => {
  await pool.query("SELECT 1");
  res.json({ ok: true, database: "connected" });
}));

app.get("/api/plans", (req, res) => {
  res.json(plans);
});

app.post("/api/register", asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").toLowerCase().trim();
  const password = String(req.body.password || "");

  if (name.length < 2 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 8) {
    return res.status(400).json({
      error: "Enter valid name, email and password of at least 8 characters."
    });
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    const result = await pool.query(
      `INSERT INTO ag_users(name,email,password_hash)
       VALUES($1,$2,$3)
       RETURNING id,name,email,role,plan,subscription_expires`,
      [name, email, hash]
    );

    const user = result.rows[0];

    res.status(201).json({
      token: makeToken(user),
      user
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "Email already registered."
      });
    }
    throw err;
  }
}));

app.post("/api/login", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").toLowerCase().trim();
  const password = String(req.body.password || "");

  const result = await pool.query(
    "SELECT * FROM ag_users WHERE email=$1",
    [email]
  );

  const user = result.rows[0];

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({
      error: "Email or password incorrect."
    });
  }

  res.json({
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
}));

app.get("/api/me", auth, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id,name,email,role,plan,subscription_expires
     FROM ag_users WHERE id=$1`,
    [req.user.id]
  );

  if (!result.rows[0]) {
    return res.status(404).json({ error: "Account not found." });
  }

  res.json(result.rows[0]);
}));

app.post("/api/payments", auth, asyncRoute(async (req, res) => {
  const planKey = String(req.body.plan || "");
  const utr = String(req.body.utr || "").trim();
  const plan = plans[planKey];

  if (!plan) {
    return res.status(400).json({ error: "Invalid plan." });
  }

  if (utr.length < 6 || utr.length > 80) {
    return res.status(400).json({ error: "Enter a valid UTR." });
  }

  const result = await pool.query(
    `INSERT INTO ag_payments(user_id,plan_key,amount,utr)
     VALUES($1,$2,$3,$4)
     RETURNING id,status,amount,plan_key`,
    [req.user.id, planKey, plan.price, utr]
  );

  res.status(201).json({
    message: "Payment submitted for manual verification.",
    payment: result.rows[0]
  });
}));

app.get("/api/pages", auth, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT p.*,
      (SELECT COUNT(*) FROM ag_events e
       WHERE e.page_id=p.id AND e.event_type='visit') AS visits,
      (SELECT COUNT(*) FROM ag_events e
       WHERE e.page_id=p.id AND e.event_type='click') AS clicks
     FROM ag_pages p
     WHERE p.user_id=$1 ORDER BY p.id DESC`,
    [req.user.id]
  );

  res.json(result.rows);
}));

app.post("/api/pages", auth, asyncRoute(async (req, res) => {
  const resultUser = await pool.query(
    "SELECT * FROM ag_users WHERE id=$1",
    [req.user.id]
  );

  const user = resultUser.rows[0];

  if (!user) {
    return res.status(404).json({ error: "User not found." });
  }

  const isAdmin = user.role === "admin";
  const active = user.subscription_expires &&
    new Date(user.subscription_expires) > new Date();

  if (!isAdmin && (!active || !plans[user.plan])) {
    return res.status(403).json({
      error: "Active subscription required."
    });
  }

  const title = String(req.body.title || "").trim();
  const headline = String(req.body.headline || "").trim();

  if (!title || !headline) {
    return res.status(400).json({
      error: "Title and headline required."
    });
  }

  const count = await pool.query(
    "SELECT COUNT(*)::int AS total FROM ag_pages WHERE user_id=$1",
    [user.id]
  );

  const limit = isAdmin ? 10000 : plans[user.plan].pages;

  if (count.rows[0].total >= limit) {
    return res.status(403).json({
      error: `Your plan allows ${limit} page(s).`
    });
  }

  const slug = slugify(title) + "-" +
    crypto.randomBytes(3).toString("hex");

  const page = await pool.query(
    `INSERT INTO ag_pages
    (user_id,title,slug,headline,description,image_url,
     button_text,button_url,whatsapp,pixel_id,background_color,published)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
    RETURNING *`,
    [
      user.id,
      title,
      slug,
      headline,
      req.body.description || "",
      req.body.image_url || "",
      req.body.button_text || "Learn More",
      req.body.button_url || "",
      req.body.whatsapp || "",
      req.body.pixel_id || "",
      /^#[0-9a-fA-F]{6}$/.test(req.body.background_color || "")
        ? req.body.background_color
        : "#0b1730",
      Boolean(req.body.published)
    ]
  );

  res.status(201).json(page.rows[0]);
}));

app.patch("/api/pages/:id", auth, asyncRoute(async (req, res) => {
  const found = await pool.query(
    "SELECT * FROM ag_pages WHERE id=$1",
    [req.params.id]
  );

  const page = found.rows[0];

  if (!page) {
    return res.status(404).json({ error: "Page not found." });
  }

  if (String(page.user_id) !== String(req.user.id) &&
      req.user.role !== "admin") {
    return res.status(403).json({ error: "Not allowed." });
  }

  const allowed = [
    "title", "headline", "description", "image_url",
    "button_text", "button_url", "whatsapp",
    "pixel_id", "background_color", "published"
  ];

  const values = [];
  const updates = [];

  for (const key of allowed) {
    if (Object.prototype.hasOwnProperty.call(req.body, key)) {
      if (key === "background_color" &&
          !/^#[0-9a-fA-F]{6}$/.test(String(req.body[key]))) {
        continue;
      }

      values.push(key === "published"
        ? Boolean(req.body[key])
        : req.body[key]);

      updates.push(`${key}=$${values.length}`);
    }
  }

  if (!updates.length) return res.json(page);

  values.push(page.id);

  const updated = await pool.query(
    `UPDATE ag_pages SET ${updates.join(",")}
     WHERE id=$${values.length} RETURNING *`,
    values
  );

  res.json(updated.rows[0]);
}));

app.delete("/api/pages/:id", auth, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `DELETE FROM ag_pages
     WHERE id=$1 AND (user_id=$2 OR $3='admin')
     RETURNING id`,
    [req.params.id, req.user.id, req.user.role]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "Page not found." });
  }

  res.json({ ok: true });
}));

app.get("/api/public/pages/:slug", asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id,title,slug,headline,description,image_url,
     button_text,button_url,whatsapp,pixel_id,background_color
     FROM ag_pages WHERE slug=$1 AND published=true`,
    [req.params.slug]
  );

  if (!result.rows[0]) {
    return res.status(404).json({ error: "Page not found." });
  }

  res.json(result.rows[0]);
}));

app.post("/api/public/pages/:slug/event", asyncRoute(async (req, res) => {
  const type = req.body.type === "click" ? "click" : "visit";

  const page = await pool.query(
    "SELECT id FROM ag_pages WHERE slug=$1 AND published=true",
    [req.params.slug]
  );

  if (!page.rows[0]) {
    return res.status(404).json({ error: "Page not found." });
  }

  const visitor = String(req.body.visitor || "").slice(0, 100) ||
    crypto.createHash("sha256")
      .update(req.ip + "|" + (req.headers["user-agent"] || ""))
      .digest("hex");

  await pool.query(
    `INSERT INTO ag_events(page_id,event_type,visitor_key)
     SELECT $1,$2,$3
     WHERE NOT EXISTS (
       SELECT 1 FROM ag_events
       WHERE page_id=$1 AND event_type=$2
       AND visitor_key=$3
       AND created_at >= date_trunc('day',NOW())
     )`,
    [page.rows[0].id, type, visitor]
  );

  res.json({ ok: true });
}));

app.get("/api/admin/overview", auth, adminOnly, asyncRoute(async (req, res) => {
  const [users, pages, payments, events] = await Promise.all([
    pool.query("SELECT id,name,email,role,plan,subscription_expires FROM ag_users ORDER BY id DESC"),
    pool.query("SELECT p.*,u.email AS owner_email FROM ag_pages p JOIN ag_users u ON u.id=p.user_id ORDER BY p.id DESC"),
    pool.query("SELECT p.*,u.email AS user_email FROM ag_payments p JOIN ag_users u ON u.id=p.user_id ORDER BY p.id DESC"),
    pool.query("SELECT event_type,COUNT(*)::int AS total FROM ag_events GROUP BY event_type")
  ]);

  res.json({
    users: users.rows,
    pages: pages.rows,
    payments: payments.rows,
    events: events.rows
  });
}));

app.post("/api/admin/payments/:id/approve", auth, adminOnly, asyncRoute(async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const found = await client.query(
      "SELECT * FROM ag_payments WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );

    const payment = found.rows[0];

    if (!payment) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Payment not found." });
    }

    if (payment.status !== "approved") {
      const plan = plans[payment.plan_key];

      if (!plan) throw new Error("Invalid plan.");

      const expires = new Date(Date.now() + plan.days * 86400000);

      await client.query(
        `UPDATE ag_users SET plan=$1,subscription_expires=$2
         WHERE id=$3`,
        [payment.plan_key, expires, payment.user_id]
      );

      await client.query(
        `UPDATE ag_payments SET status='approved',reviewed_at=NOW()
         WHERE id=$1`,
        [payment.id]
      );
    }

    await client.query("COMMIT");

    res.json({
      ok: true,
      message: "Payment approved and plan activated."
    });
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}));

app.post("/api/admin/payments/:id/reject", auth, adminOnly, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `UPDATE ag_payments SET status='rejected',reviewed_at=NOW()
     WHERE id=$1 AND status='pending' RETURNING id`,
    [req.params.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "Pending payment not found." });
  }

  res.json({ ok: true });
}));

app.get("/p/:slug", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "page.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    error: "Server error. Check Render logs."
  });
});

const PORT = process.env.PORT || 3000;

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log("ADS GROWTH AGENCY PRO running on " + PORT);
    });
  })
  .catch(err => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
