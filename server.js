const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === "false" ? false : { rejectUnauthorized: false }
});

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const PLANS = {
  basic: { name: "Basic", price: 5, days: 30, pages: 1 },
  prime_pro: { name: "Prime Pro", price: 12, days: 30, pages: 2 },
  basic_prime: { name: "Basic & Prime", price: 15, days: 30, pages: 2 }
};

const sign = user => jwt.sign(
  { id: user.id, email: user.email, role: user.role },
  process.env.JWT_SECRET,
  { expiresIn: "7d" }
);

const auth = async (req, res, next) => {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    if (!token) return res.status(401).json({ error: "Please login." });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query(
      "SELECT id,email,role,plan,subscription_expires FROM ag_users WHERE id=$1",
      [decoded.id]
    );
    if (!result.rows[0]) return res.status(401).json({ error: "Account not found." });
    req.user = result.rows[0];
    next();
  } catch {
    res.status(401).json({ error: "Session expired. Please login again." });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access only." });
  }
  next();
};

const activeSubscription = (req, res, next) => {
  // Admin is always exempt from subscription checks.
  if (req.user.role === "admin") return next();

  if (!req.user.subscription_expires ||
      new Date(req.user.subscription_expires) <= new Date()) {
    return res.status(403).json({ error: "An active subscription is required." });
  }
  next();
};

const clean = value => String(value || "").trim();
const slugify = value =>
  clean(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")
  + "-" + Math.random().toString(36).slice(2, 7);

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      plan TEXT,
      subscription_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_pages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES ag_users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      headline TEXT,
      description TEXT,
      image_url TEXT,
      button_text TEXT DEFAULT 'Contact Us',
      button_url TEXT,
      whatsapp TEXT,
      pixel_id TEXT,
      primary_color TEXT DEFAULT '#16a34a',
      slug TEXT UNIQUE NOT NULL,
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES ag_users(id),
      plan TEXT NOT NULL,
      txid TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      admin_note TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_leads (
      id BIGSERIAL PRIMARY KEY,
      page_id BIGINT REFERENCES ag_pages(id) ON DELETE CASCADE,
      name TEXT,
      email TEXT,
      phone TEXT,
      message TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Create or refresh the Admin account from Render Environment variables.
  const email = clean(process.env.ADMIN_EMAIL).toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password || password.length < 8) {
    throw new Error("Set ADMIN_EMAIL and ADMIN_PASSWORD (minimum 8 characters) in Render Environment.");
  }

  const hash = await bcrypt.hash(password, 12);
  await pool.query(`
    INSERT INTO ag_users(name,email,password_hash,role)
    VALUES('Administrator',$1,$2,'admin')
    ON CONFLICT(email) DO UPDATE SET
      password_hash=EXCLUDED.password_hash,
      role='admin'
  `, [email, hash]);
}

app.get("/health", (req, res) => res.json({ status: "ok" }));

app.get("/api/config", (req, res) => {
  res.json({
    plans: PLANS,
    paymentAddress: process.env.USDT_TRC20_ADDRESS || ""
  });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = clean(req.body.name);
    const email = clean(req.body.email).toLowerCase();
    const password = String(req.body.password || "");
    if (!name || !email || password.length < 8) {
      return res.status(400).json({ error: "Name, valid email and 8-character password required." });
    }
    if (email === clean(process.env.ADMIN_EMAIL).toLowerCase()) {
      return res.status(403).json({ error: "This email is reserved for the administrator." });
    }
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO ag_users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email,role,plan,subscription_expires",
      [name, email, hash]
    );
    const user = result.rows[0];
    res.json({ token: sign(user), user });
  } catch (e) {
    res.status(400).json({ error: e.code === "23505" ? "Email already registered." : "Registration failed." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    const password = String(req.body.password || "");
    const result = await pool.query("SELECT * FROM ag_users WHERE email=$1", [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    res.json({
      token: sign(user),
      user: {
        id: user.id, name: user.name, email: user.email,
        role: user.role, plan: user.plan,
        subscription_expires: user.subscription_expires
      }
    });
  } catch {
    res.status(500).json({ error: "Login failed." });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const count = await pool.query("SELECT COUNT(*)::int AS count FROM ag_pages WHERE user_id=$1", [req.user.id]);
  res.json({
    user: req.user,
    pageCount: count.rows[0].count,
    pageLimit: req.user.role === "admin" ? 9999 :
      (PLANS[req.user.plan]?.pages || 0)
  });
});

app.get("/api/pages", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM ag_pages WHERE user_id=$1 ORDER BY id DESC", [req.user.id]
  );
  res.json({ pages: result.rows });
});

app.post("/api/pages", auth, activeSubscription, async (req, res) => {
  try {
    const count = await pool.query(
      "SELECT COUNT(*)::int AS count FROM ag_pages WHERE user_id=$1", [req.user.id]
    );
    const limit = req.user.role === "admin" ? 9999 : (PLANS[req.user.plan]?.pages || 0);
    if (count.rows[0].count >= limit) {
      return res.status(403).json({ error: "Your plan page limit has been reached." });
    }

    const b = req.body;
    if (!clean(b.title)) return res.status(400).json({ error: "Page title is required." });

    const result = await pool.query(`
      INSERT INTO ag_pages
      (user_id,title,headline,description,image_url,button_text,button_url,whatsapp,pixel_id,primary_color,slug)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *
    `, [
      req.user.id, clean(b.title), clean(b.headline), clean(b.description),
      clean(b.image_url), clean(b.button_text) || "Contact Us",
      clean(b.button_url), clean(b.whatsapp), clean(b.pixel_id),
      /^#[0-9a-fA-F]{6}$/.test(b.primary_color) ? b.primary_color : "#16a34a",
      slugify(b.title)
    ]);
    res.json({ page: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not create page." });
  }
});

app.post("/api/pages/:id/publish", auth, activeSubscription, async (req, res) => {
  const result = await pool.query(
    "UPDATE ag_pages SET published=NOT published WHERE id=$1 AND user_id=$2 RETURNING *",
    [req.params.id, req.user.id]
  );
  if (!result.rows[0]) return res.status(404).json({ error: "Page not found." });
  res.json({ page: result.rows[0], url: `${req.protocol}://${req.get("host")}/p/${result.rows[0].slug}` });
});

app.delete("/api/pages/:id", auth, async (req, res) => {
  const result = await pool.query(
    "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2 RETURNING id",
    [req.params.id, req.user.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Page not found." });
  res.json({ message: "Page deleted." });
});

app.post("/api/payments", auth, async (req, res) => {
  const plan = PLANS[req.body.plan_id];
  const txid = clean(req.body.txid);
  if (!plan || txid.length < 8) {
    return res.status(400).json({ error: "Choose a plan and enter a valid transaction ID." });
  }
  const result = await pool.query(
    "INSERT INTO ag_payments(user_id,plan,txid) VALUES($1,$2,$3) RETURNING *",
    [req.user.id, req.body.plan_id, txid]
  );
  res.json({ payment: result.rows[0], message: "Payment submitted for manual review." });
});

app.get("/api/payments", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM ag_payments WHERE user_id=$1 ORDER BY id DESC", [req.user.id]
  );
  res.json({ payments: result.rows });
});

app.get("/api/admin/stats", auth, adminOnly, async (req, res) => {
  const [users, pages, payments, leads] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS n FROM ag_users WHERE role='user'"),
    pool.query("SELECT COUNT(*)::int AS n FROM ag_pages"),
    pool.query("SELECT COUNT(*)::int AS n FROM ag_payments WHERE status='pending'"),
    pool.query("SELECT COUNT(*)::int AS n FROM ag_leads")
  ]);
  res.json({
    users: users.rows[0].n, pages: pages.rows[0].n,
    pendingPayments: payments.rows[0].n, leads: leads.rows[0].n
  });
});

app.get("/api/admin/payments", auth, adminOnly, async (req, res) => {
  const result = await pool.query(`
    SELECT p.*,u.name,u.email FROM ag_payments p
    JOIN ag_users u ON u.id=p.user_id ORDER BY p.id DESC
  `);
  res.json({ payments: result.rows });
});

app.get("/api/admin/leads", auth, adminOnly, async (req, res) => {
  const result = await pool.query(`
    SELECT l.*,p.title AS page_title FROM ag_leads l
    JOIN ag_pages p ON p.id=l.page_id ORDER BY l.id DESC
  `);
  res.json({ leads: result.rows });
});

app.post("/api/admin/payments/:id/review", auth, adminOnly, async (req, res) => {
  const status = req.body.status;
  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid review status." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const found = await client.query(
      "SELECT * FROM ag_payments WHERE id=$1 FOR UPDATE", [req.params.id]
    );
    const payment = found.rows[0];
    if (!payment || payment.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Pending payment not found." });
    }

    await client.query(
      "UPDATE ag_payments SET status=$1,admin_note=$2 WHERE id=$3",
      [status, clean(req.body.admin_note), payment.id]
    );

    if (status === "approved") {
      const plan = PLANS[payment.plan];
      if (!plan) throw new Error("Unknown plan.");
      await client.query(`
        UPDATE ag_users SET plan=$1,
        subscription_expires=GREATEST(COALESCE(subscription_expires,NOW()),NOW()) + ($2 * INTERVAL '1 day')
        WHERE id=$3
      `, [payment.plan, plan.days, payment.user_id]);
    }
    await client.query("COMMIT");
    res.json({ message: "Payment " + status + "." });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    res.status(500).json({ error: "Payment review failed." });
  } finally {
    client.release();
  }
});

const escapeHtml = value => String(value || "").replace(/[&<>"']/g, c => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));

app.get("/p/:slug", async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM ag_pages WHERE slug=$1 AND published=TRUE", [req.params.slug]
  );
  const p = result.rows[0];
  if (!p) return res.status(404).send("Page not found.");
  res.type("html").send(`<!doctype html><html><head>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escapeHtml(p.title)}</title>
    ${p.pixel_id ? `<!-- Meta Pixel ID configured: ${escapeHtml(p.pixel_id)} -->` : ""}
    </head><body style="font-family:Arial;text-align:center;padding:30px;background:#101827;color:white">
    <h1>${escapeHtml(p.headline || p.title)}</h1><p>${escapeHtml(p.description)}</p>
    ${p.image_url ? `<img src="${escapeHtml(p.image_url)}" style="max-width:100%;max-height:420px">` : ""}
    <p><a style="display:inline-block;padding:14px 24px;background:${escapeHtml(p.primary_color)};color:white;border-radius:8px;text-decoration:none" href="${escapeHtml(p.button_url)}">${escapeHtml(p.button_text)}</a></p>
    ${p.whatsapp ? `<p><a href="https://wa.me/${encodeURIComponent(p.whatsapp.replace(/\D/g,""))}">WhatsApp</a></p>` : ""}
    <hr><h3>Contact Us</h3><form method="post" action="/p/${encodeURIComponent(p.slug)}/lead">
    <input name="name" placeholder="Your name" required><br><br>
    <input name="email" type="email" placeholder="Email"><br><br>
    <input name="phone" placeholder="Phone"><br><br>
    <textarea name="message" placeholder="Message"></textarea><br><br>
    <button>Submit</button></form></body></html>`);
});

app.post("/p/:slug/lead", async (req, res) => {
  const page = await pool.query(
    "SELECT id FROM ag_pages WHERE slug=$1 AND published=TRUE", [req.params.slug]
  );
  if (!page.rows[0]) return res.status(404).send("Page not found.");
  await pool.query(
    "INSERT INTO ag_leads(page_id,name,email,phone,message) VALUES($1,$2,$3,$4,$5)",
    [page.rows[0].id, clean(req.body.name), clean(req.body.email),
     clean(req.body.phone), clean(req.body.message)]
  );
  res.send("Thank you! Your details have been submitted.");
});

app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Server error. Please try again." });
});

async function start() {
  if (!process.env.DATABASE_URL || !process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    throw new Error("Set DATABASE_URL and JWT_SECRET (minimum 32 characters) in Render.");
  }
  await initDatabase();
  app.listen(PORT, () => console.log("ADS GROWTH server running on " + PORT));
}
start().catch(e => {
  console.error("Startup failed:", e);
  process.exit(1);
});
  
