const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;
const ADMIN = String(process.env.ADMIN_EMAIL || "").toLowerCase();
const ADMIN_PASS = process.env.ADMIN_PASSWORD || "";
const UPI = process.env.UPI_ID || "your-upi-id@bank";

if (!process.env.DATABASE_URL || !SECRET || SECRET.length < 32 || !ADMIN || ADMIN_PASS.length < 10) {
  console.error("Set DATABASE_URL, JWT_SECRET, ADMIN_EMAIL and ADMIN_PASSWORD");
  process.exit(1);
}

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false" ? false : { rejectUnauthorized: false }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api", rateLimit({ windowMs: 60000, limit: 100 }));

const plans = [
  { id: "starter", name: "Starter", amount: 999, description: "All Click" },
  { id: "growth", name: "Growth", amount: 1499, description: "50% Click" },
  { id: "pro", name: "Pro", amount: 1999, description: "100% Click" }
];

async function init() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'client',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_pages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES ag_users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      headline TEXT NOT NULL,
      description TEXT DEFAULT '',
      button_text TEXT DEFAULT 'Get Started',
      button_url TEXT DEFAULT '#',
      image_url TEXT DEFAULT '',
      pixel_id TEXT DEFAULT '',
      bg_color TEXT DEFAULT '#0b1224',
      text_color TEXT DEFAULT '#ffffff',
      button_color TEXT DEFAULT '#16a34a',
      design_template TEXT NOT NULL DEFAULT 'classic',
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS design_template TEXT NOT NULL DEFAULT 'classic';

    CREATE TABLE IF NOT EXISTS ag_payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES ag_users(id) ON DELETE CASCADE,
      plan_id TEXT NOT NULL,
      amount INT NOT NULL,
      utr TEXT UNIQUE NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ag_click_events (
      id BIGSERIAL PRIMARY KEY,
      page_id BIGINT REFERENCES ag_pages(id) ON DELETE CASCADE,
      visitor_hash TEXT NOT NULL,
      event_type TEXT NOT NULL,
      suspicious BOOLEAN DEFAULT FALSE,
      reason TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS ag_click_idx ON ag_click_events(created_at);
  `);

  const hash = await bcrypt.hash(ADMIN_PASS, 12);
  await db.query(
    `INSERT INTO ag_users(name,email,password_hash,role)
     VALUES('Admin',$1,$2,'admin')
     ON CONFLICT(email) DO UPDATE SET role='admin'`,
    [ADMIN, hash]
  );
}

function clean(value, max = 500) {
  return String(value ?? "").trim().slice(0, max);
}

function validColor(value) {
  return /^#[0-9a-fA-F]{6}$/.test(value || "");
}

function makeSlug(value) {
  return clean(value, 60).toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "") || "page";
}

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer /, "");
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Please login again" });
  }
}

function admin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin only" });
  }
  next();
}

async function paid(req, res, next) {
  if (req.user.role === "admin") return next();

  const result = await db.query(
    "SELECT 1 FROM ag_payments WHERE user_id=$1 AND status='approved'",
    [req.user.id]
  );

  if (!result.rowCount) {
    return res.status(403).json({ error: "Payment approval required" });
  }
  next();
}

function makeToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    SECRET,
    { expiresIn: "7d" }
  );
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/api/config", (req, res) => {
  res.json({
    plans,
    upiId: UPI,
    payeeName: process.env.UPI_PAYEE_NAME || "ADS GROWTH AGENCY"
  });
});

app.post("/api/register", async (req, res) => {
  try {
    const name = clean(req.body.name, 100);
    const email = clean(req.body.email, 254).toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        password.length < 8 || password.length > 72) {
      return res.status(400).json({ error: "Enter valid name, email and password" });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await db.query(
      `INSERT INTO ag_users(name,email,password_hash)
       VALUES($1,$2,$3) RETURNING id,email,role`,
      [name, email, hash]
    );

    res.status(201).json({
      token: makeToken(result.rows[0]),
      user: result.rows[0]
    });
  } catch (error) {
    res.status(error.code === "23505" ? 409 : 500).json({
      error: error.code === "23505" ? "Email already registered" : "Registration failed"
    });
  }
});

app.post("/api/login", async (req, res) => {
  const result = await db.query(
    "SELECT * FROM ag_users WHERE email=$1",
    [clean(req.body.email, 254).toLowerCase()]
  );

  if (!result.rowCount ||
      !await bcrypt.compare(String(req.body.password || ""), result.rows[0].password_hash)) {
    return res.status(401).json({ error: "Incorrect login" });
  }

  const user = result.rows[0];
  res.json({
    token: makeToken(user),
    user: { id: user.id, email: user.email, role: user.role }
  });
});

app.get("/api/me", auth, async (req, res) => {
  const result = await db.query(
    "SELECT id,email,role,created_at FROM ag_users WHERE id=$1",
    [req.user.id]
  );
  res.json({ user: result.rows[0] });
});

app.get("/api/payments/mine", auth, async (req, res) => {
  const result = await db.query(
    "SELECT * FROM ag_payments WHERE user_id=$1 ORDER BY id DESC",
    [req.user.id]
  );
  res.json({ payments: result.rows });
});

app.post("/api/payments", auth, async (req, res) => {
  const plan = plans.find(p => p.id === req.body.planId);
  const utr = clean(req.body.utr, 80);

  if (!plan || !/^[A-Za-z0-9-]{8,80}$/.test(utr)) {
    return res.status(400).json({ error: "Choose plan and enter valid UTR" });
  }

  try {
    const result = await db.query(
      `INSERT INTO ag_payments(user_id,plan_id,amount,utr)
       VALUES($1,$2,$3,$4) RETURNING id,status`,
      [req.user.id, plan.id, plan.amount, utr]
    );
    res.status(201).json({ payment: result.rows[0], message: "Payment submitted for verification" });
  } catch {
    res.status(409).json({ error: "UTR already used or payment could not be saved" });
  }
});

app.get("/api/admin/stats", auth, admin, async (req, res) => {
  const users = await db.query(
    "SELECT COUNT(*)::int total FROM ag_users WHERE role='client'"
  );
  const clicks = await db.query(
    `SELECT COUNT(*) FILTER(WHERE event_type='click' AND NOT suspicious)::int valid_clicks,
     COUNT(DISTINCT visitor_hash)::int unique_visitors,
     COUNT(*) FILTER(WHERE suspicious)::int suspicious_events
     FROM ag_click_events`
  );
  const payments = await db.query(
    `SELECT COUNT(*) FILTER(WHERE status='pending')::int pending,
     COUNT(*) FILTER(WHERE status='approved')::int approved FROM ag_payments`
  );

  res.json({
    clients: users.rows[0],
    clicks: clicks.rows[0],
    payments: payments.rows[0]
  });
});

app.get("/api/admin/payments", auth, admin, async (req, res) => {
  const result = await db.query(
    `SELECT p.*,u.email FROM ag_payments p
     JOIN ag_users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 200`
  );
  res.json({ payments: result.rows });
});

app.post("/api/admin/payments/:id/review", auth, admin, async (req, res) => {
  if (!["approved", "rejected"].includes(req.body.status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  const result = await db.query(
    "UPDATE ag_payments SET status=$1,reviewed_at=NOW() WHERE id=$2 RETURNING id,status",
    [req.body.status, req.params.id]
  );

  if (!result.rowCount) return res.status(404).json({ error: "Not found" });
  res.json({ payment: result.rows[0] });
});

app.get("/api/admin/clicks", auth, admin, async (req, res) => {
  const result = await db.query(
    `SELECT e.*,p.slug FROM ag_click_events e
     LEFT JOIN ag_pages p ON p.id=e.page_id ORDER BY e.id DESC LIMIT 200`
  );
  res.json({ events: result.rows });
});

app.get("/api/pages", auth, paid, async (req, res) => {
  const result = await db.query(
    "SELECT * FROM ag_pages WHERE user_id=$1 ORDER BY id DESC",
    [req.user.id]
  );
  res.json({ pages: result.rows });
});

app.post("/api/pages", auth, paid, async (req, res) => {
  const b = req.body;
  const colors = [
    b.bgColor || "#0b1224",
    b.textColor || "#ffffff",
    b.buttonColor || "#16a34a"
  ];

  if (!clean(b.title, 100) || !clean(b.headline, 180) || !colors.every(validColor)) {
    return res.status(400).json({ error: "Title, headline and valid colors required" });
  }

  const result = await db.query(
    `INSERT INTO ag_pages
     (user_id,title,slug,headline,description,button_text,button_url,image_url,
      pixel_id,bg_color,text_color,button_color,design_template)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
    [
      req.user.id, clean(b.title, 100),
      makeSlug(b.title) + "-" + crypto.randomBytes(3).toString("hex"),
      clean(b.headline, 180), clean(b.description, 2000),
      clean(b.buttonText, 60) || "Get Started",
      clean(b.buttonUrl, 1000) || "#",
      clean(b.imageUrl, 1000), clean(b.pixelId, 20),
      ...colors, clean(b.designTemplate, 30) || "classic"
    ]
  );

  res.status(201).json({ page: result.rows[0] });
});

app.put("/api/pages/:id", auth, paid, async (req, res) => {
  const b = req.body;
  const colors = [
    b.bgColor || "#0b1224",
    b.textColor || "#ffffff",
    b.buttonColor || "#16a34a"
  ];

  if (!colors.every(validColor)) {
    return res.status(400).json({ error: "Invalid color" });
  }

  const result = await db.query(
    `UPDATE ag_pages SET title=$1,headline=$2,description=$3,
     button_text=$4,button_url=$5,image_url=$6,pixel_id=$7,
     bg_color=$8,text_color=$9,button_color=$10,design_template=$11
     WHERE id=$12 AND user_id=$13 RETURNING *`,
    [
      clean(b.title, 100), clean(b.headline, 180),
      clean(b.description, 2000), clean(b.buttonText, 60),
      clean(b.buttonUrl, 1000), clean(b.imageUrl, 1000),
      clean(b.pixelId, 20), ...colors,
      clean(b.designTemplate, 30) || "classic",
      req.params.id, req.user.id
    ]
  );

  if (!result.rowCount) return res.status(404).json({ error: "Page not found" });
  res.json({ page: result.rows[0] });
});

app.post("/api/pages/:id/publish", auth, paid, async (req, res) => {
  const result = await db.query(
    "UPDATE ag_pages SET published=NOT published WHERE id=$1 AND user_id=$2 RETURNING slug,published",
    [req.params.id, req.user.id]
  );

  if (!result.rowCount) return res.status(404).json({ error: "Page not found" });

  res.json({
    page: result.rows[0],
    url: `${req.protocol}://${req.get("host")}/p/${result.rows[0].slug}`
  });
});

app.delete("/api/pages/:id", auth, paid, async (req, res) => {
  await db.query(
    "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2",
    [req.params.id, req.user.id]
  );
  res.json({ deleted: true });
});

app.post("/api/track/:slug", async (req, res) => {
  try {
    const page = await db.query(
      "SELECT id FROM ag_pages WHERE slug=$1 AND published=true",
      [req.params.slug]
    );

    if (!page.rowCount) return res.status(404).json({ error: "Page not found" });

    const visitor = clean(req.body.visitorId, 100);
    if (visitor.length < 10) return res.status(400).json({ error: "Invalid visitor" });

    const hash = crypto.createHash("sha256")
      .update(visitor + "|" + req.ip + "|" + SECRET).digest("hex");

    const type = req.body.eventType === "click" ? "click" : "pageview";

    const count = await db.query(
      `SELECT COUNT(*)::int n FROM ag_click_events
       WHERE page_id=$1 AND visitor_hash=$2
       AND created_at>NOW()-INTERVAL '1 minute'`,
      [page.rows[0].id, hash]
    );

    const suspicious = count.rows[0].n >= 15;

    await db.query(
      `INSERT INTO ag_click_events(page_id,visitor_hash,event_type,suspicious,reason)
       VALUES($1,$2,$3,$4,$5)`,
      [page.rows[0].id, hash, type, suspicious, suspicious ? "High event frequency" : null]
    );

    res.json({ recorded: !suspicious, flagged: suspicious });
  } catch {
    res.status(500).json({ error: "Tracking failed" });
  }
});

app.get("/p/:slug", async (req, res) => {
  const result = await db.query(
    "SELECT * FROM ag_pages WHERE slug=$1 AND published=true",
    [req.params.slug]
  );

  if (!result.rowCount) return res.status(404).send("Page not found");

  const p = result.rows[0];

  const esc = value => String(value || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));

  const safeUrl = value =>
    /^https?:\/\//i.test(value || "") ? esc(value) : "#";

  const design = ["classic", "neon", "gold", "green", "white", "red", "purple"]
    .includes(p.design_template) ? p.design_template : "classic";

  const pixel = /^\d{5,20}$/.test(p.pixel_id || "") ? `
    <script>
    !function(f,b,e,v,n,t,s){
      if(f.fbq)return;n=f.fbq=function(){n.callMethod?
      n.callMethod.apply(n,arguments):n.queue.push(arguments)};
      if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
      n.queue=[];t=b.createElement(e);t.async=!0;
      t.src=v;s=b.getElementsByTagName(e)[0];
      s.parentNode.insertBefore(t,s)
    }(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
    fbq('init','${esc(p.pixel_id)}');fbq('track','PageView');
    </script>` : "";

  res.send(`<!doctype html>
  <html><head>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${esc(p.title)}</title>
  ${pixel}
  <style>
  body{margin:0;background:${p.bg_color};color:${p.text_color};font-family:Arial}
  .box{max-width:760px;margin:50px auto;padding:30px;text-align:center;background:#ffffff0d;border-radius:20px;border:1px solid #ffffff22}
  h1{font-size:clamp(30px,7vw,52px)}
  p{line-height:1.7}
  img{max-width:100%;max-height:350px}
  .btn{display:inline-block;padding:15px 28px;border-radius:10px;background:${p.button_color};color:white;text-decoration:none;font-weight:bold}
  .design-neon{background:radial-gradient(circle at top,#153c70,#050b19);border:1px solid #00caff;box-shadow:0 0 28px #00aaff55}
  .design-gold{background:linear-gradient(145deg,#17120a,#30220d);border:1px solid #d6ad55}
  .design-green{background:linear-gradient(145deg,#062c20,#071b18);border:1px solid #28d69a}
  .design-white{background:#f7f9fc;color:#172033;border:1px solid #dce3ee}
  .design-white p{color:#45546b}
  .design-red{background:linear-gradient(145deg,#310b14,#17070c);border:1px solid #ff4c65}
  .design-purple{background:linear-gradient(145deg,#241044,#0d0920);border:1px solid #b77aff}
  </style></head>
  <body>
  <main class="box design-${design}">
  <h1>${esc(p.headline)}</h1>
  <p>${esc(p.description)}</p>
  ${p.image_url ? `<img src="${safeUrl(p.image_url)}" alt="">` : ""}
  <p><a class="btn" href="${safeUrl(p.button_url)}">${esc(p.button_text)}</a></p>
  </main>
  <script>
  let v=localStorage.getItem("ag_vid");
  if(!v){
    v="v_"+(crypto.randomUUID?crypto.randomUUID():Math.random().toString(36).slice(2)+Date.now());
    localStorage.setItem("ag_vid",v);
  }
  const send=t=>fetch("/api/track/${encodeURIComponent(p.slug)}",{
    method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({visitorId:v,eventType:t})
  }).catch(()=>{});
  send("pageview");
  document.querySelector(".btn").addEventListener("click",()=>send("click"));
  </script></body></html>`);
});

init().then(() => {
  app.listen(PORT, () => console.log("ADS GROWTH AGENCY running on " + PORT));
}).catch(error => {
  console.error(error);
  process.exit(1);
});
