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
const UPI = process.env.UPI_ID || "";
const PAYEE = process.env.UPI_PAYEE_NAME || "ADS GROWTH AGENCY";

if (
  !process.env.DATABASE_URL ||
  !SECRET ||
  SECRET.length < 32 ||
  !ADMIN ||
  ADMIN_PASS.length < 10
) {
  console.error("Set DATABASE_URL, JWT_SECRET (32+ chars), ADMIN_EMAIL and ADMIN_PASSWORD (10+ chars)");
  process.exit(1);
}

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false"
    ? false
    : { rejectUnauthorized: false },
  max: 5
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use("/api", rateLimit({
  windowMs: 60000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

const plans = [
  { id: "starter", name: "Starter", amount: 999, description: "All Click" },
  { id: "growth", name: "Growth", amount: 1499, description: "50% Click" },
  { id: "pro", name: "Pro", amount: 1999, description: "100% Click" }
];

const clean = (v, n = 500) =>
  String(v ?? "").trim().slice(0, n);

const color = v => /^#[0-9a-fA-F]{6}$/.test(v || "");

const slug = v =>
  clean(v, 60).toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "") || "page";

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

    ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS name TEXT;

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
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
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

    CREATE INDEX IF NOT EXISTS ag_click_idx
    ON ag_click_events(created_at);
  `);

  // Existing rows with a required name remain compatible.
  await db.query(`
    UPDATE ag_users
    SET name = 'Admin'
    WHERE email = $1 AND (name IS NULL OR name = '')
  `, [ADMIN]);

  const h = await bcrypt.hash(ADMIN_PASS, 12);

  await db.query(`
    INSERT INTO ag_users(name, email, password_hash, role)
    VALUES('Admin', $1, $2, 'admin')
    ON CONFLICT(email)
    DO UPDATE SET role = 'admin'
  `, [ADMIN, h]);

  console.log("Database initialized");
}

function auth(q, s, n) {
  try {
    const t = (q.headers.authorization || "").replace(/^Bearer /, "");
    q.user = jwt.verify(t, SECRET);
    n();
  } catch {
    s.status(401).json({ error: "Please login again" });
  }
}

function admin(q, s, n) {
  if (q.user.role !== "admin") {
    return s.status(403).json({ error: "Admin only" });
  }
  n();
}

async function paid(q, s, n) {
  if (q.user.role === "admin") return n();

  const r = await db.query(
    "SELECT 1 FROM ag_payments WHERE user_id=$1 AND status='approved'",
    [q.user.id]
  );

  if (!r.rowCount) {
    return s.status(403).json({ error: "Payment approval required" });
  }

  n();
}

const token = u => jwt.sign(
  { id: u.id, email: u.email, role: u.role },
  SECRET,
  { expiresIn: "7d" }
);

function upiLink(amount) {
  if (!UPI) return "";

  const params = new URLSearchParams({
    pa: UPI,
    pn: PAYEE,
    am: String(amount),
    cu: "INR"
  });

  return "upi://pay?" + params.toString();
}

app.get("/health", (q, s) => s.json({ ok: true }));

app.get("/api/config", (q, s) => {
  s.json({
    plans,
    upiId: UPI,
    payeeName: PAYEE,
    scannerUrl: "/scanner.png",
    paymentLinks: plans.map(p => ({
      planId: p.id,
      amount: p.amount,
      upiLink: upiLink(p.amount)
    }))
  });
});

// REGISTER
app.post("/api/register", async (q, s) => {
  try {
    const name = clean(q.body.name, 100);
    const email = clean(q.body.email, 254).toLowerCase();
    const pw = String(q.body.password || "");

    if (!name) {
      return s.status(400).json({ error: "Name is required" });
    }

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      pw.length < 8 ||
      pw.length > 72
    ) {
      return s.status(400).json({
        error: "Valid email and 8-72 character password required"
      });
    }

    const h = await bcrypt.hash(pw, 12);

    const r = await db.query(
      `INSERT INTO ag_users(name,email,password_hash)
       VALUES($1,$2,$3)
       RETURNING id,name,email,role`,
      [name, email, h]
    );

    s.status(201).json({
      token: token(r.rows[0]),
      user: r.rows[0]
    });
  } catch (e) {
    console.error("Register error:", e.message);
    s.status(e.code === "23505" ? 409 : 500).json({
      error: e.code === "23505"
        ? "Email already registered"
        : "Registration failed"
    });
  }
});

// LOGIN
app.post("/api/login", async (q, s) => {
  try {
    const r = await db.query(
      "SELECT * FROM ag_users WHERE email=$1",
      [clean(q.body.email, 254).toLowerCase()]
    );

    if (
      !r.rowCount ||
      !await bcrypt.compare(
        String(q.body.password || ""),
        r.rows[0].password_hash
      )
    ) {
      return s.status(401).json({ error: "Incorrect login" });
    }

    const u = r.rows[0];

    s.json({
      token: token(u),
      user: {
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.role
      }
    });
  } catch (e) {
    console.error("Login error:", e.message);
    s.status(500).json({ error: "Login failed" });
  }
});

// CURRENT USER
app.get("/api/me", auth, async (q, s) => {
  const r = await db.query(
    "SELECT id,name,email,role,created_at FROM ag_users WHERE id=$1",
    [q.user.id]
  );

  if (!r.rowCount) {
    return s.status(404).json({ error: "User not found" });
  }

  s.json({ user: r.rows[0] });
});

// USER PAYMENT HISTORY
app.get("/api/payments/mine", auth, async (q, s) => {
  const r = await db.query(
    "SELECT * FROM ag_payments WHERE user_id=$1 ORDER BY id DESC",
    [q.user.id]
  );

  s.json({ payments: r.rows });
});

// SUBMIT PAYMENT UTR
app.post("/api/payments", auth, async (q, s) => {
  const p = plans.find(x => x.id === q.body.planId);
  const utr = clean(q.body.utr, 80);

  if (!p || !/^[A-Za-z0-9-]{8,80}$/.test(utr)) {
    return s.status(400).json({
      error: "Choose a plan and enter a valid UTR"
    });
  }

  try {
    const r = await db.query(
      `INSERT INTO ag_payments(user_id,plan_id,amount,utr)
       VALUES($1,$2,$3,$4)
       RETURNING id,status,amount,plan_id`,
      [q.user.id, p.id, p.amount, utr]
    );

    s.status(201).json({
      payment: r.rows[0],
      message: "Payment submitted. Admin will verify it."
    });
  } catch (e) {
    s.status(409).json({
      error: "UTR already used or payment could not be saved"
    });
  }
});

// ADMIN STATS
app.get("/api/admin/stats", auth, admin, async (q, s) => {
  const [u, c, p] = await Promise.all([
    db.query(`
      SELECT COUNT(*)::int total,
      COUNT(*) FILTER(
        WHERE created_at > NOW()-INTERVAL '30 days'
      )::int last30
      FROM ag_users WHERE role='client'
    `),
    db.query(`
      SELECT
      COUNT(*) FILTER(
        WHERE event_type='click' AND NOT suspicious
      )::int valid_clicks,
      COUNT(DISTINCT visitor_hash)::int unique_visitors,
      COUNT(*) FILTER(WHERE suspicious)::int suspicious_events
      FROM ag_click_events
    `),
    db.query(`
      SELECT
      COUNT(*) FILTER(WHERE status='pending')::int pending,
      COUNT(*) FILTER(WHERE status='approved')::int approved
      FROM ag_payments
    `)
  ]);

  s.json({
    clients: u.rows[0],
    clicks: c.rows[0],
    payments: p.rows[0]
  });
});

// ADMIN PAYMENT LIST
app.get("/api/admin/payments", auth, admin, async (q, s) => {
  const r = await db.query(`
    SELECT p.*,u.name,u.email
    FROM ag_payments p
    JOIN ag_users u ON u.id=p.user_id
    ORDER BY p.id DESC LIMIT 200
  `);

  s.json({ payments: r.rows });
});

// ADMIN APPROVE / REJECT
app.post("/api/admin/payments/:id/review", auth, admin, async (q, s) => {
  if (!["approved", "rejected"].includes(q.body.status)) {
    return s.status(400).json({ error: "Invalid status" });
  }

  const r = await db.query(
    `UPDATE ag_payments
     SET status=$1,reviewed_at=NOW()
     WHERE id=$2
     RETURNING id,status`,
    [q.body.status, q.params.id]
  );

  if (!r.rowCount) {
    return s.status(404).json({ error: "Payment not found" });
  }

  s.json({ payment: r.rows[0] });
});

// ADMIN CLICK EVENTS
app.get("/api/admin/clicks", auth, admin, async (q, s) => {
  const r = await db.query(`
    SELECT e.*,p.slug
    FROM ag_click_events e
    LEFT JOIN ag_pages p ON p.id=e.page_id
    ORDER BY e.id DESC LIMIT 200
  `);

  s.json({ events: r.rows });
});

// LIST USER PAGES
app.get("/api/pages", auth, paid, async (q, s) => {
  const r = await db.query(
    "SELECT * FROM ag_pages WHERE user_id=$1 ORDER BY id DESC",
    [q.user.id]
  );

  s.json({ pages: r.rows });
});

// CREATE PAGE
app.post("/api/pages", auth, paid, async (q, s) => {
  const b = q.body;
  const cs = [
    b.bgColor || "#0b1224",
    b.textColor || "#ffffff",
    b.buttonColor || "#16a34a"
  ];

  if (!clean(b.title, 100) || !clean(b.headline, 180) || !cs.every(color)) {
    return s.status(400).json({
      error: "Title, headline and valid colors required"
    });
  }

  const r = await db.query(`
    INSERT INTO ag_pages(
      user_id,title,slug,headline,description,
      button_text,button_url,image_url,pixel_id,
      bg_color,text_color,button_color
    )
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
    RETURNING *
  `, [
    q.user.id,
    clean(b.title, 100),
    slug(b.title) + "-" + crypto.randomBytes(3).toString("hex"),
    clean(b.headline, 180),
    clean(b.description, 2000),
    clean(b.buttonText, 60) || "Get Started",
    clean(b.buttonUrl, 1000) || "#",
    clean(b.imageUrl, 1000),
    clean(b.pixelId, 20),
    ...cs
  ]);

  s.status(201).json({ page: r.rows[0] });
});

// UPDATE PAGE
app.put("/api/pages/:id", auth, paid, async (q, s) => {
  const b = q.body;
  const cs = [
    b.bgColor || "#0b1224",
    b.textColor || "#ffffff",
    b.buttonColor || "#16a34a"
  ];

  if (!cs.every(color)) {
    return s.status(400).json({ error: "Invalid color" });
  }

  const r = await db.query(`
    UPDATE ag_pages SET
      title=$1,headline=$2,description=$3,
      button_text=$4,button_url=$5,image_url=$6,
      pixel_id=$7,bg_color=$8,text_color=$9,button_color=$10
    WHERE id=$11 AND user_id=$12
    RETURNING *
  `, [
    clean(b.title, 100),
    clean(b.headline, 180),
    clean(b.description, 2000),
    clean(b.buttonText, 60),
    clean(b.buttonUrl, 1000),
    clean(b.imageUrl, 1000),
    clean(b.pixelId, 20),
    ...cs,
    q.params.id,
    q.user.id
  ]);

  if (!r.rowCount) {
    return s.status(404).json({ error: "Page not found" });
  }

  s.json({ page: r.rows[0] });
});

// PUBLISH PAGE
app.post("/api/pages/:id/publish", auth, paid, async (q, s) => {
  const r = await db.query(
    `UPDATE ag_pages SET published=NOT published
     WHERE id=$1 AND user_id=$2
     RETURNING slug,published`,
    [q.params.id, q.user.id]
  );

  if (!r.rowCount) {
    return s.status(404).json({ error: "Page not found" });
  }

  s.json({
    page: r.rows[0],
    url: `${q.protocol}://${q.get("host")}/p/${r.rows[0].slug}`
  });
});

// DELETE PAGE
app.delete("/api/pages/:id", auth, paid, async (q, s) => {
  await db.query(
    "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2",
    [q.params.id, q.user.id]
  );

  s.json({ deleted: true });
});

// TRACK EVENTS
app.post("/api/track/:slug", async (q, s) => {
  try {
    const p = await db.query(
      "SELECT id FROM ag_pages WHERE slug=$1 AND published=true",
      [q.params.slug]
    );

    if (!p.rowCount) {
      return s.status(404).json({ error: "Page not found" });
    }

    const v = clean(q.body.visitorId, 100);

    if (v.length < 10) {
      return s.status(400).json({ error: "Invalid visitor" });
    }

    const hash = crypto.createHash("sha256")
      .update(v + "|" + String(q.ip || "") + "|" + SECRET)
      .digest("hex");

    const type = q.body.eventType === "click" ? "click" : "pageview";

    const n = await db.query(
      `SELECT COUNT(*)::int n FROM ag_click_events
       WHERE page_id=$1 AND visitor_hash=$2
       AND created_at>NOW()-INTERVAL '1 minute'`,
      [p.rows[0].id, hash]
    );

    const bad = n.rows[0].n >= 15;

    await db.query(
      `INSERT INTO ag_click_events(
        page_id,visitor_hash,event_type,suspicious,reason
      ) VALUES($1,$2,$3,$4,$5)`,
      [
        p.rows[0].id,
        hash,
        type,
        bad,
        bad ? "High event frequency" : null
      ]
    );

    s.json({ recorded: !bad, flagged: bad });
  } catch (e) {
    s.status(500).json({ error: "Tracking failed" });
  }
});

// PUBLIC LANDING PAGE
app.get("/p/:slug", async (q, s) => {
  const r = await db.query(
    "SELECT * FROM ag_pages WHERE slug=$1 AND published=true",
    [q.params.slug]
  );

  if (!r.rowCount) {
    return s.status(404).send("Page not found");
  }

  const p = r.rows[0];

  const esc = x => String(x || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));

  const safeUrl = x =>
    /^https?:\/\//i.test(x || "") ? esc(x) : "#";

  const px = /^\d{5,20}$/.test(p.pixel_id || "")
    ? `<script>
      !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){
      n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
      if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];
      t=b.createElement(e);t.async=!0;t.src=v;
      s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}
      (window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
      fbq('init','${p.pixel_id}');fbq('track','PageView');
      </script>`
    : "";

  s.send(`<!doctype html>
  <html><head>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${esc(p.title)}</title>
  ${px}
  <style>
    body{margin:0;background:${p.bg_color};color:${p.text_color};font-family:Arial}
    .box{max-width:760px;margin:50px auto;padding:30px;text-align:center;
      background:#ffffff0d;border-radius:20px}
    h1{font-size:clamp(30px,7vw,52px)}
    p{line-height:1.7}
    img{max-width:100%;max-height:350px}
    .btn{display:inline-block;padding:15px 28px;border-radius:10px;
      background:${p.button_color};color:white;text-decoration:none;font-weight:bold}
  </style></head>
  <body><main class="box">
    <h1>${esc(p.headline)}</h1>
    <p>${esc(p.description)}</p>
    ${p.image_url ? `<img src="${safeUrl(p.image_url)}" alt="">` : ""}
    <p><a class="btn" href="${safeUrl(p.button_url)}">${esc(p.button_text)}</a></p>
  </main>
  <script>
    let v=localStorage.getItem("ag_vid");
    if(!v){
      v="v_"+(crypto.randomUUID?crypto.randomUUID():
        Math.random().toString(36).slice(2)+Date.now());
      localStorage.setItem("ag_vid",v);
    }
    const send=t=>fetch("/api/track/${encodeURIComponent(p.slug)}",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({visitorId:v,eventType:t})
    }).catch(()=>{});
    send("pageview");
    document.querySelector(".btn").addEventListener("click",()=>send("click"));
  </script></body></html>`);
});

// START SERVER
init().then(() => {
  app.listen(PORT, () => {
    console.log("ADS GROWTH AGENCY running on " + PORT);
  });
}).catch(e => {
  console.error("Startup error:", e);
  process.exit(1);
});
