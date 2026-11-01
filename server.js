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

app.set("trust proxy", 1);

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
  limit: 250,
  standardHeaders: true,
  legacyHeaders: false
}));

const plans = {
  basic: { name: "Basic", price: 5, pages: 1 },
  prime: { name: "Prime & Pro", price: 12, pages: 1 },
  premium: { name: "Basic & Prime", price: 15, pages: 2 }
};

/* DATABASE SETUP AND MIGRATIONS */

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

    CREATE INDEX IF NOT EXISTS pages_user_idx
    ON pages(user_id);

    CREATE INDEX IF NOT EXISTS events_page_idx
    ON events(page_id);
  `);

  // Add design columns to existing databases safely.
  await pool.query(`
    ALTER TABLE pages
    ADD COLUMN IF NOT EXISTS background_color TEXT DEFAULT '#ffffff';

    ALTER TABLE pages
    ADD COLUMN IF NOT EXISTS heading_color TEXT DEFAULT '#171717';

    ALTER TABLE pages
    ADD COLUMN IF NOT EXISTS button_color TEXT DEFAULT '#22c55e';

    ALTER TABLE pages
    ADD COLUMN IF NOT EXISTS image_size INTEGER DEFAULT 100;
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

/* HELPERS */

function createToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function safeColor(value, fallback) {
  const color = String(value || "").trim();

  return /^#[0-9a-fA-F]{6}$/.test(color)
    ? color
    : fallback;
}

function safeImageUrl(value) {
  try {
    const url = new URL(String(value || ""));

    if (url.protocol === "http:" || url.protocol === "https:") {
      return url.toString();
    }
  } catch (error) {}

  return "";
}

function safeButtonUrl(value) {
  try {
    const url = new URL(String(value || ""));

    if (url.protocol === "http:" || url.protocol === "https:") {
      return url.toString();
    }
  } catch (error) {}

  return "#";
}

function safeImageSize(value) {
  const size = Number(value);

  if (!Number.isFinite(size)) return 100;

  return Math.min(400, Math.max(50, Math.round(size)));
}

function makeSlug() {
  return crypto.randomBytes(8).toString("hex");
}

function isAdmin(user) {
  return user.role === "admin";
}

function hasActiveSubscription(user) {
  return user.subscription_expires &&
    new Date(user.subscription_expires).getTime() > Date.now();
}

/* AUTHENTICATION */

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({
        error: "Please login first"
      });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    const result = await pool.query(
      `SELECT id, name, email, role, plan, subscription_expires
       FROM users WHERE id=$1`,
      [decoded.id]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Account not found"
      });
    }

    req.user = result.rows[0];
    next();

  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired login"
    });
  }
}

/* PAGE LIMIT */

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

/* HEALTH */

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected"
    });

  } catch (error) {
    res.status(503).json({
      status: "error",
      database: "disconnected"
    });
  }
});

/* PLANS */

app.get("/api/plans", (req, res) => {
  res.json(plans);
});

/* REGISTER */

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    if (
      !name ||
      !email ||
      !password ||
      String(password).length < 8
    ) {
      return res.status(400).json({
        error: "Name, valid email and password of at least 8 characters required"
      });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({
        error: "Please enter a valid email"
      });
    }

    if (
      normalizedEmail ===
      process.env.ADMIN_EMAIL.toLowerCase().trim()
    ) {
      return res.status(403).json({
        error: "This email is reserved for admin"
      });
    }

    const hash = await bcrypt.hash(String(password), 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, password)
       VALUES ($1, $2, $3)
       RETURNING id, name, email, role, plan, subscription_expires`,
      [
        String(name).trim(),
        normalizedEmail,
        hash
      ]
    );

    const user = result.rows[0];

    res.status(201).json({
      user,
      token: createToken(user)
    });

  } catch (error) {
    console.error("Registration error:", error);

    res.status(400).json({
      error: error.code === "23505"
        ? "Email already registered"
        : "Registration failed"
    });
  }
});

/* LOGIN */

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .toLowerCase()
      .trim();

    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (
      !result.rows.length ||
      !(await bcrypt.compare(password, result.rows[0].password))
    ) {
      return res.status(401).json({
        error: "Incorrect email or password"
      });
    }

    const user = result.rows[0];

    delete user.password;

    res.json({
      user,
      token: createToken(user)
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

/* CURRENT USER */

app.get("/api/me", auth, (req, res) => {
  res.json({
    user: req.user,
    isAdmin: isAdmin(req.user),
    subscriptionActive:
      isAdmin(req.user) || hasActiveSubscription(req.user)
  });
});

/* GET USER PAGES */

app.get("/api/pages", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM pages
       WHERE user_id=$1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load pages"
    });
  }
});

/* CREATE PAGE WITH DESIGN SETTINGS */

app.post("/api/pages", auth, async (req, res) => {
  try {
    if (!(await canCreatePage(req.user))) {
      return res.status(403).json({
        error: "Active subscription required or page limit reached"
      });
    }

    const {
      title,
      headline,
      description,
      image_url,
      button_text,
      button_url,
      whatsapp,
      pixel_id
    } = req.body || {};

    if (!title || !String(title).trim()) {
      return res.status(400).json({
        error: "Page title is required"
      });
    }

    const backgroundColor = safeColor(
      req.body.background_color,
      "#ffffff"
    );

    const headingColor = safeColor(
      req.body.heading_color,
      "#171717"
    );

    const buttonColor = safeColor(
      req.body.button_color,
      "#22c55e"
    );

    const imageSize = safeImageSize(
      req.body.image_size
    );

    const imageUrl = safeImageUrl(image_url);

    const result = await pool.query(
      `INSERT INTO pages (
        user_id,
        title,
        slug,
        headline,
        description,
        image_url,
        button_text,
        button_url,
        whatsapp,
        pixel_id,
        background_color,
        heading_color,
        button_color,
        image_size
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
      )
      RETURNING *`,
      [
        req.user.id,
        String(title).trim(),
        makeSlug(),
        String(headline || ""),
        String(description || ""),
        imageUrl,
        String(button_text || "Learn More"),
        safeButtonUrl(button_url),
        String(whatsapp || "").replace(/\D/g, "").slice(0, 20),
        /^\d+$/.test(String(pixel_id || "")) ? String(pixel_id) : "",
        backgroundColor,
        headingColor,
        buttonColor,
        imageSize
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("Create page error:", error);

    res.status(500).json({
      error: "Could not save page"
    });
  }
});

/* EDIT PAGE */

app.put("/api/pages/:id", auth, async (req, res) => {
  try {
    const {
      title,
      headline,
      description,
      image_url,
      button_text,
      button_url,
      whatsapp,
      pixel_id
    } = req.body || {};

    if (!title || !String(title).trim()) {
      return res.status(400).json({
        error: "Page title is required"
      });
    }

    const result = await pool.query(
      `UPDATE pages SET
        title=$1,
        headline=$2,
        description=$3,
        image_url=$4,
        button_text=$5,
        button_url=$6,
        whatsapp=$7,
        pixel_id=$8,
        background_color=$9,
        heading_color=$10,
        button_color=$11,
        image_size=$12
       WHERE id=$13 AND user_id=$14
       RETURNING *`,
      [
        String(title).trim(),
        String(headline || ""),
        String(description || ""),
        safeImageUrl(image_url),
        String(button_text || "Learn More"),
        safeButtonUrl(button_url),
        String(whatsapp || "").replace(/\D/g, "").slice(0, 20),
        /^\d+$/.test(String(pixel_id || "")) ? String(pixel_id) : "",
        safeColor(req.body.background_color, "#ffffff"),
        safeColor(req.body.heading_color, "#171717"),
        safeColor(req.body.button_color, "#22c55e"),
        safeImageSize(req.body.image_size),
        req.params.id,
        req.user.id
      ]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Page not found"
      });
    }

    res.json(result.rows[0]);

  } catch (error) {
    console.error("Update page error:", error);

    res.status(500).json({
      error: "Could not update page"
    });
  }
});

/* PUBLISH PAGE */

app.post("/api/pages/:id/publish", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE pages SET published=TRUE
       WHERE id=$1 AND user_id=$2
       RETURNING *`,
      [req.params.id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Page not found"
      });
    }

    const page = result.rows[0];

    const url = `${req.protocol}://${req.get("host")}/p/${page.slug}`;

    res.json({
      message: "Page published successfully",
      url,
      page
    });

  } catch (error) {
    console.error("Publish error:", error);

    res.status(500).json({
      error: "Could not publish page"
    });
  }
});

/* DELETE PAGE */

app.delete("/api/pages/:id", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM pages
       WHERE id=$1 AND user_id=$2
       RETURNING id`,
      [req.params.id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Page not found"
      });
    }

    res.json({
      message: "Page deleted"
    });

  } catch (error) {
    console.error("Delete error:", error);

    res.status(500).json({
      error: "Could not delete page"
    });
  }
});

/* ADMIN OVERVIEW */

app.get("/api/admin/overview", auth, async (req, res) => {
  try {
    if (!isAdmin(req.user)) {
      return res.status(403).json({
        error: "Admin only"
      });
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
      events: events.rows[0].total,
      leads: 0
    });

  } catch (error) {
    console.error("Admin overview error:", error);

    res.status(500).json({
      error: "Could not load admin overview"
    });
  }
});

/* PUBLIC ANALYTICS EVENTS */

app.post("/api/events/:id/:type", async (req, res) => {
  try {
    const allowed = ["visit", "click"];

    if (!allowed.includes(req.params.type)) {
      return res.status(400).json({
        error: "Invalid event"
      });
    }

    const page = await pool.query(
      "SELECT id FROM pages WHERE id=$1 AND published=TRUE",
      [req.params.id]
    );

    if (!page.rows.length) {
      return res.status(404).json({
        error: "Page not found"
      });
    }

    await pool.query(
      `INSERT INTO events (page_id, event_type)
       VALUES ($1,$2)`,
      [req.params.id, req.params.type]
    );

    res.json({ ok: true });

  } catch (error) {
    console.error("Event error:", error);

    res.status(500).json({
      error: "Could not record event"
    });
  }
});

/* PAGE ANALYTICS */

app.get("/api/pages/:id/analytics", auth, async (req, res) => {
  try {
    const page = await pool.query(
      `SELECT id FROM pages
       WHERE id=$1 AND user_id=$2`,
      [req.params.id, req.user.id]
    );

    if (!page.rows.length) {
      return res.status(404).json({
        error: "Page not found"
      });
    }

    const result = await pool.query(
      `SELECT event_type, COUNT(*)::int AS total
       FROM events
       WHERE page_id=$1
       GROUP BY event_type`,
      [req.params.id]
    );

    const counts = {
      visits: 0,
      clicks: 0
    };

    for (const row of result.rows) {
      if (row.event_type === "visit") {
        counts.visits = row.total;
      }

      if (row.event_type === "click") {
        counts.clicks = row.total;
      }
    }

    res.json(counts);

  } catch (error) {
    console.error("Analytics error:", error);

    res.status(500).json({
      error: "Could not load analytics"
    });
  }
});

/* PUBLIC LANDING PAGE */

app.get("/p/:slug", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM pages
       WHERE slug=$1 AND published=TRUE`,
      [req.params.slug]
    );

    if (!result.rows.length) {
      return res.status(404).send("Page not found");
    }

    const p = result.rows[0];

    await pool.query(
      `INSERT INTO events (page_id,event_type)
       VALUES ($1,'visit')`,
      [p.id]
    );

    // Validate design settings before rendering.
    const backgroundColor = safeColor(
      p.background_color,
      "#ffffff"
    );

    const headingColor = safeColor(
      p.heading_color,
      "#171717"
    );

    const buttonColor = safeColor(
      p.button_color,
      "#22c55e"
    );

    const imageSize = safeImageSize(p.image_size);

    const imageUrl = safeImageUrl(p.image_url);

    const image = imageUrl
      ? `<img
          src="${escapeHtml(imageUrl)}"
          alt="Landing page image"
          style="
            width:${imageSize}px;
            height:${imageSize}px;
            max-width:100%;
            object-fit:contain;
            display:block;
            margin:15px auto;
            border-radius:12px;
          "
        >`
      : "";

    const buttonUrl = p.whatsapp
      ? `https://wa.me/${String(p.whatsapp).replace(/\D/g, "")}`
      : safeButtonUrl(p.button_url);

    const pixel = /^\d+$/.test(p.pixel_id || "")
      ? `<script>
        !function(f,b,e,v,n,t,s){
          if(f.fbq)return;
          n=f.fbq=function(){
            n.callMethod?
            n.callMethod.apply(n,arguments):
            n.queue.push(arguments)
          };
          if(!f._fbq)f._fbq=n;
          n.push=n;
          n.loaded=!0;
          n.version='2.0';
          n.queue=[];
          t=b.createElement(e);
          t.async=!0;
          t.src=v;
          s=b.getElementsByTagName(e)[0];
          s.parentNode.insertBefore(t,s)
        }(
          window,
          document,
          'script',
          'https://connect.facebook.net/en_US/fbevents.js'
        );
        fbq('init','${p.pixel_id}');
        fbq('track','PageView');
      </script>`
      : "";

    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(p.title)}</title>
${pixel}
<style>
*{box-sizing:border-box}
body{
  margin:0;
  min-height:100vh;
  background:${backgroundColor};
  color:#222;
  font-family:Arial,sans-serif;
}
main{
  max-width:760px;
  margin:40px auto;
  padding:25px;
  text-align:center;
}
h1{
  font-size:clamp(30px,6vw,52px);
  color:${headingColor};
  overflow-wrap:anywhere;
}
p{
  line-height:1.7;
  color:#555;
  overflow-wrap:anywhere;
}
.action{
  display:inline-block;
  background:${buttonColor};
  color:#07130d;
  padding:15px 28px;
  border-radius:12px;
  text-decoration:none;
  font-weight:bold;
  margin-top:20px;
}
@med
