require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL || !JWT_SECRET) {
  throw new Error("DATABASE_URL aur JWT_SECRET environment variables set karein.");
}

const db = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.static(path.join(__dirname, "public")));

const plans = [
  { id: "starter", name: "Starter", amount: 999 },
  { id: "growth", name: "Growth", amount: 1499 },
  { id: "pro", name: "Pro", amount: 1999 }
];

async function init() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS ag_pages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES ag_users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'My Landing Page',
      slug TEXT UNIQUE NOT NULL,
      image_url TEXT DEFAULT '',
      image_width_percent INTEGER NOT NULL DEFAULT 100,
      image_height_px INTEGER NOT NULL DEFAULT 350,
      button_text TEXT DEFAULT 'Join Now',
      button_url TEXT DEFAULT '',
      heading TEXT DEFAULT '',
      description TEXT DEFAULT '',
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.query(`
    ALTER TABLE ag_pages
    ADD COLUMN IF NOT EXISTS image_width_percent INTEGER NOT NULL DEFAULT 100
  `);

  await db.query(`
    ALTER TABLE ag_pages
    ADD COLUMN IF NOT EXISTS image_height_px INTEGER NOT NULL DEFAULT 350
  `);
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({ error: "Login required" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function makeSlug() {
  return crypto.randomBytes(6).toString("hex");
}

function safeNumber(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, Math.round(number)));
}

app.get("/api/health", (req, res) => {
  res.json({ success: true, message: "Server running" });
});

app.get("/api/plans", (req, res) => {
  res.json(plans);
});

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      !name ||
      !email ||
      typeof password !== "string" ||
      password.length < 6
    ) {
      return res.status(400).json({
        error: "Name, email aur minimum 6 character password required"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await db.query(
      `INSERT INTO ag_users (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, name, email, role`,
      [
        name.trim(),
        email.trim().toLowerCase(),
        hash
      ]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      user,
      token
    });

  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Email already registered"
      });
    }

    console.error("REGISTER ERROR:", error);
    res.status(500).json({ error: "Registration failed" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || typeof password !== "string") {
      return res.status(400).json({
        error: "Email aur password required"
      });
    }

    const result = await db.query(
      `SELECT * FROM ag_users WHERE email = $1`,
      [email.trim().toLowerCase()]
    );

    const user = result.rows[0];

    if (!user || !user.password_hash) {
      return res.status(401).json({
        error: "Wrong email or password"
      });
    }

    const passwordMatch = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatch) {
      return res.status(401).json({
        error: "Wrong email or password"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

// CURRENT USER
app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, name, email, role
       FROM ag_users WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "User request failed" });
  }
});

// GET USER PAGES
app.get("/api/pages", auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM ag_pages
       WHERE user_id = $1 ORDER BY id DESC`,
      [req.user.id]
    );

    res.json(result.rows);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load pages" });
  }
});

// CREATE PAGE
app.post("/api/pages", auth, async (req, res) => {
  try {
    const {
      title,
      imageUrl,
      image_url,
      imageWidth,
      imageHeight,
      buttonText,
      buttonUrl,
      heading,
      description
    } = req.body;

    const slug = makeSlug();

    const result = await db.query(
      `INSERT INTO ag_pages
       (
         user_id, title, slug, image_url,
         image_width_percent, image_height_px,
         button_text, button_url, heading, description
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING *`,
      [
        req.user.id,
        title || "My Landing Page",
        slug,
        imageUrl || image_url || "",
        safeNumber(imageWidth, 100, 10, 100),
        safeNumber(imageHeight, 350, 80, 1200),
        buttonText || "Join Now",
        buttonUrl || "",
        heading || "",
        description || ""
      ]
    );

    res.json({
      success: true,
      page: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Page could not be saved" });
  }
});

// UPDATE PAGE
app.put("/api/pages/:id", auth, async (req, res) => {
  try {
    const {
      title,
      imageUrl,
      image_url,
      imageWidth,
      imageHeight,
      buttonText,
      buttonUrl,
      heading,
      description
    } = req.body;

    const result = await db.query(
      `UPDATE ag_pages SET
       title = COALESCE($1, title),
       image_url = COALESCE($2, image_url),
       image_width_percent = $3,
       image_height_px = $4,
       button_text = COALESCE($5, button_text),
       button_url = COALESCE($6, button_url),
       heading = COALESCE($7, heading),
       description = COALESCE($8, description),
       updated_at = CURRENT_TIMESTAMP
       WHERE id = $9 AND user_id = $10
       RETURNING *`,
      [
        title ?? null,
        imageUrl ?? image_url ?? null,
        safeNumber(imageWidth, 100, 10, 100),
        safeNumber(imageHeight, 350, 80, 1200),
        buttonText ?? null,
        buttonUrl ?? null,
        heading ?? null,
        description ?? null,
        req.params.id,
        req.user.id
      ]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Page not found" });
    }

    res.json({
      success: true,
      page: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Page update failed" });
  }
});

// PUBLISH PAGE
app.post("/api/pages/:id/publish", auth, async (req, res) => {
  try {
    const result = await db.query(
      `UPDATE ag_pages
       SET published = TRUE,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1 AND user_id = $2
       RETURNING *`,
      [req.params.id, req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Page not found" });
    }

    res.json({
      success: true,
      url: `/p/${result.rows[0].slug}`,
      page: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Publish failed" });
  }
});

// DELETE PAGE
app.delete("/api/pages/:id", auth, async (req, res) => {
  try {
    const result = await db.query(
      `DELETE FROM ag_pages
       WHERE id = $1 AND user_id = $2
       RETURNING id`,
      [req.params.id, req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Page not found" });
    }

    res.json({ success: true });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Delete failed" });
  }
});

// PUBLIC LANDING PAGE
app.get("/p/:slug", async (req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM ag_pages
       WHERE slug = $1 AND published = TRUE`,
      [req.params.slug]
    );

    const page = result.rows[0];

    if (!page) {
      return res.status(404).send("Page not found");
    }

    const escapeHtml = value =>
      String(value || "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      })[char]);

    const image = page.image_url
      ? `<img src="${escapeHtml(page.image_url)}"
          style="width:${safeNumber(page.image_width_percent,100,10,100)}%;height:${safeNumber(page.image_height_px,350,80,1200)}px;object-fit:contain;max-width:100%">`
      : "";

    res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(page.title)}</title>
<style>
body {
  margin: 0;
  padding: 20px;
  background: #0d162b;
  color: white;
  font-family: Arial, sans-serif;
  text-align: center;
}
main {
  max-width: 500px;
  margin: 30px auto;
}
img {
  display: block;
  margin: 20px auto;
}
a {
  display: inline-block;
  background: #0088cc;
  color: white;
  padding: 14px 25px;
  border-radius: 10px;
  text-decoration: none;
  font-weight: bold;
}
</style>
</head>
<body>
<main>
<h1>${escapeHtml(page.heading || page.title)}</h1>
<p>${escapeHtml(page.description)}</p>
${image}
<a href="${escapeHtml(page.button_url)}">
${escapeHtml(page.button_text)}
</a>
</main>
</body>
</html>`);

  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

// HOME PAGE
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
  
