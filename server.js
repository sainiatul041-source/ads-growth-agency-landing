
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

if (!DATABASE_URL || !JWT_SECRET) {
  console.error("DATABASE_URL and JWT_SECRET are required.");
  process.exit(1);
}

const pool = new Pool({
  connectionString:DATABASE_URL,
  ssl:process.env.DB_SSL === "false" ? false : {rejectUnauthorized:false}
});

app.use(express.static(path.join(__dirname,"public")));

const text = (v,n=3000) => String(v ?? "").trim().slice(0,n);

function slugify(v) {
  return (text(v,40).toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"") || "page")
    + "-" + crypto.randomBytes(4).toString("hex");
}

function cleanPage(b) {
  const imageUrl = text(b.imageUrl,2000);
  const buttonLink = text(b.buttonLink,1000);
  return {
    title:text(b.title,120),
    headline:text(b.headline,180),
    description:text(b.description,3000),
    buttonText:text(b.buttonText || "Join Now",60),
    buttonLink:/^https?:\/\//i.test(buttonLink) ? buttonLink : "",
    imageUrl:/^https?:\/\//i.test(imageUrl) ? imageUrl : "",
    background:/^#[0-9a-fA-F]{6}$/.test(b.background || "") ? b.background : "#0b1730"
  };
}

function signToken(user) {
  return jwt.sign(
    {id:user.id,email:user.email,role:user.role},
    JWT_SECRET,{expiresIn:"7d"}
  );
}

function auth(req,res,next) {
  try {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    if (!token) return res.status(401).json({error:"Please login first."});
    req.user = jwt.verify(token,JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({error:"Login expired. Please login again."});
  }
}

function adminOnly(req,res,next) {
  if (req.user.role !== "admin") return res.status(403).json({error:"Admin access required."});
  next();
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) DEFAULT 'user',
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
      image_url TEXT DEFAULT '',
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

  await pool.query(`
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_text VARCHAR(60) DEFAULT 'Join Now';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS button_link TEXT DEFAULT '';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS image_url TEXT DEFAULT '';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS background VARCHAR(7) DEFAULT '#0b1730';
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS published BOOLEAN DEFAULT FALSE;
    ALTER TABLE ag_pages ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
  `);

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const found = await pool.query("SELECT id FROM ag_users WHERE email=$1",[ADMIN_EMAIL]);
    if (found.rowCount) {
      await pool.query("UPDATE ag_users SET role='admin' WHERE email=$1",[ADMIN_EMAIL]);
    } else {
      const hash = await bcrypt.hash(ADMIN_PASSWORD,12);
      await pool.query(
        "INSERT INTO ag_users(name,email,password_hash,role) VALUES($1,$2,$3,'admin')",
        ["Admin",ADMIN_EMAIL,hash]
      );
    }
  }
  console.log("Database ready.");
}

// Register
app.post("/api/auth/register",async(req,res)=>{
  try {
    const name=text(req.body.name,120);
    const email=text(req.body.email,255).toLowerCase();
    const password=String(req.body.password || "");
    if(!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<6)
      return res.status(400).json({error:"Enter name, valid email and password of at least 6 characters."});

    const hash=await bcrypt.hash(password,12);
    const result=await pool.query(
      "INSERT INTO ag_users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email,role",
      [name,email,hash]
    );
    const user=result.rows[0];
    res.status(201).json({token:signToken(user),user});
  } catch(e) {
    if(e.code==="23505") return res.status(409).json({error:"Email already registered."});
    console.error(e);
    res.status(500).json({error:"Registration failed."});
  }
});

// Login
app.post("/api/auth/login",async(req,res)=>{
  try {
    const email=text(req.body.email,255).toLowerCase();
    const password=String(req.body.password || "");
    const result=await pool.query("SELECT * FROM ag_users WHERE email=$1",[email]);
    const user=result.rows[0];
    if(!user || !(await bcrypt.compare(password,user.password_hash)))
      return res.status(401).json({error:"Incorrect email or password."});
    res.json({
      token:signToken(user),
      user:{id:user.id,name:user.name,email:user.email,role:user.role}
    });
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Login failed."});
  }
});

// Current user
app.get("/api/me",auth,async(req,res)=>{
  try {
    const r=await pool.query("SELECT id,name,email,role FROM ag_users WHERE id=$1",[req.user.id]);
    if(!r.rowCount) return res.status(404).json({error:"User not found."});
    res.json({user:r.rows[0]});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not load account."});
  }
});

// Get pages
app.get("/api/pages",auth,async(req,res)=>{
  try {
    const r=await pool.query(`
      SELECT id,title,headline,description,
      button_text AS "buttonText",button_link AS "buttonLink",
      image_url AS "imageUrl",background,slug,published
      FROM ag_pages WHERE user_id=$1 ORDER BY id DESC
    `,[req.user.id]);
    res.json({pages:r.rows});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not load pages."});
  }
});

// Create page
app.post("/api/pages",auth,async(req,res)=>{
  try {
    const p=cleanPage(req.body);
    if(!p.title || !p.headline) return res.status(400).json({error:"Title and headline required."});
    const r=await pool.query(`
      INSERT INTO ag_pages
      (user_id,title,headline,description,button_text,button_link,image_url,background,slug)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING id,title,headline,description,
      button_text AS "buttonText",button_link AS "buttonLink",
      image_url AS "imageUrl",background,slug,published
    `,[req.user.id,p.title,p.headline,p.description,p.buttonText,p.buttonLink,p.imageUrl,p.background,slugify(p.title)]);
    res.status(201).json({page:r.rows[0]});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not create page."});
  }
});

// Edit page
app.put("/api/pages/:id",auth,async(req,res)=>{
  try {
    const p=cleanPage(req.body);
    if(!p.title || !p.headline) return res.status(400).json({error:"Title and headline required."});
    const r=await pool.query(`
      UPDATE ag_pages SET
      title=$1,headline=$2,description=$3,button_text=$4,
      button_link=$5,image_url=$6,background=$7,updated_at=NOW()
      WHERE id=$8 AND user_id=$9
      RETURNING id,title,headline,description,
      button_text AS "buttonText",button_link AS "buttonLink",
      image_url AS "imageUrl",background,slug,published
    `,[p.title,p.headline,p.description,p.buttonText,p.buttonLink,p.imageUrl,p.background,req.params.id,req.user.id]);
    if(!r.rowCount) return res.status(404).json({error:"Page not found."});
    res.json({page:r.rows[0]});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not update page."});
  }
});

// Delete page
app.delete("/api/pages/:id",auth,async(req,res)=>{
  try {
    const r=await pool.query(
      "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2 RETURNING id",
      [req.params.id,req.user.id]
    );
    if(!r.rowCount) return res.status(404).json({error:"Page not found."});
    res.json({success:true});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not delete page."});
  }
});

// Publish / Unpublish
app.post("/api/pages/:id/publish",auth,async(req,res)=>{
  try {
    const r=await pool.query(`
      UPDATE ag_pages SET published=NOT published,updated_at=NOW()
      WHERE id=$1 AND user_id=$2 RETURNING id,published,slug
    `,[req.params.id,req.user.id]);
    if(!r.rowCount) return res.status(404).json({error:"Page not found."});
    res.json({success:true,page:r.rows[0]});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not change publish status."});
  }
});

// Public landing page
app.get("/p/:slug",async(req,res)=>{
  try {
    const r=await pool.query(`
      SELECT title,headline,description,button_text,button_link,image_url,background
      FROM ag_pages WHERE slug=$1 AND published=TRUE
    `,[req.params.slug]);
    if(!r.rowCount) return res.status(404).send("Page not found or not published.");

    const p=r.rows[0];
    const esc=v=>String(v ?? "").replace(/[&<>"']/g,c=>({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
    })[c]);
    const bg=/^#[0-9a-fA-F]{6}$/.test(p.background || "")?p.background:"#0b1730";
    const img=/^https?:\/\//i.test(p.image_url || "")
      ? `<img src="${esc(p.image_url)}" alt="${esc(p.title)}" style="max-width:100%;max-height:360px;object-fit:cover;border-radius:14px;margin-bottom:20px">`
      : "";
    const link=/^https?:\/\//i.test(p.button_link || "")?esc(p.button_link):"#";

    res.send(`<!DOCTYPE html><html lang="hi"><head>
      <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <title>${esc(p.title)}</title>
      <style>
      *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:${bg};color:white;font-family:Arial}
      main{width:min(700px,94%);padding:28px;text-align:center}h1{font-size:clamp(28px,6vw,42px)}
      p{line-height:1.7;color:#d7e2f0;white-space:pre-wrap}
      a{display:inline-block;padding:14px 25px;background:#20c982;color:#061b13;text-decoration:none;border-radius:8px;font-weight:bold}
      </style></head><body><main>${img}<h1>${esc(p.headline)}</h1>
      <h2>${esc(p.title)}</h2><p>${esc(p.description)}</p>
      <a href="${link}" target="_blank" rel="noopener noreferrer">${esc(p.button_text || "Join Now")}</a>
      </main></body></html>`);
  } catch(e) {
    console.error(e);
    res.status(500).send("Could not display this page.");
  }
});

// Payment submission (manual verification)
app.post("/api/payments",auth,async(req,res)=>{
  try {
    const plan=String(req.body.plan || "");
    const amount=Number(req.body.amount);
    const txid=text(req.body.txid,200);
    const prices={Starter:499,Growth:999,Pro:1499};
    if(!prices[plan] || amount!==prices[plan] || !txid)
      return res.status(400).json({error:"Invalid plan, amount or transaction ID."});
    const r=await pool.query(`
      INSERT INTO ag_payments(user_id,plan,amount,txid)
      VALUES($1,$2,$3,$4)
      RETURNING id,plan,amount,txid,status,created_at
    `,[req.user.id,plan,amount,txid]);
    res.status(201).json({payment:r.rows[0]});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not submit payment."});
  }
});

// User payment history
app.get("/api/payments",auth,async(req,res)=>{
  try {
    const r=await pool.query(
      "SELECT id,plan,amount,txid,status,created_at FROM ag_payments WHERE user_id=$1 ORDER BY id DESC",
      [req.user.id]
    );
    res.json({payments:r.rows});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not load payment history."});
  }
});

// Admin stats
app.get("/api/admin/stats",auth,adminOnly,async(req,res)=>{
  try {
    const [u,p,m]=await Promise.all([
      pool.query("SELECT COUNT(*)::int AS count FROM ag_users"),
      pool.query("SELECT COUNT(*)::int AS count FROM ag_pages"),
      pool.query("SELECT COUNT(*)::int AS count FROM ag_payments")
    ]);
    res.json({users:u.rows[0].count,pages:p.rows[0].count,payments:m.rows[0].count});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not load admin stats."});
  }
});

// Admin payments
app.get("/api/admin/payments",auth,adminOnly,async(req,res)=>{
  try {
    const r=await pool.query(`
      SELECT p.id,p.plan,p.amount,p.txid,p.status,p.created_at,u.email
      FROM ag_payments p JOIN ag_users u ON u.id=p.user_id
      ORDER BY p.id DESC LIMIT 200
    `);
    res.json({payments:r.rows});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not load admin payments."});
  }
});

// Admin approve/reject
app.post("/api/admin/payments/:id/status",auth,adminOnly,async(req,res)=>{
  try {
    const status=String(req.body.status || "");
    if(!["approved","rejected"].includes(status))
      return res.status(400).json({error:"Invalid payment status."});
    const r=await pool.query(
      "UPDATE ag_payments SET status=$1 WHERE id=$2 RETURNING id,status,plan,amount",
      [status,req.params.id]
    );
    if(!r.rowCount) return res.status(404).json({error:"Payment not found."});
    res.json({success:true,payment:r.rows[0]});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"Could not update payment."});
  }
});

app.get("/health",(req,res)=>res.json({status:"ok"}));
app.get("/",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

initDatabase()
.then(()=>app.listen(PORT,"0.0.0.0",()=>console.log("ADS GROWTH running on "+PORT)))
.catch(e=>{console.error("Database initialization failed:",e);process.exit(1);});
                               
