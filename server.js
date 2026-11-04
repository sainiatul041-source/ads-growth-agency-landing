require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

const required = ['DATABASE_URL', 'JWT_SECRET', 'ADMIN_EMAIL', 'ADMIN_PASSWORD'];
for (const key of required) {
  if (!process.env[key]) throw new Error(`Missing environment variable: ${key}`);
}
if (process.env.JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters');
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === 'false'
    ? false
    : { rejectUnauthorized: false }
});

const PORT = Number(process.env.PORT || 3000);
const UPI_ID = process.env.UPI_ID || 'sainiatul041@okhdfcbank';

const plans = {
  starter: { id: 'starter', name: 'Starter', price: 999, pages: 1, days: 30 },
  growth: { id: 'growth', name: 'Growth', price: 1499, pages: 1, days: 30 },
  pro: { id: 'pro', name: 'Pro', price: 1999, pages: 2, days: 30 }
};

const clean = (v, max = 500) => String(v ?? '').trim().slice(0, max);
const emailOk = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

const safeUrl = value => {
  const s = clean(value, 1000);
  if (!s) return '';
  try {
    const u = new URL(s);
    return ['http:', 'https:'].includes(u.protocol) ? u.toString() : '';
  } catch {
    return '';
  }
};

const colorOk = v =>
  /^#[0-9a-fA-F]{6}$/.test(String(v || '')) ? v : '#2563eb';

const tokenFor = user =>
  jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    if (!token) throw new Error('Missing token');
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Please login again.' });
  }
}

const adminOnly = (req, res, next) =>
  req.user?.role === 'admin'
    ? next()
    : res.status(403).json({ error: 'Admin access required.' });

const asyncRoute = fn =>
  (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ag_users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(254) NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'customer',
      plan VARCHAR(30),
      subscription_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES ag_users(id) ON DELETE CASCADE,
      plan_id VARCHAR(30) NOT NULL,
      amount INTEGER NOT NULL,
      utr VARCHAR(100) NOT NULL UNIQUE,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      admin_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ag_pages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES ag_users(id) ON DELETE CASCADE,
      slug VARCHAR(100) NOT NULL UNIQUE,
      title VARCHAR(160) NOT NULL,
      headline VARCHAR(220) NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      button_text VARCHAR(40) NOT NULL DEFAULT 'Learn More',
      button_url TEXT NOT NULL DEFAULT '',
      image_url TEXT NOT NULL DEFAULT '',
      pixel_id VARCHAR(40) NOT NULL DEFAULT '',
      bg_color VARCHAR(7) NOT NULL DEFAULT '#0b1530',
      text_color VARCHAR(7) NOT NULL DEFAULT '#ffffff',
      button_color VARCHAR(7) NOT NULL DEFAULT '#2563eb',
      published BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ag_events (
      id BIGSERIAL PRIMARY KEY,
      page_id BIGINT NOT NULL REFERENCES ag_pages(id) ON DELETE CASCADE,
      event_type VARCHAR(20) NOT NULL
        CHECK (event_type IN ('visit','click')),
      visitor_hash VARCHAR(64) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS ag_pages_user_idx
      ON ag_pages(user_id);

    CREATE INDEX IF NOT EXISTS ag_events_page_idx
      ON ag_events(page_id, created_at);
  `);

  await pool.query(`
    ALTER TABLE ag_payments
    ADD COLUMN IF NOT EXISTS admin_note TEXT
  `);

  await pool.query(`
    ALTER TABLE ag_pages
    ADD COLUMN IF NOT EXISTS bg_color VARCHAR(7) NOT NULL DEFAULT '#0b1530'
  `);

  await pool.query(`
    ALTER TABLE ag_pages
    ADD COLUMN IF NOT EXISTS text_color VARCHAR(7) NOT NULL DEFAULT '#ffffff'
  `);

  await pool.query(`
    ALTER TABLE ag_pages
    ADD COLUMN IF NOT EXISTS button_color VARCHAR(7) NOT NULL DEFAULT '#2563eb'
  `);

  const email = clean(process.env.ADMIN_EMAIL, 254).toLowerCase();
  const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);

  await pool.query(`
    INSERT INTO ag_users(name,email,password,role)
    VALUES($1,$2,$3,'admin')
    ON CONFLICT(email)
    DO UPDATE SET role='admin', password=EXCLUDED.password
  `, ['Administrator', email, hash]);
}

// Health and public configuration
app.get('/health', asyncRoute(async (req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true, database: 'connected' });
}));

app.get('/api/config', (req, res) => {
  res.json({
    brand: 'ADS GROWTH AGENCY PRO',
    upiId: UPI_ID
  });
});

app.get('/api/plans', (req, res) => {
  res.json(Object.values(plans));
});

app.get('/api/payment-info', (req, res) => {
  res.json({
    upiId: UPI_ID,
    qrPath: '/scanner.png'
  });
});

// Register
app.post('/api/register', asyncRoute(async (req, res) => {
  const name = clean(req.body.name, 100);
  const email = clean(req.body.email, 254).toLowerCase();
  const password = String(req.body.password || '');

  if (name.length < 2 || !emailOk(email) || password.length < 8) {
    return res.status(400).json({
      error: 'Name, valid email and password (8+ characters) required.'
    });
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    const { rows } = await pool.query(
      `INSERT INTO ag_users(name,email,password)
       VALUES($1,$2,$3)
       RETURNING id,name,email,role,plan,subscription_expires`,
      [name, email, hash]
    );

    res.status(201).json({
      token: tokenFor(rows[0]),
      user: rows[0]
    });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Email already registered.' });
    }
    throw e;
  }
}));

// Login
app.post('/api/login', asyncRoute(async (req, res) => {
  const email = clean(req.body.email, 254).toLowerCase();
  const password = String(req.body.password || '');

  const { rows } = await pool.query(
    'SELECT * FROM ag_users WHERE email=$1',
    [email]
  );

  if (!rows[0] || !(await bcrypt.compare(password, rows[0].password))) {
    return res.status(401).json({
      error: 'Incorrect email or password.'
    });
  }

  const u = rows[0];
  const user = {
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    plan: u.plan,
    subscription_expires: u.subscription_expires
  };

  res.json({ token: tokenFor(user), user });
}));

// Current account
app.get('/api/me', auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id,name,email,role,plan,subscription_expires
     FROM ag_users WHERE id=$1`,
    [req.user.id]
  );

  if (!rows[0]) {
    return res.status(404).json({ error: 'Account not found.' });
  }

  res.json({ user: rows[0] });
}));

// Submit payment reference for manual verification
app.post('/api/payments', auth, asyncRoute(async (req, res) => {
  const plan = plans[clean(req.body.plan_id, 30)];
  const utr = clean(req.body.utr, 100)
    .replace(/\s/g, '')
    .toUpperCase();

  if (!plan || !/^[A-Z0-9-]{8,40}$/.test(utr)) {
    return res.status(400).json({
      error: 'Select a plan and enter a valid UTR/reference number.'
    });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO ag_payments(user_id,plan_id,amount,utr)
       VALUES($1,$2,$3,$4)
       RETURNING id,plan_id,amount,utr,status,created_at`,
      [req.user.id, plan.id, plan.price, utr]
    );

    res.status(201).json({
      payment: rows[0],
      message: 'Payment submitted. Access starts only after admin verifies the transaction.'
    });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({
        error: 'This UTR has already been submitted.'
      });
    }
    throw e;
  }
}));

app.get('/api/payments/mine', auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id,plan_id,amount,utr,status,admin_note,created_at,reviewed_at
     FROM ag_payments
     WHERE user_id=$1
     ORDER BY id DESC`,
    [req.user.id]
  );

  res.json({ payments: rows });
}));

// Page validation
function pagePayload(body) {
  const title = clean(body.title, 160);
  const headline = clean(body.headline, 220);

  if (title.length < 2 || headline.length < 2) {
    throw Object.assign(
      new Error('Page title and headline are required.'),
      { status: 400 }
    );
  }

  return {
    title,
    headline,
    description: clean(body.description, 4000),
    button_text: clean(body.button_text, 40) || 'Learn More',
    button_url: safeUrl(body.button_url),
    image_url: safeUrl(body.image_url),
    pixel_id: clean(body.pixel_id, 40).replace(/[^0-9]/g, ''),
    bg_color: colorOk(body.bg_color),
    text_color: colorOk(body.text_color),
    button_color: colorOk(body.button_color)
  };
}

async function canCreate(userId, role) {
  if (role === 'admin') {
    return { allowed: true, limit: 999999 };
  }

  const { rows } = await pool.query(
    'SELECT plan,subscription_expires FROM ag_users WHERE id=$1',
    [userId]
  );

  const u = rows[0];

  if (
    !u?.plan ||
    !u.subscription_expires ||
    new Date(u.subscription_expires) <= new Date()
  ) {
    return { allowed: false, limit: 0 };
  }

  const plan = plans[u.plan];

  return {
    allowed: !!plan,
    limit: plan?.pages || 0
  };
}

// Customer pages
app.get('/api/pages', auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id,slug,title,headline,description,button_text,
      button_url,image_url,pixel_id,bg_color,text_color,
      button_color,published,created_at,updated_at
     FROM ag_pages
     WHERE user_id=$1
     ORDER BY id DESC`,
    [req.user.id]
  );

  res.json({ pages: rows });
}));

app.post('/api/pages', auth, asyncRoute(async (req, res) => {
  const access = await canCreate(req.user.id, req.user.role);

  const { rows: count } = await pool.query(
    'SELECT COUNT(*)::int AS n FROM ag_pages WHERE user_id=$1',
    [req.user.id]
  );

  if (!access.allowed || count[0].n >= access.limit) {
    return res.status(403).json({
      error: 'An active plan with available page slots is required.'
    });
  }

  const p = pagePayload(req.body);

  const slug = clean(req.body.slug, 80)
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '') ||
    crypto.randomBytes(5).toString('hex');

  try {
    const { rows } = await pool.query(
      `INSERT INTO ag_pages(
        user_id,slug,title,headline,description,button_text,
        button_url,image_url,pixel_id,bg_color,text_color,button_color
      )
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING *`,
      [req.user.id, slug, ...Object.values(p)]
    );

    res.status(201).json({ page: rows[0] });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({
        error: 'That page URL is already in use. Change the page slug.'
      });
    }
    throw e;
  }
}));

app.put('/api/pages/:id', auth, asyncRoute(async (req, res) => {
  const p = pagePayload(req.body);

  const { rows } = await pool.query(
    `UPDATE ag_pages
     SET title=$1,headline=$2,description=$3,button_text=$4,
       button_url=$5,image_url=$6,pixel_id=$7,bg_color=$8,
       text_color=$9,button_color=$10,updated_at=NOW()
     WHERE id=$11 AND user_id=$12
     RETURNING *`,
    [...Object.values(p), req.params.id, req.user.id]
  );

  if (!rows[0]) {
    return res.status(404).json({ error: 'Page not found.' });
  }

  res.json({ page: rows[0] });
}));

app.post('/api/pages/:id/publish', auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE ag_pages
     SET published=NOT published,updated_at=NOW()
     WHERE id=$1 AND user_id=$2
     RETURNING id,slug,published`,
    [req.params.id, req.user.id]
  );

  if (!rows[0]) {
    return res.status(404).json({ error: 'Page not found.' });
  }

  res.json({ page: rows[0] });
}));

app.delete('/api/pages/:id', auth, asyncRoute(async (req, res) => {
  const result = await pool.query(
    'DELETE FROM ag_pages WHERE id=$1 AND user_id=$2',
    [req.params.id, req.user.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: 'Page not found.' });
  }

  res.json({ ok: true });
}));

// Admin statistics
app.get('/api/admin/stats', auth, adminOnly, asyncRoute(async (req, res) => {
  const [clients, pages, published, pending, visits, clicks] =
    await Promise.all([
      pool.query("SELECT COUNT(*)::int total FROM ag_users WHERE role<>'admin'"),
      pool.query('SELECT COUNT(*)::int total FROM ag_pages'),
      pool.query('SELECT COUNT(*)::int total FROM ag_pages WHERE published=true'),
      pool.query("SELECT COUNT(*)::int total FROM ag_payments WHERE status='pending'"),
      pool.query("SELECT COUNT(*)::int total FROM ag_events WHERE event_type='visit'"),
      pool.query("SELECT COUNT(*)::int total FROM ag_events WHERE event_type='click'")
    ]);

  res.json({
    clients: clients.rows[0],
    pages: pages.rows[0],
    publishedPages: published.rows[0],
    payments: { pending: pending.rows[0].total },
    clicks: {
      visits: visits.rows[0].total,
      valid_clicks: clicks.rows[0].total
    }
  });
}));

app.get('/api/admin/payments', auth, adminOnly, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT p.*,u.name,u.email
    FROM ag_payments p
    JOIN ag_users u ON u.id=p.user_id
    ORDER BY p.created_at DESC
  `);

  res.json({ payments: rows });
}));

// Admin manually reviews submitted payment
app.post('/api/admin/payments/:id/review', auth, adminOnly, asyncRoute(async (req, res) => {
  const status = clean(req.body.status, 20);
  const note = clean(req.body.note, 500);

  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({
      error: 'Status must be approved or rejected.'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const { rows } = await client.query(
      'SELECT * FROM ag_payments WHERE id=$1 FOR UPDATE',
      [req.params.id]
    );

    const payment = rows[0];

    if (!payment) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Payment not found.' });
    }

    if (payment.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'This payment was already reviewed.'
      });
    }

    if (status === 'approved') {
      const plan = plans[payment.plan_id];
      if (!plan) throw new Error('Unknown plan');

      await client.query(
        `UPDATE ag_users
         SET plan=$1,
           subscription_expires=
             GREATEST(COALESCE(subscription_expires,NOW()),NOW())
             + ($2 || ' days')::interval
         WHERE id=$3`,
        [plan.id, plan.days, payment.user_id]
      );
    }

    await client.query(
      `UPDATE ag_payments
       SET status=$1,admin_note=$2,reviewed_at=NOW()
       WHERE id=$3`,
      [status, note, req.params.id]
    );

    await client.query('COMMIT');
    res.json({ ok: true, status });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

app.get('/api/admin/clicks', auth, adminOnly, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT e.id,e.event_type,e.created_at,p.title,p.slug,u.email
    FROM ag_events e
    JOIN ag_pages p ON p.id=e.page_id
    JOIN ag_users u ON u.id=p.user_id
    ORDER BY e.created_at DESC
    LIMIT 500
  `);

  res.json({ events: rows });
}));

// Genuine visit and click tracking, deduplicated for 30 minutes
app.get('/api/track/:slug/:event', asyncRoute(async (req, res) => {
  const event = req.params.event;

  if (!['visit', 'click'].includes(event)) {
    return res.status(400).json({ error: 'Invalid event' });
  }

  const { rows } = await pool.query(
    'SELECT id FROM ag_pages WHERE slug=$1 AND published=true',
    [req.params.slug]
  );

  if (!rows[0]) {
    return res.status(404).json({ error: 'Page not found' });
  }

  const visitor = crypto
    .createHash('sha256')
    .update((req.ip || '') + '|' + (req.get('user-agent') || ''))
    .digest('hex');

  const recent = await pool.query(
    `SELECT 1 FROM ag_events
     WHERE page_id=$1 AND event_type=$2 AND visitor_hash=$3
       AND created_at>NOW()-INTERVAL '30 minutes'
     LIMIT 1`,
    [rows[0].id, event, visitor]
  );

  if (!recent.rowCount) {
    await pool.query(
      'INSERT INTO ag_events(page_id,event_type,visitor_hash) VALUES($1,$2,$3)',
      [rows[0].id, event, visitor]
    );
  }

  res.json({ ok: true });
}));

// Public landing page
app.get('/p/:slug', asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM ag_pages WHERE slug=$1 AND published=true',
    [req.params.slug]
  );

  const p = rows[0];

  if (!p) {
    return res.status(404).send('Page not found or not published.');
  }

  const esc = s =>
    String(s ?? '').replace(/[&<>"']/g, c => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[c]));

  const img = p.image_url
    ? `<img class="heroimg" src="${esc(p.image_url)}" alt="${esc(p.title)}">`
    : '';

  const pixel = p.pixel_id
    ? `<script>
      !function(f,b,e,v,n,t,s){
        if(f.fbq)return;
        n=f.fbq=function(){
          n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)
        };
        if(!f._fbq)f._fbq=n;
        n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];
        t=b.createElement(e);t.async=!0;
        t.src=v;s=b.getElementsByTagName(e)[0];
        s.parentNode.insertBefore(t,s)
      }(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
      fbq('init','${esc(p.pixel_id)}');
      fbq('track','PageView');
    </script>`
    : '';

  res.type('html').send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(p.title)}</title>
${pixel}
<style>
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;display:grid;place-items:center;
  padding:24px;background:${esc(p.bg_color)};
  color:${esc(p.text_color)};font-family:Arial,sans-serif
}
.card{
  width:min(760px,100%);text-align:center;padding:38px 24px;
  border:1px solid #ffffff22;border-radius:24px;background:#ffffff0b
}
.heroimg{
  max-width:100%;max-height:360px;object-fit:contain;
  border-radius:16px;margin:0 auto 24px
}
h1{font-size:clamp(30px,6vw,54px);margin:12px 0}
p{font-size:18px;line-height:1.7;opacity:.88}
.cta{
  display:inline-block;margin-top:16px;padding:16px 28px;
  border-radius:12px;background:${esc(p.button_color)};
  color:white;tex
