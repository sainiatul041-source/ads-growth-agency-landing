const express=require("express"),path=require("path"),crypto=require("crypto"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),helmet=require("helmet"),rateLimit=require("express-rate-limit"),{Pool}=require("pg");

const app=express(),PORT=process.env.PORT||3000,SECRET=process.env.JWT_SECRET,ADMIN=String(process.env.ADMIN_EMAIL||"").toLowerCase(),ADMIN_PASS=process.env.ADMIN_PASSWORD||"",UPI=process.env.UPI_ID||"your-upi-id@bank";

if(!process.env.DATABASE_URL||!SECRET||SECRET.length<32||!ADMIN||ADMIN_PASS.length<10){
 console.error("Set DATABASE_URL, JWT_SECRET (32+ chars), ADMIN_EMAIL and ADMIN_PASSWORD (10+ chars)");
 process.exit(1);
}

const db=new Pool({
 connectionString:process.env.DATABASE_URL,
 ssl:process.env.DATABASE_SSL==="false"?false:{rejectUnauthorized:false},
 max:5
});

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"1mb"}));
app.use(express.static(path.join(__dirname,"public")));
app.use("/api",rateLimit({windowMs:60000,limit:100,standardHeaders:true,legacyHeaders:false}));

const plans=[
 {id:"starter",name:"Starter",amount:999,description:"All Click"},
 {id:"growth",name:"Growth",amount:1499,description:"50% Click"},
 {id:"pro",name:"Pro",amount:1999,description:"100% Click"}
];

async function init(){
 await db.query(`
 CREATE TABLE IF NOT EXISTS ag_users(
 id BIGSERIAL PRIMARY KEY,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'client',
 created_at TIMESTAMPTZ DEFAULT NOW()
 );

 ALTER TABLE ag_users ADD COLUMN IF NOT EXISTS name TEXT;
 UPDATE ag_users SET name=split_part(email,'@',1) WHERE name IS NULL OR btrim(name)='';
 ALTER TABLE ag_users ALTER COLUMN name SET NOT NULL;

 CREATE TABLE IF NOT EXISTS ag_payments(
 id BIGSERIAL PRIMARY KEY,
 user_id BIGINT REFERENCES ag_users(id) ON DELETE CASCADE,
 plan_id TEXT NOT NULL,
 amount INT NOT NULL,
 utr TEXT UNIQUE NOT NULL,
 status TEXT DEFAULT 'pending',
 created_at TIMESTAMPTZ DEFAULT NOW(),
 reviewed_at TIMESTAMPTZ
 );

 CREATE TABLE IF NOT EXISTS ag_pages(
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

 CREATE TABLE IF NOT EXISTS ag_click_events(
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

 const h=await bcrypt.hash(ADMIN_PASS,12);
 await db.query(
  "INSERT INTO ag_users(name,email,password_hash,role) VALUES('Admin',$1,$2,'admin') ON CONFLICT(email) DO UPDATE SET role='admin'",
  [ADMIN,h]
 );
}

const clean=(v,n=500)=>String(v??"").trim().slice(0,n);
const color=v=>/^#[0-9a-fA-F]{6}$/.test(v||"");
const slug=v=>clean(v,60).toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"")||"page";

function auth(q,s,n){
 try{
  let t=(q.headers.authorization||"").replace(/^Bearer /,"");
  q.user=jwt.verify(t,SECRET);
  n();
 }catch{
  s.status(401).json({error:"Please login again"});
 }
}

function admin(q,s,n){
 if(q.user.role!=="admin")return s.status(403).json({error:"Admin only"});
 n();
}

async function paid(q,s,n){
 if(q.user.role==="admin")return n();
 let r=await db.query(
  "SELECT 1 FROM ag_payments WHERE user_id=$1 AND status='approved'",
  [q.user.id]
 );
 if(!r.rowCount)return s.status(403).json({error:"Payment approval required"});
 n();
}

const token=u=>jwt.sign(
 {id:u.id,email:u.email,role:u.role},
 SECRET,
 {expiresIn:"7d"}
);

app.get("/health",(q,s)=>s.json({ok:true}));

app.get("/api/config",(q,s)=>s.json({
 plans,
 upiId:UPI,
 payeeName:process.env.UPI_PAYEE_NAME||"ADS GROWTH AGENCY"
}));

app.post("/api/register",async(q,s)=>{
 try{
  let name=clean(q.body.name,100),
  email=clean(q.body.email,254).toLowerCase(),
  pw=String(q.body.password||"");

  if(!name||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||pw.length<8||pw.length>72){
   return s.status(400).json({error:"Name, valid email and 8-72 character password required"});
  }

  let h=await bcrypt.hash(pw,12);
  let r=await db.query(
   "INSERT INTO ag_users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,email,role",
   [name,email,h]
  );

  s.status(201).json({token:token(r.rows[0]),user:r.rows[0]});
 }catch(e){
  console.error("Register error:",e);
  s.status(e.code==="23505"?409:500).json({
   error:e.code==="23505"?"Email already registered":"Registration failed"
  });
 }
});

app.post("/api/login",async(q,s)=>{
 let r=await db.query(
  "SELECT * FROM ag_users WHERE email=$1",
  [clean(q.body.email,254).toLowerCase()]
 );

 if(!r.rowCount||!await bcrypt.compare(String(q.body.password||""),r.rows[0].password_hash)){
  return s.status(401).json({error:"Incorrect login"});
 }

 let u=r.rows[0];
 s.json({token:token(u),user:{id:u.id,email:u.email,role:u.role}});
});

app.get("/api/me",auth,async(q,s)=>{
 let r=await db.query(
  "SELECT id,email,role,created_at FROM ag_users WHERE id=$1",
  [q.user.id]
 );
 s.json({user:r.rows[0]});
});

app.get("/api/payments/mine",auth,async(q,s)=>{
 let r=await db.query(
  "SELECT * FROM ag_payments WHERE user_id=$1 ORDER BY id DESC",
  [q.user.id]
 );
 s.json({payments:r.rows});
});

app.post("/api/payments",auth,async(q,s)=>{
 let p=plans.find(x=>x.id===q.body.planId),
 utr=clean(q.body.utr,80);

 if(!p||!/^[A-Za-z0-9-]{8,80}$/.test(utr)){
  return s.status(400).json({error:"Choose plan and enter valid UTR"});
 }

 try{
  let r=await db.query(
   "INSERT INTO ag_payments(user_id,plan_id,amount,utr) VALUES($1,$2,$3,$4) RETURNING id,status",
   [q.user.id,p.id,p.amount,utr]
  );
  s.status(201).json({
   payment:r.rows[0],
   message:"Submitted. Admin will verify payment."
  });
 }catch(e){
  s.status(409).json({error:"UTR already used or payment could not be saved"});
 }
});

app.get("/api/admin/stats",auth,admin,async(q,s)=>{
 let [u,c,p]=await Promise.all([
  db.query("SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE created_at>NOW()-INTERVAL '30 days')::int last30 FROM ag_users WHERE role='client'"),
  db.query("SELECT COUNT(*) FILTER(WHERE event_type='click' AND NOT suspicious)::int valid_clicks,COUNT(DISTINCT visitor_hash)::int unique_visitors,COUNT(*) FILTER(WHERE suspicious)::int suspicious_events FROM ag_click_events"),
  db.query("SELECT COUNT(*) FILTER(WHERE status='pending')::int pending,COUNT(*) FILTER(WHERE status='approved')::int approved FROM ag_payments")
 ]);

 s.json({clients:u.rows[0],clicks:c.rows[0],payments:p.rows[0]});
});

app.get("/api/admin/payments",auth,admin,async(q,s)=>{
 let r=await db.query(
  "SELECT p.*,u.email FROM ag_payments p JOIN ag_users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 200"
 );
 s.json({payments:r.rows});
});

app.post("/api/admin/payments/:id/review",auth,admin,async(q,s)=>{
 if(!["approved","rejected"].includes(q.body.status)){
  return s.status(400).json({error:"Invalid status"});
 }

 let r=await db.query(
  "UPDATE ag_payments SET status=$1,reviewed_at=NOW() WHERE id=$2 RETURNING id,status",
  [q.body.status,q.params.id]
 );

 if(!r.rowCount)return s.status(404).json({error:"Not found"});
 s.json({payment:r.rows[0]});
});

app.get("/api/admin/clicks",auth,admin,async(q,s)=>{
 let r=await db.query(
  "SELECT e.*,p.slug FROM ag_click_events e LEFT JOIN ag_pages p ON p.id=e.page_id ORDER BY e.id DESC LIMIT 200"
 );
 s.json({events:r.rows});
});

app.get("/api/pages",auth,paid,async(q,s)=>{
 let r=await db.query(
  "SELECT * FROM ag_pages WHERE user_id=$1 ORDER BY id DESC",
  [q.user.id]
 );
 s.json({pages:r.rows});
});

app.post("/api/pages",auth,paid,async(q,s)=>{
 let b=q.body,
 cs=[b.bgColor||"#0b1224",b.textColor||"#ffffff",b.buttonColor||"#16a34a"];

 if(!clean(b.title,100)||!clean(b.headline,180)||!cs.every(color)){
  return s.status(400).json({error:"Title, headline and valid colors required"});
 }

 let r=await db.query(`
  INSERT INTO ag_pages(
   user_id,title,slug,headline,description,button_text,
   button_url,image_url,pixel_id,bg_color,text_color,button_color
  )
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
  RETURNING *
 `,[
  q.user.id,clean(b.title,100),
  slug(b.title)+"-"+crypto.randomBytes(3).toString("hex"),
  clean(b.headline,180),clean(b.description,2000),
  clean(b.buttonText,60)||"Get Started",
  clean(b.buttonUrl,1000)||"#",
  clean(b.imageUrl,1000),clean(b.pixelId,20),...cs
 ]);

 s.status(201).json({page:r.rows[0]});
});

app.put("/api/pages/:id",auth,paid,async(q,s)=>{
 let b=q.body,
 cs=[b.bgColor||"#0b1224",b.textColor||"#ffffff",b.buttonColor||"#16a34a"];

 if(!cs.every(color))return s.status(400).json({error:"Invalid color"});

 let r=await db.query(`
  UPDATE ag_pages SET
   title=$1,headline=$2,description=$3,button_text=$4,
   button_url=$5,image_url=$6,pixel_id=$7,
   bg_color=$8,text_color=$9,button_color=$10
  WHERE id=$11 AND user_id=$12 RETURNING *
 `,[
  clean(b.title,100),clean(b.headline,180),
  clean(b.description,2000),clean(b.buttonText,60),
  clean(b.buttonUrl,1000),clean(b.imageUrl,1000),
  clean(b.pixelId,20),...cs,q.params.id,q.user.id
 ]);

 if(!r.rowCount)return s.status(404).json({error:"Page not found"});
 s.json({page:r.rows[0]});
});

app.post("/api/pages/:id/publish",auth,paid,async(q,s)=>{
 let r=await db.query(
  "UPDATE ag_pages SET published=NOT published WHERE id=$1 AND user_id=$2 RETURNING slug,published",
  [q.params.id,q.user.id]
 );

 if(!r.rowCount)return s.status(404).json({error:"Page not found"});

 s.json({
  page:r.rows[0],
  url:`${q.protocol}://${q.get("host")}/p/${r.rows[0].slug}`
 });
});

app.delete("/api/pages/:id",auth,paid,async(q,s)=>{
 await db.query(
  "DELETE FROM ag_pages WHERE id=$1 AND user_id=$2",
  [q.params.id,q.user.id]
 );
 s.json({deleted:true});
});

app.post("/api/track/:slug",async(q,s)=>{
 try{
  let p=await db.query(
   "SELECT id FROM ag_pages WHERE slug=$1 AND published=true",
   [q.params.slug]
  );

  if(!p.rowCount)return s.status(404).json({error:"Page not found"});

  let v=clean(q.body.visitorId,100);
  if(v.length<10)return s.status(400).json({error:"Invalid visitor"});

  let ip=String(q.ip||"");
  let hash=crypto.createHash("sha256").update(v+"|"+ip+"|"+SECRET).digest("hex");
  let type=q.body.eventType==="click"?"click":"pageview";

  let n=await db.query(
   "SELECT COUNT(*)::int n FROM ag_click_events WHERE page_id=$1 AND visitor_hash=$2 AND created_at>NOW()-INTERVAL '1 minute'",
   [p.rows[0].id,hash]
  );

  let bad=n.rows[0].n>=15;

  await db.query(
   "INSERT INTO ag_click_events(page_id,visitor_hash,event_type,suspicious,reason) VALUES($1,$2,$3,$4,$5)",
   [p.rows[0].id,hash,type,bad,bad?"High event frequency":null]
  );

  s.json({recorded:!bad,flagged:bad});
 }catch(e){
  s.status(500).json({error:"Tracking failed"});
 }
});

/* =========================================
   NEW LANDING PAGE DESIGN
   बाकी backend और APIs में कोई बदलाव नहीं
========================================= */

app.get("/p/:slug",async(q,s)=>{
 let r=await db.query(
  "SELECT * FROM ag_pages WHERE slug=$1 AND published=true",
  [q.params.slug]
 );

 if(!r.rowCount)return s.status(404).send("Page not found");

 let p=r.rows[0];

 let esc=x=>String(x||"").replace(/[&<>"']/g,c=>({
  "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
 }[c]));

 let url=x=>/^https?:\/\//i.test(x||"")?esc(x):"#";

 let px=/^\d{5,20}$/.test(p.pixel_id||"")?`
 <script>
 !function(f,b,e,v,n,t,s){
  if(f.fbq)return;
  n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
  if(!f._fbq)f._fbq=n;
  n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];
  t=b.createElement(e);t.async=!0;t.src=v;
  s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)
 }(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
 fbq('init','${p.pixel_id}');
 fbq('track','PageView');
 </script>`:"";

 s.send(`<!DOCTYPE html>
 <html lang="en">
 <head>
 <meta charset="UTF-8">
 <meta name="viewport" content="width=device-width,initial-scale=1">
 <meta name="theme-color" content="#0b1429">
 <title>${esc(p.title)}</title>
 ${px}

 <style>
 *{box-sizing:border-box}

 body{
  margin:0;
  min-height:100vh;
  background:
   radial-gradient(ellipse at 50% 20%,#102e5b 0%,transparent 42%),
   linear-gradient(180deg,#0c1428,#071126 100%);
  color:#fff;
  font-family:Arial,sans-serif;
  text-align:center;
  padding:25px 16px 40px;
 }

 .landing{
  width:100%;
  max-width:480px;
  margin:0 auto;
  padding:18px 0;
 }

 .logo-wrap{
  width:150px;
  height:150px;
  margin:12px auto 16px;
  border-radius:50%;
  padding:6px;
  background:linear-gradient(145deg,#08d9ff,#167bff,#071a3d);
  box-shadow:0 0 22px #00aaff99,0 0 48px #087dff55;
  overflow:hidden;
 }

 .logo-wrap img{
  width:100%;
  height:100%;
  object-fit:cover;
  border-radius:50%;
  background:#111c32;
 }

 .logo-placeholder{
  width:100%;
  height:100%;
  display:flex;
  align-items:center;
  justify-content:center;
  font-size:45px;
  background:linear-gradient(145deg,#172b4d,#071126);
  border-radius:50%;
 }

 .telegram-label{
  display:inline-block;
  background:#168bff;
  color:white;
  font-size:14px;
  font-weight:bold;
  padding:8px 22px;
  border-radius:30px;
  margin-top:-5px;
  position:relative;
  box-shadow:0 0 15px #168bff88;
 }

 .small-tag{
  display:inline-block;
  margin:22px auto 28px;
  padding:10px 24px;
  border:1px solid #168edb88;
  border-radius:30px;
  background:#102d49;
  color:#40d6ff;
  font-size:17px;
  letter-spacing:1px;
 }

 h1{
  font-size:clamp(30px,8vw,43px);
  line-height:1.25;
  font-weight:900;
  font-style:italic;
  text-transform:uppercase;
  margin:8px 0 18px;
  background:linear-gradient(90deg,#fff,#24caff,#fff);
  -webkit-background-clip:text;
  background-clip:text;
  color:transparent;
 }

 .description{
  color:#aab8d2;
  font-size:17px;
  line-height:1.65;
  margin:0 auto 34px;
  max-width:390px;
  white-space:pre-line;
 }

 .stats{
  display:grid;
  grid-template-columns:repeat(3,1fr);
  gap:10px;
  margin:25px 0 38px;
 }

 .stat{
  padding:18px 5px;
  border-radius:19px;
  background:linear-gradient(145deg,#1b2942,#121e34);
  border:1px solid #ffffff15;
  box-shadow:0 7px 18px #0003;
 }

 .stat strong{
  display:block;
  font-size:22px;
  color:#fff;
  margin-bottom:6px;
 }

 .stat:nth-child(2) strong{color:#19e7a0}
 .stat:nth-child(3) strong{color:#ffd45b}

 .stat span{
  font-size:12px;
  color:#9baac4;
  letter-spacing:.5px;
 }

 .join-btn{
  display:flex;
  align-items:center;
  justify-content:center;
  width:100%;
  min-height:92px;
  margin:0 auto;
  border-radius:28px;
  background:linear-gradient(100deg,#05c8f5,#328cff,#60b7ff);
  color:#fff;
  font-size:30px;
  font-weight:900;
  text-decoration:none;
  letter-spacing:1px;
  box-shadow:0 0 22px #00baff77,0 10px 28px #007bff44;
  transition:transform .2s,box-shadow .2s;
 }

 .join-btn:active{
  transform:scale(.98);
  box-shadow:0 0 12px #00baff88;
 }

 .join-note{
  color:#91a3c1;
  font-size:13px;
  letter-spacing:2px;
  margin-top:28px;
 }

 .timer-label{
  color:#8998b3;
  font-size:14px;
  margin-top:45px;
  letter-spacing:1px;
 }

 .timer{
  color:#00caff;
  font-size:48px;
  font-weight:900;
  letter-spacing:4px;
  text-shadow:0 0 15px #00bfff,0 0 28px #008cff;
  margin-top:8px;
 }

 @media(max-width:360px){
  .stat strong{font-size:18px}
  .join-btn{min-height:76px;font-size:25px}
  .logo-wrap{width:130px;height:130px}
 }
 </style>
 </head>

 <body>
 <main class="landing">

  <div class="logo-wrap">
   ${p.image_url?`<img src="${url(p.image_url)}" alt="Logo">`:`<div class="logo-placeholder">✦</div>`}
  </div>

  <div class="telegram-label">TELEGRAM</div>

  <div class="small-tag">✨ NUMBER COMMUNITY</div>

  <h1>${esc(p.headline)}</h1>

  <p class="description">${esc(p.description)}</p>

  <section class="stats">
   <div class="stat">
    <strong>LIVE</strong>
    <span>UPDATES</span>
   </div>
   <div class="stat">
    <strong>24/7</strong>
    <span>COMMUNITY</span>
   </div>
   <div class="stat">
    <strong>VIP</strong>
    <span>ACCESS</span>
   </div>
  </section>

  <a class="join-btn" id="joinButton" href="${url(p.button_url)}">
   ${esc(p.button_text||"JOIN NOW")}
  </a>

  <div class="join-note">✦ &nbsp; JOIN OUR TELEGRAM COMMUNITY &nbsp; ✦</div>

  <div class="timer-label">WELCOME TO OUR COMMUNITY</div>
  <div class="timer" id="timer">00:55</div>

 </main>

 <script>
 let seconds=55;
 const timer=document.getElementById("timer");

 setInterval(()=>{
  if(seconds>0)seconds--;
  timer.textContent="00:"+String(seconds).padStart(2,"0");
 },1000);

 let v=localStorage.getItem("ag_vid");

 if(!v){
  v="v_"+(crypto.randomUUID?crypto.randomUUID():Math.random().toString(36).slice(2)+Date.now());
  localStorage.setItem("ag_vid",v);
 }

 const send=t=>fetch("/api/track/${encodeURIComponent(p.slug)}",{
  method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({visitorId:v,eventType:t})
 }).catch(()=>{});

 send("pageview");

 document.getElementById("joinButton").addEventListener("click",()=>{
  send("click");
 });
 </script>

 </body>
 </html>`);
});

app.get("/",(q,s)=>s.sendFile(path.join(__dirname,"public","index.html")));

init().then(()=>{
 app.listen(PORT,()=>console.log("ADS GROWTH AGENCY on "+PORT));
}).catch(e=>{
 console.error(e);
 process.exit(1);
});
