const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const cookieSession = require("cookie-session");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_FILE || "dating.db");

db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  age INTEGER NOT NULL,
  gender TEXT NOT NULL,
  city TEXT NOT NULL,
  bio TEXT DEFAULT '',
  photo TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS likes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_user INTEGER NOT NULL,
  to_user INTEGER NOT NULL,
  UNIQUE(from_user,to_user)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender INTEGER NOT NULL,
  receiver INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter INTEGER NOT NULL,
  reported INTEGER NOT NULL,
  reason TEXT NOT NULL,
  status TEXT DEFAULT 'open',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@tanzaniadating.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin@12345";

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(cookieSession({
  name:"session",
  keys:[process.env.SESSION_SECRET || "change-this-secret"],
  httpOnly:true,
  sameSite:"lax",
  secure: process.env.NODE_ENV === "production"
}));
app.use(express.static(path.join(__dirname, "public")));

function userFromReq(req){
  return req.session?.userId ? db.prepare("SELECT id,name,email,age,gender,city,bio,photo,created_at FROM users WHERE id=?").get(req.session.userId) : null;
}
function requireUser(req,res,next){
  const u=userFromReq(req); if(!u) return res.status(401).json({error:"Login required"}); req.user=u; next();
}
function requireAdmin(req,res,next){
  if(req.session?.admin) return next();
  return res.status(401).json({error:"Admin login required"});
}

app.post("/api/register",(req,res)=>{
  const {name,email,password,age,gender,city,bio="",photo=""}=req.body;
  if(!name||!email||!password||!age||!gender||!city) return res.status(400).json({error:"Fill all required fields"});
  try{
    const hash=bcrypt.hashSync(password,10);
    const info=db.prepare("INSERT INTO users(name,email,password,age,gender,city,bio,photo) VALUES(?,?,?,?,?,?,?,?)")
      .run(name,email.toLowerCase(),hash,Number(age),gender,city,bio,photo);
    req.session.userId=info.lastInsertRowid;
    res.json({ok:true});
  }catch(e){res.status(400).json({error:"Email already exists"});}
});

app.post("/api/login",(req,res)=>{
  const u=db.prepare("SELECT * FROM users WHERE email=?").get((req.body.email||"").toLowerCase());
  if(!u || !bcrypt.compareSync(req.body.password||"",u.password)) return res.status(401).json({error:"Invalid login"});
  req.session.userId=u.id; res.json({ok:true});
});
app.post("/api/logout",(req,res)=>{req.session=null;res.json({ok:true})});
app.get("/api/me",(req,res)=>res.json(userFromReq(req)||null));

app.get("/api/discover",requireUser,(req,res)=>{
  const rows=db.prepare(`
    SELECT id,name,age,gender,city,bio,photo FROM users
    WHERE id<>? AND id NOT IN (SELECT to_user FROM likes WHERE from_user=?)
    ORDER BY id DESC LIMIT 50
  `).all(req.user.id,req.user.id);
  res.json(rows);
});

app.post("/api/like",requireUser,(req,res)=>{
  const to=Number(req.body.userId);
  if(!to || to===req.user.id) return res.status(400).json({error:"Invalid user"});
  db.prepare("INSERT OR IGNORE INTO likes(from_user,to_user) VALUES(?,?)").run(req.user.id,to);
  const mutual=db.prepare("SELECT 1 FROM likes WHERE from_user=? AND to_user=?").get(to,req.user.id);
  res.json({matched:!!mutual});
});

app.get("/api/matches",requireUser,(req,res)=>{
  const rows=db.prepare(`
    SELECT u.id,u.name,u.age,u.city,u.photo FROM users u
    WHERE u.id IN (
      SELECT l1.to_user FROM likes l1 JOIN likes l2 ON l2.from_user=l1.to_user AND l2.to_user=l1.from_user
      WHERE l1.from_user=?
    )
  `).all(req.user.id);
  res.json(rows);
});

app.get("/api/messages/:id",requireUser,(req,res)=>{
  const id=Number(req.params.id);
  const ok=db.prepare(`SELECT 1 FROM likes a JOIN likes b ON b.from_user=a.to_user AND b.to_user=a.from_user WHERE a.from_user=? AND a.to_user=?`).get(req.user.id,id);
  if(!ok) return res.status(403).json({error:"You can chat after matching"});
  res.json(db.prepare(`SELECT m.id,m.sender,m.receiver,m.body,m.created_at,u.name sender_name FROM messages m JOIN users u ON u.id=m.sender WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) ORDER BY m.id`).all(req.user.id,id,id,req.user.id));
});
app.post("/api/messages/:id",requireUser,(req,res)=>{
  const id=Number(req.params.id), body=(req.body.body||"").trim();
  if(!body) return res.status(400).json({error:"Empty message"});
  const ok=db.prepare(`SELECT 1 FROM likes a JOIN likes b ON b.from_user=a.to_user AND b.to_user=a.from_user WHERE a.from_user=? AND a.to_user=?`).get(req.user.id,id);
  if(!ok) return res.status(403).json({error:"Not matched"});
  db.prepare("INSERT INTO messages(sender,receiver,body) VALUES(?,?,?)").run(req.user.id,id,body);
  res.json({ok:true});
});

app.post("/api/report",requireUser,(req,res)=>{
  const id=Number(req.body.userId), reason=(req.body.reason||"").trim();
  if(!id||!reason) return res.status(400).json({error:"User and reason required"});
  db.prepare("INSERT INTO reports(reporter,reported,reason) VALUES(?,?,?)").run(req.user.id,id,reason);
  res.json({ok:true});
});

app.post("/api/profile",requireUser,(req,res)=>{
  const {name,age,gender,city,bio,photo}=req.body;
  db.prepare("UPDATE users SET name=?,age=?,gender=?,city=?,bio=?,photo=? WHERE id=?")
    .run(name,Number(age),gender,city,bio||"",photo||"",req.user.id);
  res.json({ok:true});
});

// Admin
app.post("/api/admin/login",(req,res)=>{
  if(req.body.email===ADMIN_EMAIL && req.body.password===ADMIN_PASSWORD){req.session.admin=true; return res.json({ok:true});}
  res.status(401).json({error:"Invalid admin credentials"});
});
app.post("/api/admin/logout",(req,res)=>{req.session=null;res.json({ok:true})});
app.get("/api/admin/stats",requireAdmin,(req,res)=>{
  res.json({
    users:db.prepare("SELECT COUNT(*) c FROM users").get().c,
    matches:db.prepare("SELECT COUNT(*) c FROM likes").get().c,
    messages:db.prepare("SELECT COUNT(*) c FROM messages").get().c,
    reports:db.prepare("SELECT COUNT(*) c FROM reports WHERE status='open'").get().c
  });
});
app.get("/api/admin/users",requireAdmin,(req,res)=>{
  res.json(db.prepare("SELECT id,name,email,age,gender,city,created_at FROM users ORDER BY id DESC").all());
});
app.delete("/api/admin/users/:id",requireAdmin,(req,res)=>{
  const id=Number(req.params.id);
  db.prepare("DELETE FROM messages WHERE sender=? OR receiver=?").run(id,id);
  db.prepare("DELETE FROM likes WHERE from_user=? OR to_user=?").run(id,id);
  db.prepare("DELETE FROM reports WHERE reporter=? OR reported=?").run(id,id);
  db.prepare("DELETE FROM users WHERE id=?").run(id);
  res.json({ok:true});
});
app.get("/api/admin/reports",requireAdmin,(req,res)=>{
  res.json(db.prepare(`
    SELECT r.id,r.reason,r.status,r.created_at,
      a.name reporter_name,b.name reported_name
    FROM reports r JOIN users a ON a.id=r.reporter JOIN users b ON b.id=r.reported
    ORDER BY r.id DESC
  `).all());
});
app.patch("/api/admin/reports/:id",requireAdmin,(req,res)=>{
  db.prepare("UPDATE reports SET status=? WHERE id=?").run(req.body.status||"closed",Number(req.params.id));
  res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Tanzania Dating running on port ${PORT}`));
