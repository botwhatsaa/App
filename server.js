const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================
   MIDDLEWARE
========================= */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* Serve frontend */
app.use(express.static(__dirname));

/* =========================
   DATABASE
========================= */

const DB_FILE = path.join(__dirname, "database.json");

function emptyDB() {
  return {
    users: [],
    likes: [],
    messages: [],
    reports: []
  };
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const db = emptyDB();

    fs.writeFileSync(
      DB_FILE,
      JSON.stringify(db, null, 2)
    );

    return db;
  }

  try {
    const data = JSON.parse(
      fs.readFileSync(DB_FILE, "utf8")
    );

    return {
      users: Array.isArray(data.users) ? data.users : [],
      likes: Array.isArray(data.likes) ? data.likes : [],
      messages: Array.isArray(data.messages)
        ? data.messages
        : [],
      reports: Array.isArray(data.reports)
        ? data.reports
        : []
    };

  } catch (error) {

    console.error("Database error:", error);

    return emptyDB();
  }
}

let db = loadDB();

function saveDB() {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(db, null, 2)
  );
}

/* =========================
   SESSIONS
========================= */

const sessions = new Map();

function createSession(userId, admin = false) {

  const token =
    crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    userId,
    admin,
    createdAt: Date.now()
  });

  return token;
}

function getSession(req) {

  const cookie =
    req.headers.cookie || "";

  const match =
    cookie.match(/(?:^|;\s*)session=([^;]+)/);

  if (!match) {
    return null;
  }

  return sessions.get(match[1]) || null;
}

function setSession(res, token) {

  res.setHeader(
    "Set-Cookie",
    `session=${token}; Path=/; HttpOnly; SameSite=Lax`
  );
}

/* =========================
   LOGIN MIDDLEWARE
========================= */

function requireLogin(req, res, next) {

  const session = getSession(req);

  if (!session || !session.userId) {

    return res.status(401).json({
      error: "Tafadhali ingia kwanza."
    });
  }

  req.userId = Number(session.userId);

  next();
}

/* =========================
   ADMIN MIDDLEWARE
========================= */

function requireAdmin(req, res, next) {

  const session = getSession(req);

  if (!session || !session.admin) {

    return res.status(401).json({
      error: "Admin login required."
    });
  }

  next();
}

/* =========================
   HOME
========================= */

app.get("/", (req, res) => {

  res.sendFile(
    path.join(__dirname, "index.html")
  );

});

/* =========================
   REGISTER
========================= */

app.post("/api/register", (req, res) => {

  const {
    name,
    email,
    password,
    age,
    gender,
    city,
    bio,
    photo
  } = req.body;

  if (
    !name ||
    !email ||
    !password ||
    !age ||
    !gender ||
    !city
  ) {

    return res.status(400).json({
      error:
        "Jaza taarifa zote zinazohitajika."
    });

  }

  const cleanName =
    String(name).trim();

  const cleanEmail =
    String(email).trim().toLowerCase();

  const cleanPassword =
    String(password);

  const cleanAge =
    Number(age);

  const cleanCity =
    String(city).trim();

  if (cleanAge < 18) {

    return res.status(400).json({
      error:
        "Ni lazima uwe na miaka 18 au zaidi."
    });

  }

  if (cleanPassword.length < 6) {

    return res.status(400).json({
      error:
        "Password iwe na angalau characters 6."
    });

  }

  const existing =
    db.users.find(
      u =>
        String(u.email).toLowerCase() ===
        cleanEmail
    );

  if (existing) {

    return res.status(400).json({
      error:
        "Email hii tayari imesajiliwa."
    });

  }

  const user = {

    id: Date.now(),

    name: cleanName,

    email: cleanEmail,

    password: cleanPassword,

    age: cleanAge,

    gender: String(gender),

    city: cleanCity,

    bio: String(bio || "").trim(),

    photo: String(photo || "").trim(),

    createdAt:
      new Date().toISOString()

  };

  db.users.push(user);

  saveDB();

  const token =
    createSession(user.id);

  setSession(res, token);

  res.json({

    ok: true,

    user: publicUser(user)

  });

});

/* =========================
   LOGIN
========================= */

app.post("/api/login", (req, res) => {

  const {
    email,
    password
  } = req.body;

  const cleanEmail =
    String(email || "")
      .trim()
      .toLowerCase();

  const cleanPassword =
    String(password || "");

  const user =
    db.users.find(
      u =>
        String(u.email).toLowerCase() ===
          cleanEmail &&
        u.password === cleanPassword
    );

  if (!user) {

    return res.status(401).json({
      error:
        "Email au password si sahihi."
    });

  }

  const token =
    createSession(user.id);

  setSession(res, token);

  res.json({

    ok: true,

    user: publicUser(user)

  });

});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {

  const session =
    getSession(req);

  if (session) {

    const cookie =
      req.headers.cookie || "";

    const match =
      cookie.match(
        /(?:^|;\s*)session=([^;]+)/
      );

    if (match) {
      sessions.delete(match[1]);
    }

  }

  res.setHeader(
    "Set-Cookie",
    "session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax"
  );

  res.json({
    ok: true
  });

});

/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/me",
  requireLogin,
  (req, res) => {

    const user =
      db.users.find(
        u => u.id === req.userId
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User hajapatikana."
      });

    }

    res.json(
      publicUser(user)
    );

  }
);

/* =========================
   DISCOVER
========================= */

app.get(
  "/api/discover",
  requireLogin,
  (req, res) => {

    const users =
      db.users
        .filter(
          u => u.id !== req.userId
        )
        .map(publicUser);

    res.json(users);

  }
);

/* =========================
   LIKE
========================= */

app.post(
  "/api/like",
  requireLogin,
  (req, res) => {

    const targetId =
      Number(req.body.userId);

    if (!Number.isFinite(targetId)) {

      return res.status(400).json({
        error:
          "User ID si sahihi."
      });

    }

    if (targetId === req.userId) {

      return res.status(400).json({
        error:
          "Huwezi kujilike mwenyewe."
      });

    }

    const target =
      db.users.find(
        u => u.id === targetId
      );

    if (!target) {

      return res.status(404).json({
        error:
          "User hajapatikana."
      });

    }

    const alreadyLiked =
      db.likes.find(
        l =>
          l.from === req.userId &&
          l.to === targetId
      );

    if (!alreadyLiked) {

      db.likes.push({

        id: Date.now(),

        from: req.userId,

        to: targetId,

        createdAt:
          new Date().toISOString()

      });

      saveDB();

    }

    const mutual =
      db.likes.some(
        l =>
          l.from === targetId &&
          l.to === req.userId
      );

    res.json({

      ok: true,

      matched: mutual

    });

  }
);

/* =========================
   MATCHES
========================= */

app.get(
  "/api/matches",
  requireLogin,
  (req, res) => {

    const myLikes =
      db.likes
        .filter(
          l => l.from === req.userId
        )
        .map(l => l.to);

    const matches =
      db.likes
        .filter(
          l =>
            l.to === req.userId &&
            myLikes.includes(l.from)
        )
        .map(
          l =>
            db.users.find(
              u => u.id === l.from
            )
        )
        .filter(Boolean)
        .map(publicUser);

    res.json(matches);

  }
);

/* =========================
   PROFILE UPDATE
========================= */

app.post(
  "/api/profile",
  requireLogin,
  (req, res) => {

    const user =
      db.users.find(
        u => u.id === req.userId
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User hajapatikana."
      });

    }

    const {
      name,
      age,
      gender,
      city,
      bio,
      photo
    } = req.body;

    if (name) {
      user.name =
        String(name).trim();
    }

    if (age) {

      const newAge =
        Number(age);

      if (newAge >= 18) {
        user.age = newAge;
      }

    }

    if (gender) {
      user.gender =
        String(gender);
    }

    if (city) {
      user.city =
        String(city).trim();
    }

    user.bio =
      String(bio || "").trim();

    user.photo =
      String(photo || "").trim();

    saveDB();

    res.json({

      ok: true,

      user: publicUser(user)

    });

  }
);

/* =========================
   MESSAGES - GET
========================= */

app.get(
  "/api/messages/:id",
  requireLogin,
  (req, res) => {

    const otherId =
      Number(req.params.id);

    const otherUser =
      db.users.find(
        u => u.id === otherId
      );

    if (!otherUser) {

      return res.status(404).json({
        error:
          "User hajapatikana."
      });

    }

    const messages =
      db.messages.filter(
        m =>
          (
            m.sender === req.userId &&
            m.receiver === otherId
          ) ||
          (
            m.sender === otherId &&
            m.receiver === req.userId
          )
      );

    res.json(messages);

  }
);

/* =========================
   MESSAGES - SEND
========================= */

app.post(
  "/api/messages/:id",
  requireLogin,
  (req, res) => {

    const receiver =
      Number(req.params.id);

    const body =
      String(
        req.body.body || ""
      ).trim();

    if (!body) {

      return res.status(400).json({
        error:
          "Ujumbe hauwezi kuwa tupu."
      });

    }

    const user =
      db.users.find(
        u => u.id === receiver
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User hajapatikana."
      });

    }

    if (receiver === req.userId) {

      return res.status(400).json({
        error:
          "Huwezi kujitumia ujumbe."
      });

    }

    const message = {

      id: Date.now(),

      sender: req.userId,

      receiver: receiver,

      body: body,

      createdAt:
        new Date().toISOString()

    };

    db.messages.push(message);

    saveDB();

    res.json({

      ok: true,

      message

    });

  }
);

/* =========================
   REPORT USER
========================= */

app.post(
  "/api/report",
  requireLogin,
  (req, res) => {

    const userId =
      Number(req.body.userId);

    const reason =
      String(
        req.body.reason || ""
      ).trim();

    if (!reason) {

      return res.status(400).json({
        error:
          "Andika sababu ya ripoti."
      });

    }

    const reportedUser =
      db.users.find(
        u => u.id === userId
      );

    if (!reportedUser) {

      return res.status(404).json({
        error:
          "User hajapatikana."
      });

    }

    if (userId === req.userId) {

      return res.status(400).json({
        error:
          "Huwezi kujireport mwenyewe."
      });

    }

    db.reports.push({

      id: Date.now(),

      reporter: req.userId,

      reported: userId,

      reason: reason,

      status: "open",

      createdAt:
        new Date().toISOString()

    });

    saveDB();

    res.json({
      ok: true
    });

  }
);

/* =========================
   ADMIN LOGIN
========================= */

app.post(
  "/api/admin/login",
  (req, res) => {

    const {
      email,
      password
    } = req.body;

    const adminEmail =
      process.env.ADMIN_EMAIL ||
      "admin@tanzaniadating.com";

    const adminPassword =
      process.env.ADMIN_PASSWORD ||
      "Admin@12345";

    if (
      String(email || "").trim() !==
        adminEmail ||
      String(password || "") !==
        adminPassword
    ) {

      return res.status(401).json({
        error:
          "Admin email au password si sahihi."
      });

    }

    const token =
      createSession(
        "admin",
        true
      );

    setSession(res, token);

    res.json({
      ok: true
    });

  }
);

/* =========================
   ADMIN STATS
========================= */

app.get(
  "/api/admin/stats",
  requireAdmin,
  (req, res) => {

    const uniqueMatches =
      db.likes.filter(
        like => {

          return db.likes.some(
            other =>
              other.from === like.to &&
              other.to === like.from
          );

        }
      ).length / 2;

    res.json({

      users:
        db.users.length,

      matches:
        uniqueMatches,

      messages:
        db.messages.length,

      reports:
        db.reports.filter(
          r => r.status === "open"
        ).length

    });

  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  "/api/admin/users",
  requireAdmin,
  (req, res) => {

    res.json(
      db.users.map(
        publicUser
      )
    );

  }
);

/* =========================
   ADMIN DELETE USER
========================= */

app.delete(
  "/api/admin/users/:id",
  requireAdmin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const exists =
      db.users.some(
        u => u.id === id
      );

    if (!exists) {

      return res.status(404).json({
        error:
          "User hajapatikana."
      });

    }

    db.users =
      db.users.filter(
        u => u.id !== id
      );

    db.likes =
      db.likes.filter(
        l =>
          l.from !== id &&
          l.to !== id
      );

    db.messages =
      db.messages.filter(
        m =>
          m.sender !== id &&
          m.receiver !== id
      );

    db.reports =
      db.reports.filter(
        r =>
          r.reporter !== id &&
          r.reported !== id
      );

    saveDB();

    res.json({
      ok: true
    });

  }
);

/* =========================
   ADMIN REPORTS
========================= */

app.get(
  "/api/admin/reports",
  requireAdmin,
  (req, res) => {

    const reports =
      db.reports.map(r => {

        const reported =
          db.users.find(
            u => u.id === r.reported
          );

        const reporter =
          db.users.find(
            u => u.id === r.reporter
          );

        return {

          id: r.id,

          reporter_name:
            reporter
              ? reporter.name
              : "Deleted user",

          reported_name:
            reported
              ? reported.name
              : "Deleted user",

          reason:
            r.reason,

          status:
            r.status,

          createdAt:
            r.createdAt

        };

      });

    res.json(reports);

  }
);

/* =========================
   ADMIN CLOSE REPORT
========================= */

app.patch(
  "/api/admin/reports/:id",
  requireAdmin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const report =
      db.reports.find(
        r => r.id === id
      );

    if (!report) {

      return res.status(404).json({
        error:
          "Report haijapatikana."
      });

    }

    const status =
      String(
        req.body.status || "closed"
      );

    report.status =
      status === "open"
        ? "open"
        : "closed";

    saveDB();

    res.json({
      ok: true
    });

  }
);

/* =========================
   PUBLIC USER
========================= */

function publicUser(user) {

  return {

    id: user.id,

    name: user.name,

    email: user.email,

    age: user.age,

    gender: user.gender,

    city: user.city,

    bio: user.bio,

    photo: user.photo,

    createdAt:
      user.createdAt

  };

}

/* =========================
   404 API
========================= */

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({
      error:
        "API endpoint haijapatikana."
    });

  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (err, req, res, next) => {

    console.error(
      "SERVER ERROR:",
      err
    );

    res.status(500).json({
      error:
        "Server error."
    });

  }
);

/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `Tanzania Dating running on port ${PORT}`
    );

  }
);
