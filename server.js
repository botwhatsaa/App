const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

/* =========================
   DATABASE
========================= */

const DB_FILE = path.join(__dirname, "database.json");

function emptyDB() {
  return {
    users: [],
    likes: [],
    messages: [],
    reports: [],
    notifications: [],
    sessions: []
  };
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const db = emptyDB();
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    return db;
  }

  try {
    const data = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));

    return {
      users: Array.isArray(data.users) ? data.users : [],
      likes: Array.isArray(data.likes) ? data.likes : [],
      messages: Array.isArray(data.messages) ? data.messages : [],
      reports: Array.isArray(data.reports) ? data.reports : [],
      notifications: Array.isArray(data.notifications)
        ? data.notifications
        : [],
      sessions: Array.isArray(data.sessions)
        ? data.sessions
        : []
    };
  } catch (error) {
    console.error("Database error:", error);
    return emptyDB();
  }
}

let db = loadDB();

function saveDB() {
  const tempFile = DB_FILE + ".tmp";

  fs.writeFileSync(
    tempFile,
    JSON.stringify(db, null, 2),
    "utf8"
  );

  fs.renameSync(tempFile, DB_FILE);
}

/* =========================
   PASSWORD
========================= */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `scrypt:${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  if (!String(storedPassword).startsWith("scrypt:")) {
    return storedPassword === password;
  }

  const parts = String(storedPassword).split(":");

  if (parts.length !== 3) {
    return false;
  }

  const salt = parts[1];
  const storedHash = parts[2];

  try {
    const hash = crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(storedHash, "hex")
    );
  } catch {
    return false;
  }
}

/* =========================
   SESSION
========================= */

const SESSION_DAYS = 30;

function createSession(userId, admin = false) {
  const token = crypto.randomBytes(32).toString("hex");

  const session = {
    token,
    userId,
    admin,
    createdAt: Date.now(),
    expiresAt:
      Date.now() +
      SESSION_DAYS * 24 * 60 * 60 * 1000
  };

  db.sessions = db.sessions.filter(
    s => !(String(s.userId) === String(userId) && s.admin === admin)
  );

  db.sessions.push(session);

  saveDB();

  return token;
}

function getSession(req) {
  const cookieHeader = req.headers.cookie || "";

  const match = cookieHeader.match(
    /(?:^|;\s*)session=([^;]+)/
  );

  if (!match) {
    return null;
  }

  const token = decodeURIComponent(match[1]);

  const session = db.sessions.find(
    s => s.token === token
  );

  if (!session) {
    return null;
  }

  if (
    session.expiresAt &&
    Date.now() > session.expiresAt
  ) {
    db.sessions = db.sessions.filter(
      s => s.token !== token
    );

    saveDB();

    return null;
  }

  return session;
}

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    [
      `session=${encodeURIComponent(token)}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`
    ].join("; ")
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
  );
}

/* =========================
   AUTH
========================= */

function requireLogin(req, res, next) {
  const session = getSession(req);

  if (
    !session ||
    !session.userId ||
    session.admin
  ) {
    return res.status(401).json({
      error: "Tafadhali ingia kwanza."
    });
  }

  req.userId = Number(session.userId);

  next();
}

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
   SECURITY / STATIC FILES
========================= */

app.use((req, res, next) => {
  const blocked = [
    "/database.json",
    "/server.js",
    "/package.json",
    "/package-lock.json"
  ];

  if (blocked.includes(req.path)) {
    return res.status(404).end();
  }

  next();
});

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

/* =========================
   REGISTER
========================= */

app.post("/api/register", (req, res) => {
  try {
    const {
      name,
      email,
      password,
      age,
      gender,
      city,
      bio,
      photo
    } = req.body || {};

    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "")
      .trim()
      .toLowerCase();

    const cleanPassword = String(password || "");

    const cleanAge = Number(age);

    const cleanGender = String(gender || "").trim();

    const cleanCity = String(city || "").trim();

    const cleanBio = String(bio || "").trim();

    const cleanPhoto = String(photo || "").trim();

    if (
      !cleanName ||
      !cleanEmail ||
      !cleanPassword ||
      !cleanAge ||
      !cleanGender ||
      !cleanCity
    ) {
      return res.status(400).json({
        error: "Jaza taarifa zote zinazohitajika."
      });
    }

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        cleanEmail
      )
    ) {
      return res.status(400).json({
        error: "Weka email sahihi."
      });
    }

    if (
      cleanPassword.length < 6
    ) {
      return res.status(400).json({
        error:
          "Password iwe na angalau characters 6."
      });
    }

    if (
      cleanAge < 18 ||
      cleanAge > 100
    ) {
      return res.status(400).json({
        error:
          "Umri lazima uwe kati ya miaka 18 na 100."
      });
    }

    const existingUser = db.users.find(
      user =>
        String(user.email)
          .toLowerCase() === cleanEmail
    );

    if (existingUser) {
      return res.status(400).json({
        error:
          "Email hii tayari imesajiliwa."
      });
    }

    const user = {
      id: Date.now(),
      name: cleanName,
      email: cleanEmail,
      password: hashPassword(cleanPassword),
      age: cleanAge,
      gender: cleanGender,
      city: cleanCity,
      bio: cleanBio,
      photo: cleanPhoto,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);

    saveDB();

    const token = createSession(user.id);

    setSessionCookie(res, token);

    return res.json({
      ok: true,
      user: publicUser(user)
    });
  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    return res.status(500).json({
      error:
        "Imeshindikana kujisajili. Jaribu tena."
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", (req, res) => {
  try {
    const email = String(
      req.body?.email || ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body?.password || ""
    );

    if (!email || !password) {
      return res.status(400).json({
        error:
          "Weka email na password."
      });
    }

    const user = db.users.find(
      u =>
        String(u.email)
          .trim()
          .toLowerCase() === email
    );

    if (!user) {
      return res.status(401).json({
        error:
          "Email au password si sahihi."
      });
    }

    const passwordOK = verifyPassword(
      password,
      user.password
    );

    if (!passwordOK) {
      return res.status(401).json({
        error:
          "Email au password si sahihi."
      });
    }

    // Upgrade old plaintext password
    if (
      !String(user.password).startsWith(
        "scrypt:"
      )
    ) {
      user.password =
        hashPassword(password);

      saveDB();
    }

    const token = createSession(
      user.id,
      false
    );

    setSessionCookie(res, token);

    return res.json({
      ok: true,
      user: publicUser(user)
    });
  } catch (error) {
    console.error(
      "LOGIN ERROR:",
      error
    );

    return res.status(500).json({
      error:
        "Imeshindikana kuingia. Jaribu tena."
    });
  }
});

/* =========================
   LOGOUT
========================= */

app.post(
  "/api/logout",
  (req, res) => {
    try {
      const session = getSession(req);

      if (session) {
        db.sessions =
          db.sessions.filter(
            s =>
              s.token !== session.token
          );

        saveDB();
      }

      clearSessionCookie(res);

      return res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        "LOGOUT ERROR:",
        error
      );

      clearSessionCookie(res);

      return res.json({
        ok: true
      });
    }
  }
);

/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/me",
  requireLogin,
  (req, res) => {
    const user = db.users.find(
      u => Number(u.id) === Number(req.userId)
    );

    if (!user) {
      return res.status(404).json({
        error:
          "User hajapatikana."
      });
    }

    res.json(publicUser(user));
  }
);

/* =========================
   DISCOVER
========================= */

app.get(
  "/api/discover",
  requireLogin,
  (req, res) => {
    const users = db.users
      .filter(
        u =>
          Number(u.id) !==
          Number(req.userId)
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
    const targetId = Number(
      req.body?.userId
    );

    if (!Number.isFinite(targetId)) {
      return res.status(400).json({
        error:
          "User ID si sahihi."
      });
    }

    if (
      targetId ===
      Number(req.userId)
    ) {
      return res.status(400).json({
        error:
          "Huwezi kujilike mwenyewe."
      });
    }

    const target = db.users.find(
      u => Number(u.id) === targetId
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
          Number(l.from) ===
            Number(req.userId) &&
          Number(l.to) === targetId
      );

    if (!alreadyLiked) {
      db.likes.push({
        id: Date.now(),
        from: Number(req.userId),
        to: targetId,
        createdAt:
          new Date().toISOString()
      });

      saveDB();
    }

    const mutual =
      db.likes.some(
        l =>
          Number(l.from) === targetId &&
          Number(l.to) ===
            Number(req.userId)
      );

    if (mutual) {
      createNotification({
        userId: targetId,
        type: "match",
        title: "❤️ Match mpya!",
        message:
          `${getUserName(req.userId)} amekumatch.`,
        fromUserId:
          Number(req.userId)
      });
    } else {
      createNotification({
        userId: targetId,
        type: "like",
        title: "❤️ Like mpya",
        message:
          `${getUserName(req.userId)} amekulike.`,
        fromUserId:
          Number(req.userId)
      });
    }

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
    const myId = Number(
      req.userId
    );

    const myLikes =
      db.likes
        .filter(
          l =>
            Number(l.from) === myId
        )
        .map(l => Number(l.to));

    const matches =
      db.likes
        .filter(
          l =>
            Number(l.to) === myId &&
            myLikes.includes(
              Number(l.from)
            )
        )
        .map(l =>
          db.users.find(
            u =>
              Number(u.id) ===
              Number(l.from)
          )
        )
        .filter(Boolean)
        .map(publicUser);

    res.json(matches);
  }
);

/* =========================
   PROFILE
========================= */

app.post(
  "/api/profile",
  requireLogin,
  (req, res) => {
    const user = db.users.find(
      u =>
        Number(u.id) ===
        Number(req.userId)
    );

    if (!user) {
      return res.status(404).json({
        error:
          "User hajapatikana."
      });
    }

    const name = String(
      req.body?.name || ""
    ).trim();

    const age = Number(
      req.body?.age
    );

    const gender = String(
      req.body?.gender ||
        user.gender ||
        ""
    ).trim();

    const city = String(
      req.body?.city || ""
    ).trim();

    const bio = String(
      req.body?.bio || ""
    ).trim();

    const photo = String(
      req.body?.photo || ""
    ).trim();

    if (
      !name ||
      !city ||
      !Number.isFinite(age) ||
      age < 18 ||
      age > 100
    ) {
      return res.status(400).json({
        error:
          "Jina, umri na mji ni lazima ziwe sahihi."
      });
    }

    user.name = name;
    user.age = age;
    user.gender = gender;
    user.city = city;
    user.bio = bio;
    user.photo = photo;

    saveDB();

    res.json({
      ok: true,
      user: publicUser(user)
    });
  }
);

/* =========================
   MESSAGES
========================= */

app.get(
  "/api/messages/:id",
  requireLogin,
  (req, res) => {
    const otherId = Number(
      req.params.id
    );

    const otherUser = db.users.find(
      u =>
        Number(u.id) ===
        otherId
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
            Number(m.sender) ===
              Number(req.userId) &&
            Number(m.receiver) ===
              otherId
          ) ||
          (
            Number(m.sender) ===
              otherId &&
            Number(m.receiver) ===
              Number(req.userId)
          )
      );

    res.json(messages);
  }
);

app.post(
  "/api/messages/:id",
  requireLogin,
  (req, res) => {
    const receiver = Number(
      req.params.id
    );

    const body = String(
      req.body?.body || ""
    ).trim();

    if (!body) {
      return res.status(400).json({
        error:
          "Ujumbe hauwezi kuwa tupu."
      });
    }

    if (body.length > 2000) {
      return res.status(400).json({
        error:
          "Ujumbe ni mrefu sana."
      });
    }

    if (
      receiver ===
      Number(req.userId)
    ) {
      return res.status(400).json({
        error:
          "Huwezi kujitumia ujumbe."
      });
    }

    const target = db.users.find(
      u =>
        Number(u.id) ===
        receiver
    );

    if (!target) {
      return res.status(404).json({
        error:
          "User hajapatikana."
      });
    }

    const message = {
      id: Date.now(),
      sender: Number(req.userId),
      receiver,
      body,
      createdAt:
        new Date().toISOString()
    };

    db.messages.push(message);

    saveDB();

    createNotification({
      userId: receiver,
      type: "message",
      title: "💬 Ujumbe mpya",
      message:
        `${getUserName(req.userId)} amekutumia ujumbe.`,
      fromUserId:
        Number(req.userId),
      relatedId: message.id
    });

    res.json({
      ok: true,
      message
    });
  }
);

/* =========================
   NOTIFICATIONS
========================= */

function createNotification({
  userId,
  type,
  title,
  message,
  fromUserId = null,
  relatedId = null
}) {
  db.notifications.push({
    id: Date.now() + Math.floor(Math.random() * 1000),
    userId: Number(userId),
    type,
    title,
    message,
    fromUserId:
      fromUserId !== null
        ? Number(fromUserId)
        : null,
    relatedId,
    read: false,
    createdAt:
      new Date().toISOString()
  });

  saveDB();
}

function getUserName(userId) {
  const user = db.users.find(
    u =>
      Number(u.id) ===
      Number(userId)
  );

  return user
    ? user.name
    : "Mtu";
}

app.get(
  "/api/notifications",
  requireLogin,
  (req, res) => {
    const notifications =
      db.notifications
        .filter(
          n =>
            Number(n.userId) ===
            Number(req.userId)
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    const unread =
      notifications.filter(
        n => !n.read
      ).length;

    res.json({
      notifications,
      unread
    });
  }
);

app.post(
  "/api/notifications/read-all",
  requireLogin,
  (req, res) => {
    db.notifications.forEach(
      n => {
        if (
          Number(n.userId) ===
          Number(req.userId)
        ) {
          n.read = true;
        }
      }
    );

    saveDB();

    res.json({
      ok: true
    });
  }
);

/* =========================
   REPORT
========================= */

app.post(
  "/api/report",
  requireLogin,
  (req, res) => {
    const userId = Number(
      req.body?.userId
    );

    const reason = String(
      req.body?.reason || ""
    ).trim();

    if (!reason) {
      return res.status(400).json({
        error:
          "Andika sababu ya ripoti."
      });
    }

    if (
      userId ===
      Number(req.userId)
    ) {
      return res.status(400).json({
        error:
          "Huwezi kujireport mwenyewe."
      });
    }

    const reportedUser =
      db.users.find(
        u =>
          Number(u.id) ===
          userId
      );

    if (!reportedUser) {
      return res.status(404).json({
        error:
          "User hajapatikana."
      });
    }

    db.reports.push({
      id: Date.now(),
      reporter:
        Number(req.userId),
      reported: userId,
      reason,
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
    const adminEmail =
      process.env.ADMIN_EMAIL;

    const adminPassword =
      process.env.ADMIN_PASSWORD;

    if (
      !adminEmail ||
      !adminPassword
    ) {
      return res.status(503).json({
        error:
          "Admin credentials hazijawekwa kwenye Environment Variables."
      });
    }

    const email = String(
      req.body?.email || ""
    ).trim();

    const password = String(
      req.body?.password || ""
    );

    if (
      email !== adminEmail ||
      password !== adminPassword
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

    setSessionCookie(
      res,
      token
    );

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
    const pairs = new Set();

    for (const like of db.likes) {
      const mutual =
        db.likes.some(
          other =>
            Number(other.from) ===
              Number(like.to) &&
            Number(other.to) ===
              Number(like.from)
        );

      if (mutual) {
        pairs.add(
          [
            Number(like.from),
            Number(like.to)
          ]
            .sort((a, b) => a - b)
            .join(":")
        );
      }
    }

    res.json({
      users: db.users.length,
      matches: pairs.size,
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
      db.users.map(publicUser)
    );
  }
);

app.delete(
  "/api/admin/users/:id",
  requireAdmin,
  (req, res) => {
    const id = Number(
      req.params.id
    );

    if (
      !db.users.some(
        u =>
          Number(u.id) === id
      )
    ) {
      return res.status(404).json({
        error:
          "User hajapatikana."
      });
    }

    db.users =
      db.users.filter(
        u =>
          Number(u.id) !== id
      );

    db.likes =
      db.likes.filter(
        l =>
          Number(l.from) !== id &&
          Number(l.to) !== id
      );

    db.messages =
      db.messages.filter(
        m =>
          Number(m.sender) !== id &&
          Number(m.receiver) !== id
      );

    db.reports =
      db.reports.filter(
        r =>
          Number(r.reporter) !== id &&
          Number(r.reported) !== id
      );

    db.notifications =
      db.notifications.filter(
        n =>
          Number(n.userId) !== id &&
          Number(n.fromUserId) !== id
      );

    db.sessions =
      db.sessions.filter(
        s =>
          String(s.userId) !==
          String(id)
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
      db.reports.map(
        report => {
          const reported =
            db.users.find(
              u =>
                Number(u.id) ===
                Number(report.reported)
            );

          const reporter =
            db.users.find(
              u =>
                Number(u.id) ===
                Number(report.reporter)
            );

          return {
            id: report.id,
            reporter_name:
              reporter
                ? reporter.name
                : "Deleted user",
            reported_name:
              reported
                ? reported.name
                : "Deleted user",
            reason:
              report.reason,
            status:
              report.status,
            createdAt:
              report.createdAt
          };
        }
      );

    res.json(reports);
  }
);

/* =========================
   ADMIN REPORT STATUS
========================= */

app.patch(
  "/api/admin/reports/:id",
  requireAdmin,
  (req, res) => {
    const id = Number(
      req.params.id
    );

    const report =
      db.reports.find(
        r =>
          Number(r.id) === id
      );

    if (!report) {
      return res.status(404).json({
        error:
          "Report haijapatikana."
      });
    }

    const status = String(
      req.body?.status ||
        "closed"
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
    createdAt: user.createdAt
  };
}

/* =========================
   API 404
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
