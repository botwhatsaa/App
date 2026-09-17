const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;
const DB_FILE = path.join(__dirname, "database.json");

const MAX_PHOTO_BYTES = 5 * 1024 * 1024;

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

function defaultDB() {
  return {
    users: [],
    likes: [],
    messages: [],
    reports: [],
    notifications: []
  };
}

function loadDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const fresh = defaultDB();
      fs.writeFileSync(DB_FILE, JSON.stringify(fresh, null, 2));
      return fresh;
    }

    const raw = fs.readFileSync(DB_FILE, "utf8");
    if (!raw.trim()) return defaultDB();

    const data = JSON.parse(raw);

    return {
      users: Array.isArray(data.users) ? data.users : [],
      likes: Array.isArray(data.likes) ? data.likes : [],
      messages: Array.isArray(data.messages) ? data.messages : [],
      reports: Array.isArray(data.reports) ? data.reports : [],
      notifications: Array.isArray(data.notifications)
        ? data.notifications
        : []
    };
  } catch (err) {
    console.error("Database load error:", err);
    return defaultDB();
  }
}

let db = loadDB();

function saveDB() {
  const temp = DB_FILE + ".tmp";

  fs.writeFileSync(
    temp,
    JSON.stringify(db, null, 2),
    "utf8"
  );

  fs.renameSync(temp, DB_FILE);
}

function makeId() {
  return crypto.randomBytes(12).toString("hex");
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

/* =========================
   PASSWORD
========================= */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto.scryptSync(
    String(password),
    salt,
    64
  ).toString("hex");

  return `scrypt:${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;

  if (String(stored).startsWith("scrypt:")) {
    const parts = String(stored).split(":");

    if (parts.length !== 3) return false;

    const salt = parts[1];
    const originalHash = parts[2];

    const newHash = crypto.scryptSync(
      String(password),
      salt,
      64
    ).toString("hex");

    try {
      return crypto.timingSafeEqual(
        Buffer.from(originalHash, "hex"),
        Buffer.from(newHash, "hex")
      );
    } catch {
      return false;
    }
  }

  return String(password) === String(stored);
}

/* =========================
   PHOTO
========================= */

function validatePhoto(photo) {
  if (!photo) {
    return {
      ok: true,
      value: ""
    };
  }

  if (typeof photo !== "string") {
    return {
      ok: false,
      error: "Picha sio sahihi."
    };
  }

  const match = photo.match(
    /^data:(image\/jpeg|image\/png|image\/webp);base64,([A-Za-z0-9+/=\s]+)$/
  );

  if (!match) {
    return {
      ok: false,
      error: "Picha lazima iwe JPG, PNG au WEBP."
    };
  }

  const mime = match[1];
  const base64 = match[2].replace(/\s/g, "");

  let buffer;

  try {
    buffer = Buffer.from(base64, "base64");
  } catch {
    return {
      ok: false,
      error: "Picha haijasomeka."
    };
  }

  if (!buffer.length) {
    return {
      ok: false,
      error: "Picha haina data."
    };
  }

  if (buffer.length > MAX_PHOTO_BYTES) {
    return {
      ok: false,
      error: "Picha ni kubwa sana. Maximum ni 5MB."
    };
  }

  return {
    ok: true,
    value: `data:${mime};base64,${base64}`
  };
}

/* =========================
   PUBLIC USER
========================= */

function publicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    age: user.age,
    gender: user.gender,
    city: user.city,
    bio: user.bio || "",
    photo: user.photo || "",
    createdAt: user.createdAt
  };
}

/* =========================
   SESSIONS
========================= */

const sessions = new Map();

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    userId,
    createdAt: Date.now()
  });

  return token;
}

function getSessionUser(req) {
  const cookie = req.headers.cookie || "";

  const match = cookie.match(
    /(?:^|;\s*)session=([^;]+)/
  );

  if (!match) return null;

  const token = decodeURIComponent(match[1]);
  const session = sessions.get(token);

  if (!session) return null;

  return db.users.find(
    u => String(u.id) === String(session.userId)
  ) || null;
}

function requireAuth(req, res, next) {
  const user = getSessionUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Tafadhali ingia kwanza."
    });
  }

  req.user = user;
  next();
}

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"
  );
}

/* =========================
   NOTIFICATION HELPER
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
    id: makeId(),
    userId,
    type,
    title,
    message,
    fromUserId,
    relatedId,
    read: false,
    createdAt: new Date().toISOString()
  });
}

/* =========================
   SECURITY
========================= */

app.use((req, res, next) => {
  const blocked = [
    "/database.json",
    "/server.js",
    "/package.json",
    "/.env"
  ];

  if (blocked.includes(req.path)) {
    return res.status(403).send("Forbidden");
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
    const name = String(req.body.name || "").trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const age = Number(req.body.age);
    const gender = String(req.body.gender || "").trim();
    const city = String(req.body.city || "").trim();
    const bio = String(req.body.bio || "").trim();
    const photo = req.body.photo || "";

    if (!name) {
      return res.status(400).json({
        error: "Jina linahitajika."
      });
    }

    if (!email || !email.includes("@")) {
      return res.status(400).json({
        error: "Email sio sahihi."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password lazima iwe na characters 6 au zaidi."
      });
    }

    if (!Number.isInteger(age) || age < 18 || age > 100) {
      return res.status(400).json({
        error: "Umri lazima uwe kati ya 18 na 100."
      });
    }

    if (!gender) {
      return res.status(400).json({
        error: "Chagua jinsia."
      });
    }

    if (!city) {
      return res.status(400).json({
        error: "Mji unahitajika."
      });
    }

    if (bio.length > 500) {
      return res.status(400).json({
        error: "Bio ni refu sana."
      });
    }

    const existing = db.users.find(
      u => normalizeEmail(u.email) === email
    );

    if (existing) {
      return res.status(409).json({
        error: "Email hii tayari imesajiliwa."
      });
    }

    const photoResult = validatePhoto(photo);

    if (!photoResult.ok) {
      return res.status(400).json({
        error: photoResult.error
      });
    }

    const user = {
      id: makeId(),
      name,
      email,
      password: hashPassword(password),
      age,
      gender,
      city,
      bio,
      photo: photoResult.value,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    saveDB();

    const token = createSession(user.id);
    setSessionCookie(res, token);

    res.json({
      ok: true,
      user: publicUser(user)
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Imeshindikana kusajili account."
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    const user = db.users.find(
      u => normalizeEmail(u.email) === email
    );

    if (!user) {
      return res.status(401).json({
        error: "Email au password sio sahihi."
      });
    }

    if (!verifyPassword(password, user.password)) {
      return res.status(401).json({
        error: "Email au password sio sahihi."
      });
    }

    if (!String(user.password).startsWith("scrypt:")) {
      user.password = hashPassword(password);
      saveDB();
    }

    const token = createSession(user.id);
    setSessionCookie(res, token);

    res.json({
      ok: true,
      user: publicUser(user)
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Imeshindikana kuingia."
    });
  }
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {
  const cookie = req.headers.cookie || "";

  const match = cookie.match(
    /(?:^|;\s*)session=([^;]+)/
  );

  if (match) {
    sessions.delete(
      decodeURIComponent(match[1])
    );
  }

  clearSessionCookie(res);

  res.json({
    ok: true
  });
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    user: publicUser(req.user)
  });
});

/* =========================
   DISCOVER
========================= */

app.get("/api/discover", requireAuth, (req, res) => {
  const myId = String(req.user.id);

  const likedIds = new Set(
    db.likes
      .filter(l => String(l.from) === myId)
      .map(l => String(l.to))
  );

  const users = db.users
    .filter(u => String(u.id) !== myId)
    .filter(u => !likedIds.has(String(u.id)))
    .map(publicUser);

  res.json(users);
});

/* =========================
   LIKE
========================= */

app.post("/api/like", requireAuth, (req, res) => {
  try {
    const targetId = String(
      req.body.userId || ""
    );

    if (!targetId) {
      return res.status(400).json({
        error: "User ID inahitajika."
      });
    }

    if (targetId === String(req.user.id)) {
      return res.status(400).json({
        error: "Huwezi kujilike mwenyewe."
      });
    }

    const target = db.users.find(
      u => String(u.id) === targetId
    );

    if (!target) {
      return res.status(404).json({
        error: "User hakupatikana."
      });
    }

    const alreadyLiked = db.likes.some(
      l =>
        String(l.from) === String(req.user.id) &&
        String(l.to) === targetId
    );

    if (alreadyLiked) {
      return res.json({
        ok: true,
        matched: false
      });
    }

    const likeId = makeId();

    db.likes.push({
      id: likeId,
      from: req.user.id,
      to: target.id,
      createdAt: new Date().toISOString()
    });

    /* Notification ya Like */
    createNotification({
      userId: target.id,
      type: "like",
      title: "❤️ Umepewa Like",
      message: `${req.user.name} amekupenda.`,
      fromUserId: req.user.id,
      relatedId: likeId
    });

    const matched = db.likes.some(
      l =>
        String(l.from) === targetId &&
        String(l.to) === String(req.user.id)
    );

    /* Notification ya Match */
    if (matched) {
      createNotification({
        userId: target.id,
        type: "match",
        title: "❤️ Match mpya!",
        message: `Wewe na ${req.user.name} mmekuwa Match.`,
        fromUserId: req.user.id,
        relatedId: target.id
      });

      createNotification({
        userId: req.user.id,
        type: "match",
        title: "❤️ Match mpya!",
        message: `Wewe na ${target.name} mmekuwa Match.`,
        fromUserId: target.id,
        relatedId: target.id
      });
    }

    saveDB();

    res.json({
      ok: true,
      matched
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Like imeshindikana."
    });
  }
});

/* =========================
   MATCHES
========================= */

app.get("/api/matches", requireAuth, (req, res) => {
  const myId = String(req.user.id);

  const matches = db.users.filter(user => {
    const id = String(user.id);

    const iLikedThem = db.likes.some(
      l =>
        String(l.from) === myId &&
        String(l.to) === id
    );

    const theyLikedMe = db.likes.some(
      l =>
        String(l.from) === id &&
        String(l.to) === myId
    );

    return iLikedThem && theyLikedMe;
  });

  res.json(
    matches.map(publicUser)
  );
});

/* =========================
   PROFILE
========================= */

app.post("/api/profile", requireAuth, (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const age = Number(req.body.age);
    const gender = String(req.body.gender || "").trim();
    const city = String(req.body.city || "").trim();
    const bio = String(req.body.bio || "").trim();

    const photo =
      typeof req.body.photo === "string"
        ? req.body.photo
        : req.user.photo || "";

    if (!name) {
      return res.status(400).json({
        error: "Jina linahitajika."
      });
    }

    if (!Number.isInteger(age) || age < 18 || age > 100) {
      return res.status(400).json({
        error: "Umri lazima uwe kati ya 18 na 100."
      });
    }

    if (!gender || !city) {
      return res.status(400).json({
        error: "Jinsia na mji vinahitajika."
      });
    }

    if (bio.length > 500) {
      return res.status(400).json({
        error: "Bio ni refu sana."
      });
    }

    const photoResult = validatePhoto(photo);

    if (!photoResult.ok) {
      return res.status(400).json({
        error: photoResult.error
      });
    }

    req.user.name = name;
    req.user.age = age;
    req.user.gender = gender;
    req.user.city = city;
    req.user.bio = bio;
    req.user.photo = photoResult.value;

    saveDB();

    res.json({
      ok: true,
      user: publicUser(req.user)
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Profile haijahifadhiwa."
    });
  }
});

/* =========================
   NOTIFICATIONS
========================= */

app.get(
  "/api/notifications",
  requireAuth,
  (req, res) => {
    const myId = String(req.user.id);

    const notifications = db.notifications
      .filter(n => String(n.userId) === myId)
      .sort(
        (a, b) =>
          new Date(b.createdAt) -
          new Date(a.createdAt)
      )
      .slice(0, 100);

    const unread = notifications.filter(
      n => !n.read
    ).length;

    res.json({
      notifications,
      unread
    });
  }
);

/* =========================
   MARK NOTIFICATIONS READ
========================= */

app.post(
  "/api/notifications/read-all",
  requireAuth,
  (req, res) => {
    const myId = String(req.user.id);

    db.notifications.forEach(n => {
      if (String(n.userId) === myId) {
        n.read = true;
      }
    });

    saveDB();

    res.json({
      ok: true
    });
  }
);

/* =========================
   MESSAGES
========================= */

app.get(
  "/api/messages/:id",
  requireAuth,
  (req, res) => {
    const otherId = String(req.params.id);
    const myId = String(req.user.id);

    const messages = db.messages
      .filter(m =>
        (
          String(m.sender) === myId &&
          String(m.receiver) === otherId
        ) ||
        (
          String(m.sender) === otherId &&
          String(m.receiver) === myId
        )
      )
      .map(m => ({
        id: m.id,
        sender: m.sender,
        receiver: m.receiver,
        body: m.body,
        createdAt: m.createdAt
      }));

    res.json(messages);
  }
);

app.post(
  "/api/messages/:id",
  requireAuth,
  (req, res) => {
    try {
      const receiverId = String(
        req.params.id
      );

      const body = String(
        req.body.body || ""
      ).trim();

      if (!body) {
        return res.status(400).json({
          error: "Ujumbe hauwezi kuwa empty."
        });
      }

      if (body.length > 2000) {
        return res.status(400).json({
          error: "Ujumbe ni mrefu sana."
        });
      }

      const receiver = db.users.find(
        u => String(u.id) === receiverId
      );

      if (!receiver) {
        return res.status(404).json({
          error: "User hakupatikana."
        });
      }

      const message = {
        id: makeId(),
        sender: req.user.id,
        receiver: receiver.id,
        body,
        createdAt: new Date().toISOString()
      };

      db.messages.push(message);

      /* Notification ya ujumbe */
      createNotification({
        userId: receiver.id,
        type: "message",
        title: "💬 Ujumbe mpya",
        message: `${req.user.name} amekutumia ujumbe.`,
        fromUserId: req.user.id,
        relatedId: message.id
      });

      saveDB();

      res.json({
        ok: true,
        message
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Ujumbe haujatumwa."
      });
    }
  }
);

/* =========================
   REPORT
========================= */

app.post(
  "/api/report",
  requireAuth,
  (req, res) => {
    try {
      const userId = String(
        req.body.userId || ""
      );

      const reason = String(
        req.body.reason || ""
      ).trim();

      if (!userId || !reason) {
        return res.status(400).json({
          error: "User na sababu vinahitajika."
        });
      }

      const user = db.users.find(
        u => String(u.id) === userId
      );

      if (!user) {
        return res.status(404).json({
          error: "User hakupatikana."
        });
      }

      db.reports.push({
        id: makeId(),
        reporter: req.user.id,
        reportedUser: user.id,
        reason,
        status: "open",
        createdAt: new Date().toISOString()
      });

      saveDB();

      res.json({
        ok: true
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Report haijatumwa."
      });
    }
  }
);

/* =========================
   ADMIN
========================= */

const adminSessions = new Map();

function requireAdmin(req, res, next) {
  const cookie = req.headers.cookie || "";

  const match = cookie.match(
    /(?:^|;\s*)adminSession=([^;]+)/
  );

  if (!match) {
    return res.status(401).json({
      error: "Admin login inahitajika."
    });
  }

  const token = decodeURIComponent(match[1]);

  if (!adminSessions.has(token)) {
    return res.status(401).json({
      error: "Admin session ime-expire."
    });
  }

  next();
}

app.post("/admin/login", (req, res) => {
  const email = normalizeEmail(
    req.body.email
  );

  const password = String(
    req.body.password || ""
  );

  const adminEmail = normalizeEmail(
    process.env.ADMIN_EMAIL
  );

  const adminPassword = String(
    process.env.ADMIN_PASSWORD || ""
  );

  if (!adminEmail || !adminPassword) {
    return res.status(503).json({
      error: "ADMIN_EMAIL na ADMIN_PASSWORD hazijawekwa."
    });
  }

  if (
    email !== adminEmail ||
    password !== adminPassword
  ) {
    return res.status(401).json({
      error: "Admin email au password sio sahihi."
    });
  }

  const token = crypto.randomBytes(32).toString("hex");

  adminSessions.set(token, {
    createdAt: Date.now()
  });

  res.setHeader(
    "Set-Cookie",
    `adminSession=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax`
  );

  res.json({
    ok: true
  });
});

app.get(
  "/admin/stats",
  requireAdmin,
  (req, res) => {
    res.json({
      users: db.users.length,
      likes: db.likes.length,
      messages: db.messages.length,
      reports: db.reports.filter(
        r => r.status === "open"
      ).length,
      notifications: db.notifications.length
    });
  }
);

app.get(
  "/admin/users",
  requireAdmin,
  (req, res) => {
    res.json(
      db.users.map(publicUser)
    );
  }
);

app.delete(
  "/admin/users/:id",
  requireAdmin,
  (req, res) => {
    const id = String(req.params.id);

    db.users = db.users.filter(
      u => String(u.id) !== id
    );

    db.likes = db.likes.filter(
      l =>
        String(l.from) !== id &&
        String(l.to) !== id
    );

    db.messages = db.messages.filter(
      m =>
        String(m.sender) !== id &&
        String(m.receiver) !== id
    );

    db.notifications =
      db.notifications.filter(
        n =>
          String(n.userId) !== id &&
          String(n.fromUserId) !== id
      );

    db.reports = db.reports.filter(
      r =>
        String(r.reporter) !== id &&
        String(r.reportedUser) !== id
    );

    saveDB();

    res.json({
      ok: true
    });
  }
);

/* =========================
   404
========================= */

app.use((req, res) => {
  if (
    req.path.startsWith("/api/") ||
    req.path.startsWith("/admin/")
  ) {
    return res.status(404).json({
      error: "Endpoint haikupatikana."
    });
  }

  res.status(404).send(
    "Page haikupatikana."
  );
});

/* =========================
   ERROR HANDLER
========================= */

app.use((err, req, res, next) => {
  console.error(err);

  if (err.type === "entity.too.large") {
    return res.status(413).json({
      error: "Data ni kubwa sana."
    });
  }

  res.status(500).json({
    error: "Server error."
  });
});

/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Tanzania Dating server running on port ${PORT}`
    );
  }
);
