const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;

/* =========================================================
   DATABASE
========================================================= */

if (!process.env.DATABASE_URL) {
  console.error("ERROR: DATABASE_URL haijawekwa kwenye Environment Variables.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

pool.on("error", (err) => {
  console.error("PostgreSQL pool error:", err);
});

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,POST,PUT,PATCH,DELETE,OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

/* =========================================================
   SESSION
========================================================= */

const sessions = new Map();

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    userId: Number(userId),
    createdAt: Date.now()
  });

  return token;
}

function getToken(req) {
  const auth = req.headers.authorization || "";

  if (auth.startsWith("Bearer ")) {
    return auth.substring(7).trim();
  }

  if (req.headers["x-session-token"]) {
    return req.headers["x-session-token"];
  }

  return null;
}

async function auth(req, res, next) {
  try {
    const token = getToken(req);

    if (!token || !sessions.has(token)) {
      return res.status(401).json({
        ok: false,
        error: "Hujaingia kwenye akaunti."
      });
    }

    const session = sessions.get(token);

    const result = await pool.query(
      `
      SELECT id, name, email, age, gender, city, bio, photo, created_at
      FROM users
      WHERE id = $1
      `,
      [session.userId]
    );

    if (!result.rows.length) {
      sessions.delete(token);

      return res.status(401).json({
        ok: false,
        error: "Akaunti haijapatikana."
      });
    }

    req.user = result.rows[0];
    req.token = token;

    next();
  } catch (error) {
    console.error("AUTH ERROR:", error);

    return res.status(500).json({
      ok: false,
      error: "Tatizo la server."
    });
  }
}

/* =========================================================
   PASSWORD HASH
========================================================= */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .pbkdf2Sync(password, salt, 100000, 64, "sha512")
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  try {
    const parts = String(storedPassword).split(":");

    if (parts.length !== 2) {
      return false;
    }

    const salt = parts[0];
    const storedHash = parts[1];

    const hash = crypto
      .pbkdf2Sync(password, salt, 100000, 64, "sha512")
      .toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(storedHash, "hex")
    );
  } catch {
    return false;
  }
}

/* =========================================================
   DATABASE TABLES
========================================================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      age INTEGER,
      gender TEXT,
      city TEXT,
      bio TEXT DEFAULT '',
      photo TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS likes (
      id SERIAL PRIMARY KEY,
      from_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      to_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(from_user, to_user)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      from_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      to_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT DEFAULT 'general',
      title TEXT DEFAULT '',
      message TEXT DEFAULT '',
      related_user INTEGER,
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      reporter INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reported INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("Database tables ready.");
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* =========================================================
   HEALTH
========================================================= */

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      status: "online",
      database: "connected"
    });
  } catch (error) {
    console.error("HEALTH ERROR:", error);

    res.status(500).json({
      ok: false,
      status: "online",
      database: "error"
    });
  }
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {
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
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        ok: false,
        error: "Jaza jina, email na password."
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        ok: false,
        error: "Password iwe na angalau characters 4."
      });
    }

    const cleanEmail = String(email).trim().toLowerCase();

    const exists = await pool.query(
      `SELECT id FROM users WHERE email = $1`,
      [cleanEmail]
    );

    if (exists.rows.length) {
      return res.status(409).json({
        ok: false,
        error: "Email hii tayari imesajiliwa."
      });
    }

    const hashedPassword = hashPassword(password);

    const result = await pool.query(
      `
      INSERT INTO users
      (name, email, password, age, gender, city, bio, photo)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING id, name, email, age, gender, city, bio, photo, created_at
      `,
      [
        String(name).trim(),
        cleanEmail,
        hashedPassword,
        age ? Number(age) : null,
        gender || "",
        city || "",
        bio || "",
        photo || ""
      ]
    );

    const user = result.rows[0];

    const token = createSession(user.id);

    res.json({
      ok: true,
      token,
      user
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kusajili akaunti."
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        error: "Weka email na password."
      });
    }

    const cleanEmail = String(email).trim().toLowerCase();

    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE email = $1
      `,
      [cleanEmail]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        ok: false,
        error: "Email au password sio sahihi."
      });
    }

    const user = result.rows[0];

    if (!verifyPassword(password, user.password)) {
      return res.status(401).json({
        ok: false,
        error: "Email au password sio sahihi."
      });
    }

    delete user.password;

    const token = createSession(user.id);

    res.json({
      ok: true,
      token,
      user
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kuingia."
    });
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", auth, (req, res) => {
  if (req.token) {
    sessions.delete(req.token);
  }

  res.json({
    ok: true
  });
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/api/me", auth, (req, res) => {
  res.json({
    ok: true,
    user: req.user
  });
});

/* =========================================================
   USERS / DISCOVER
========================================================= */

app.get("/api/users", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        name,
        age,
        gender,
        city,
        bio,
        photo,
        created_at
      FROM users
      WHERE id <> $1
      ORDER BY created_at DESC
      `,
      [req.user.id]
    );

    res.json({
      ok: true,
      users: result.rows
    });
  } catch (error) {
    console.error("USERS ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata users."
    });
  }
});

/* =========================================================
   PROFILE
========================================================= */

app.get("/api/profile", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, name, email, age, gender, city, bio, photo, created_at
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    res.json({
      ok: true,
      user: result.rows[0]
    });
  } catch (error) {
    console.error("PROFILE ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata profile."
    });
  }
});

app.put("/api/profile", auth, async (req, res) => {
  try {
    const {
      name,
      age,
      gender,
      city,
      bio,
      photo
    } = req.body;

    const result = await pool.query(
      `
      UPDATE users
      SET
        name = COALESCE($1, name),
        age = COALESCE($2, age),
        gender = COALESCE($3, gender),
        city = COALESCE($4, city),
        bio = COALESCE($5, bio),
        photo = COALESCE($6, photo)
      WHERE id = $7
      RETURNING id, name, email, age, gender, city, bio, photo, created_at
      `,
      [
        name,
        age !== undefined ? Number(age) : null,
        gender,
        city,
        bio,
        photo,
        req.user.id
      ]
    );

    res.json({
      ok: true,
      user: result.rows[0]
    });
  } catch (error) {
    console.error("UPDATE PROFILE ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kusasisha profile."
    });
  }
});

/* =========================================================
   LIKE
========================================================= */

app.post("/api/like/:id", auth, async (req, res) => {
  try {
    const toUser = Number(req.params.id);

    if (!toUser || toUser === req.user.id) {
      return res.status(400).json({
        ok: false,
        error: "User si sahihi."
      });
    }

    const userExists = await pool.query(
      `SELECT id, name FROM users WHERE id = $1`,
      [toUser]
    );

    if (!userExists.rows.length) {
      return res.status(404).json({
        ok: false,
        error: "User hajapatikana."
      });
    }

    await pool.query(
      `
      INSERT INTO likes (from_user, to_user)
      VALUES ($1,$2)
      ON CONFLICT (from_user,to_user) DO NOTHING
      `,
      [req.user.id, toUser]
    );

    const mutual = await pool.query(
      `
      SELECT id
      FROM likes
      WHERE from_user = $1
      AND to_user = $2
      `,
      [toUser, req.user.id]
    );

    let match = false;

    if (mutual.rows.length) {
      match = true;

      // Notification to other user
      try {
        await pool.query(
          `
          INSERT INTO notifications
          (user_id, type, title, message, related_user)
          VALUES ($1,$2,$3,$4,$5)
          `,
          [
            toUser,
            "match",
            "New Match ❤️",
            `${req.user.name} amematch na wewe.`,
            req.user.id
          ]
        );
      } catch (notificationError) {
        console.error(
          "MATCH NOTIFICATION ERROR:",
          notificationError.message
        );
      }
    }

    res.json({
      ok: true,
      liked: true,
      match
    });
  } catch (error) {
    console.error("LIKE ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kuweka like."
    });
  }
});

/* =========================================================
   MATCHES
========================================================= */

app.get("/api/matches", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT DISTINCT
        u.id,
        u.name,
        u.age,
        u.gender,
        u.city,
        u.bio,
        u.photo
      FROM users u
      JOIN likes l1
        ON l1.to_user = u.id
      JOIN likes l2
        ON l2.from_user = u.id
       AND l2.to_user = $1
      WHERE l1.from_user = $1
      ORDER BY u.name
      `,
      [req.user.id]
    );

    res.json({
      ok: true,
      matches: result.rows
    });
  } catch (error) {
    console.error("MATCHES ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata matches."
    });
  }
});

/* =========================================================
   CHATS
========================================================= */

app.get("/api/chats", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        u.id,
        u.name,
        u.age,
        u.gender,
        u.city,
        u.bio,
        u.photo,

        (
          SELECT m.message
          FROM messages m
          WHERE
            (m.from_user = $1 AND m.to_user = u.id)
            OR
            (m.from_user = u.id AND m.to_user = $1)
          ORDER BY m.created_at DESC
          LIMIT 1
        ) AS last_message,

        (
          SELECT m.created_at
          FROM messages m
          WHERE
            (m.from_user = $1 AND m.to_user = u.id)
            OR
            (m.from_user = u.id AND m.to_user = $1)
          ORDER BY m.created_at DESC
          LIMIT 1
        ) AS last_message_time

      FROM users u
      WHERE u.id IN (
        SELECT DISTINCT
          CASE
            WHEN from_user = $1 THEN to_user
            ELSE from_user
          END
        FROM messages
        WHERE from_user = $1 OR to_user = $1
      )
      ORDER BY last_message_time DESC NULLS LAST
      `,
      [req.user.id]
    );

    res.json({
      ok: true,
      chats: result.rows
    });
  } catch (error) {
    console.error("CHATS ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata chats."
    });
  }
});

/* =========================================================
   GET MESSAGES
========================================================= */

app.get("/api/messages/:id", auth, async (req, res) => {
  try {
    const otherUser = Number(req.params.id);

    if (!otherUser) {
      return res.status(400).json({
        ok: false,
        error: "User wa chat hajapatikana."
      });
    }

    const result = await pool.query(
      `
      SELECT
        m.id,
        m.from_user,
        m.to_user,
        m.message,
        m.created_at,

        fu.name AS from_name,
        fu.photo AS from_photo,

        tu.name AS to_name,
        tu.photo AS to_photo

      FROM messages m

      LEFT JOIN users fu
        ON fu.id = m.from_user

      LEFT JOIN users tu
        ON tu.id = m.to_user

      WHERE
        (m.from_user = $1 AND m.to_user = $2)
        OR
        (m.from_user = $2 AND m.to_user = $1)

      ORDER BY m.created_at ASC
      `,
      [req.user.id, otherUser]
    );

    res.json({
      ok: true,
      messages: result.rows
    });
  } catch (error) {
    console.error("GET MESSAGES ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata ujumbe."
    });
  }
});

/* =========================================================
   SEND MESSAGE
========================================================= */

app.post("/api/messages/:id", auth, async (req, res) => {
  try {
    const toUser = Number(req.params.id);
    const message = String(req.body.message || "").trim();

    if (!toUser) {
      return res.status(400).json({
        ok: false,
        error: "Mtumiaji hajapatikana."
      });
    }

    if (toUser === Number(req.user.id)) {
      return res.status(400).json({
        ok: false,
        error: "Huwezi kujitumia ujumbe."
      });
    }

    if (!message) {
      return res.status(400).json({
        ok: false,
        error: "Andika ujumbe kwanza."
      });
    }

    if (message.length > 5000) {
      return res.status(400).json({
        ok: false,
        error: "Ujumbe ni mrefu sana."
      });
    }

    /* -----------------------------------------------
       Hakikisha recipient yupo
    ------------------------------------------------ */

    const recipient = await pool.query(
      `
      SELECT id, name
      FROM users
      WHERE id = $1
      `,
      [toUser]
    );

    if (!recipient.rows.length) {
      return res.status(404).json({
        ok: false,
        error: "Mtumiaji huyo hajapatikana."
      });
    }

    /* -----------------------------------------------
       SAVE MESSAGE KWANZA
       
       HII NDIYO FIX KUBWA.
       Notification ikifeli haitafuta message.
    ------------------------------------------------ */

    const result = await pool.query(
      `
      INSERT INTO messages
      (from_user, to_user, message)
      VALUES ($1,$2,$3)
      RETURNING
        id,
        from_user,
        to_user,
        message,
        created_at
      `,
      [
        Number(req.user.id),
        toUser,
        message
      ]
    );

    const savedMessage = result.rows[0];

    /* -----------------------------------------------
       NOTIFICATION
       
       Notification ikifeli:
       - message bado ipo database
       - response bado inakuwa OK
    ------------------------------------------------ */

    try {
      await pool.query(
        `
        INSERT INTO notifications
        (user_id, type, title, message, related_user)
        VALUES ($1,$2,$3,$4,$5)
        `,
        [
          toUser,
          "message",
          "Ujumbe mpya 💬",
          `${req.user.name} amekutumia ujumbe mpya.`,
          Number(req.user.id)
        ]
      );
    } catch (notificationError) {
      console.error(
        "NOTIFICATION ERROR:",
        notificationError.message
      );
    }

    /* -----------------------------------------------
       SUCCESS
    ------------------------------------------------ */

    return res.status(200).json({
      ok: true,
      success: true,
      message: savedMessage
    });

  } catch (error) {
    console.error("SEND MESSAGE ERROR:", error);

    return res.status(500).json({
      ok: false,
      success: false,
      error: "Imeshindikana kutuma ujumbe."
    });
  }
});

/* =========================================================
   NOTIFICATIONS
========================================================= */

app.get("/api/notifications", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        type,
        title,
        message,
        related_user,
        is_read,
        created_at
      FROM notifications
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [req.user.id]
    );

    res.json({
      ok: true,
      notifications: result.rows
    });
  } catch (error) {
    console.error("NOTIFICATIONS ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata notifications."
    });
  }
});

/* =========================================================
   MARK NOTIFICATIONS READ
========================================================= */

app.post("/api/notifications/read", auth, async (req, res) => {
  try {
    await pool.query(
      `
      UPDATE notifications
      SET is_read = TRUE
      WHERE user_id = $1
      `,
      [req.user.id]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error("READ NOTIFICATIONS ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kusoma notifications."
    });
  }
});

/* =========================================================
   REPORT USER
========================================================= */

app.post("/api/report/:id", auth, async (req, res) => {
  try {
    const reported = Number(req.params.id);
    const reason = String(req.body.reason || "").trim();

    if (!reported) {
      return res.status(400).json({
        ok: false,
        error: "User si sahihi."
      });
    }

    if (reported === Number(req.user.id)) {
      return res.status(400).json({
        ok: false,
        error: "Huwezi kujireport."
      });
    }

    if (!reason) {
      return res.status(400).json({
        ok: false,
        error: "Andika sababu ya report."
      });
    }

    await pool.query(
      `
      INSERT INTO reports
      (reporter, reported, reason)
      VALUES ($1,$2,$3)
      `,
      [
        Number(req.user.id),
        reported,
        reason
      ]
    );

    res.json({
      ok: true,
      message: "Report imetumwa."
    });
  } catch (error) {
    console.error("REPORT ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kutuma report."
    });
  }
});

/* =========================================================
   DELETE SESSION
========================================================= */

app.post("/api/logout", auth, (req, res) => {
  sessions.delete(req.token);

  res.json({
    ok: true,
    message: "Umetoka kwenye akaunti."
  });
});

/* =========================================================
   404 API
========================================================= */

app.use("/api", (req, res) => {
  res.status(404).json({
    ok: false,
    error: "API endpoint haijapatikana."
  });
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
  console.error("GLOBAL ERROR:", err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    ok: false,
    error: "Server error."
  });
});

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await initDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("----------------------------------------");
      console.log("Tanzania Dating server is running");
      console.log(`PORT: ${PORT}`);
      console.log("----------------------------------------");
    });
  } catch (error) {
    console.error("SERVER START ERROR:", error);
    process.exit(1);
  }
}

startServer();
