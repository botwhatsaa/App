const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL haijawekwa kwenye Environment Variables.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

/* =========================
   STATIC FILES
========================= */

app.use((req, res, next) => {
  const blocked = [
    "/server.js",
    "/package.json",
    "/database.json",
    "/.env"
  ];

  if (blocked.includes(req.path)) {
    return res.status(403).send("Forbidden");
  }

  next();
});

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* =========================
   SESSION
========================= */

const sessions = new Map();

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, userId);
  return token;
}

function getSessionUserId(req) {
  const cookie = req.headers.cookie || "";

  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);

  if (!match) return null;

  return sessions.get(match[1]) || null;
}

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `session=${token}; HttpOnly; Path=/; SameSite=Lax`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"
  );
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

function verifyPassword(password, stored) {
  if (!stored) return false;

  if (!stored.startsWith("scrypt:")) {
    return password === stored;
  }

  const parts = stored.split(":");

  if (parts.length !== 3) return false;

  const salt = parts[1];
  const originalHash = parts[2];

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(originalHash, "hex")
  );
}

/* =========================
   HELPERS
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
    createdAt: user.created_at
  };
}

async function auth(req, res, next) {
  const userId = getSessionUserId(req);

  if (!userId) {
    return res.status(401).json({
      ok: false,
      message: "Tafadhali ingia kwanza."
    });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [userId]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        ok: false,
        message: "Session imekwisha."
      });
    }

    req.user = result.rows[0];
    next();

  } catch (error) {
    console.error(error);

    res.status(500).json({
      ok: false,
      message: "Server error."
    });
  }
}

/* =========================
   DATABASE
========================= */

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      age INTEGER NOT NULL,
      gender TEXT NOT NULL,
      city TEXT NOT NULL,
      bio TEXT DEFAULT '',
      photo TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS likes (
      id SERIAL PRIMARY KEY,
      from_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      to_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(from_user, to_user)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      from_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      to_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      related_user INTEGER,
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      reporter INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reported INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log("PostgreSQL database tayari.");
}

/* =========================
   REGISTER
========================= */

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

    if (!name || !name.trim()) {
      return res.status(400).json({
        ok: false,
        message: "Weka jina."
      });
    }

    if (!email || !email.includes("@")) {
      return res.status(400).json({
        ok: false,
        message: "Weka email sahihi."
      });
    }

    if (!password || password.length < 6) {
      return res.status(400).json({
        ok: false,
        message: "Password iwe na angalau herufi 6."
      });
    }

    const userAge = Number(age);

    if (!userAge || userAge < 18 || userAge > 100) {
      return res.status(400).json({
        ok: false,
        message: "Umri lazima uwe kati ya 18 na 100."
      });
    }

    if (!gender) {
      return res.status(400).json({
        ok: false,
        message: "Chagua jinsia."
      });
    }

    if (!city || !city.trim()) {
      return res.status(400).json({
        ok: false,
        message: "Weka mji."
      });
    }

    if (bio && bio.length > 500) {
      return res.status(400).json({
        ok: false,
        message: "Bio isiwe zaidi ya herufi 500."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const exists = await pool.query(
      "SELECT id FROM users WHERE LOWER(email) = LOWER($1)",
      [normalizedEmail]
    );

    if (exists.rows.length) {
      return res.status(400).json({
        ok: false,
        message: "Email hii tayari imesajiliwa."
      });
    }

    const passwordHash = hashPassword(password);

    const result = await pool.query(
      `
      INSERT INTO users
      (name,email,password,age,gender,city,bio,photo)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING *
      `,
      [
        name.trim(),
        normalizedEmail,
        passwordHash,
        userAge,
        gender,
        city.trim(),
        bio || "",
        photo || ""
      ]
    );

    const user = result.rows[0];

    const token = createSession(user.id);

    setSessionCookie(res, token);

    res.json({
      ok: true,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      ok: false,
      message: "Imeshindikana kusajili account."
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        message: "Weka email na password."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(email) = LOWER($1)",
      [normalizedEmail]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        ok: false,
        message: "Email au password sio sahihi."
      });
    }

    const user = result.rows[0];

    if (!verifyPassword(password, user.password)) {
      return res.status(401).json({
        ok: false,
        message: "Email au password sio sahihi."
      });
    }

    if (!user.password.startsWith("scrypt:")) {
      const newHash = hashPassword(password);

      await pool.query(
        "UPDATE users SET password = $1 WHERE id = $2",
        [newHash, user.id]
      );
    }

    const token = createSession(user.id);

    setSessionCookie(res, token);

    res.json({
      ok: true,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      ok: false,
      message: "Server error."
    });
  }
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {
  const cookie = req.headers.cookie || "";

  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);

  if (match) {
    sessions.delete(match[1]);
  }

  clearSessionCookie(res);

  res.json({
    ok: true
  });
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", auth, async (req, res) => {
  res.json({
    ok: true,
    user: publicUser(req.user)
  });
});

/* =========================
   DISCOVER
========================= */

app.get("/api/discover", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        u.id,
        u.name,
        u.email,
        u.age,
        u.gender,
        u.city,
        u.bio,
        u.photo,
        u.created_at
      FROM users u
      LEFT JOIN likes l
        ON l.from_user = $1
       AND l.to_user = u.id
      WHERE u.id <> $1
        AND l.id IS NULL
      ORDER BY u.created_at DESC
      LIMIT 100
      `,
      [req.user.id]
    );

    res.json({
      ok: true,
      users: result.rows.map(publicUser)
    });

  } catch (error) {
    console.error("DISCOVER ERROR:", error);

    res.status(500).json({
      ok: false,
      message: "Imeshindikana kupata watu."
    });
  }
});

/* =========================
   LIKE
========================= */

app.post("/api/like", auth, async (req, res) => {
  try {
    const toUser = Number(req.body.userId);

    if (!toUser || toUser === req.user.id) {
      return res.status(400).json({
        ok: false,
        message: "Huwezi kujilike mwenyewe."
      });
    }

    const target = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [toUser]
    );

    if (!target.rows.length) {
      return res.status(404).json({
        ok: false,
        message: "User hajapatikana."
      });
    }

    await pool.query(
      `
      INSERT INTO likes(from_user,to_user)
      VALUES($1,$2)
      ON CONFLICT(from_user,to_user) DO NOTHING
      `,
      [req.user.id, toUser]
    );

    await pool.query(
      `
      INSERT INTO notifications
      (user_id,type,title,message,related_user)
      VALUES($1,'like','❤️ Umepewa Like',$2,$3)
      `,
      [
        toUser,
        `${req.user.name} amekupenda ❤️`,
        req.user.id
      ]
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

    if (mutual.rows.length) {
      await pool.query(
        `
        INSERT INTO notifications
        (user_id,type,title,message,related_user)
        VALUES
        ($1,'match','❤️ Match mpya!',$2,$3),
        ($3,'match','❤️ Match mpya!',$4,$1)
        `,
        [
          req.user.id,
          `Ume-match na ${target.rows[0].name}`,
          toUser,
          `Ume-match na ${req.user.name}`
        ]
      );
    }

    res.json({
      ok: true,
      match: mutual.rows.length > 0
    });

  } catch (error) {
    console.error("LIKE ERROR:", error);

    res.status(500).json({
      ok: false,
      message: "Like imeshindikana."
    });
  }
});

/* =========================
   MATCHES
========================= */

app.get("/api/matches", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT DISTINCT
        u.id,
        u.name,
        u.email,
        u.age,
        u.gender,
        u.city,
        u.bio,
        u.photo,
        u.created_at
      FROM users u
      JOIN likes a
        ON a.to_user = u.id
       AND a.from_user = $1
      JOIN likes b
        ON b.from_user = u.id
       AND b.to_user = $1
      ORDER BY u.created_at DESC
      `,
      [req.user.id]
    );

    res.json({
      ok: true,
      users: result.rows.map(publicUser)
    });

  } catch (error) {
    console.error("MATCH ERROR:", error);

    res.status(500).json({
      ok: false,
      message: "Imeshindikana kupata matches."
    });
  }
});

/* =========================
   CHATS / INBOX
   WHATSAPP STYLE
========================= */

app.get("/api/chats", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      WITH conversation_users AS (
        SELECT DISTINCT
          CASE
            WHEN from_user = $1 THEN to_user
            ELSE from_user
          END AS user_id
        FROM messages
        WHERE from_user = $1
           OR to_user = $1
      ),
      last_messages AS (
        SELECT DISTINCT ON (
          CASE
            WHEN from_user = $1 THEN to_user
            ELSE from_user
          END
        )
          CASE
            WHEN from_user = $1 THEN to_user
            ELSE from_user
          END AS user_id,
          message,
          created_at
        FROM messages
        WHERE from_user = $1
           OR to_user = $1
        ORDER BY
          CASE
            WHEN from_user = $1 THEN to_user
            ELSE from_user
          END,
          created_at DESC
      )
      SELECT
        u.id,
        u.name,
        u.photo,
        u.city,
        lm.message AS last_message,
        lm.created_at AS last_message_at
      FROM conversation_users cu
      JOIN users u ON u.id = cu.user_id
      JOIN last_messages lm ON lm.user_id = u.id
      ORDER BY lm.created_at DESC
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
      message: "Imeshindikana kupata chats."
    });
  }
});

/* =========================
   GET MESSAGES
========================= */

app.get("/api/messages/:id", auth, async (req, res) => {
  try {
    const otherUser = Number(req.params.id);

    if (!otherUser) {
      return res.status(400).json({
        ok: false,
        message: "User sio sahihi."
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
        u.name AS sender_name
      FROM messages m
      JOIN users u ON u.id = m.from_user
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
      message: "Imeshindikana kupata ujumbe."
    });
  }
});

/* =========================
   SEND MESSAGE
   NO LIKE / NO MATCH REQUIRED
========================= */

app.post("/api/messages/:id", auth, async (req, res) => {
  try {
    const toUser = Number(req.params.id);
    const message = String(req.body.message || "").trim();

    if (!toUser) {
      return res.status(400).json({
        ok: false,
        message: "User sio sah
