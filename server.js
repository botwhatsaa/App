const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

// =====================================================
// DATABASE
// =====================================================

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
  console.error("PostgreSQL error:", err);
});

// =====================================================
// MIDDLEWARE
// =====================================================

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

app.use(express.static(__dirname));

// Zuia mafaili muhimu yasifikiwe kupitia browser
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

// =====================================================
// SESSION
// =====================================================

const sessions = new Map();

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    userId,
    createdAt: Date.now()
  });
  return token;
}

function getUserIdFromSession(req) {
  const token = req.headers.cookie
    ?.split(";")
    .map(x => x.trim())
    .find(x => x.startsWith("session="))
    ?.split("=")[1];

  if (!token) return null;

  const session = sessions.get(token);

  if (!session) return null;

  return session.userId;
}

function requireAuth(req, res, next) {
  const userId = getUserIdFromSession(req);

  if (!userId) {
    return res.status(401).json({
      ok: false,
      error: "Tafadhali ingia kwanza."
    });
  }

  req.userId = userId;
  next();
}

// =====================================================
// PASSWORD
// =====================================================

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `scrypt:${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  if (!storedPassword) return false;

  // Support old plain-text passwords
  if (!storedPassword.startsWith("scrypt:")) {
    return password === storedPassword;
  }

  const parts = storedPassword.split(":");

  if (parts.length !== 3) return false;

  const salt = parts[1];
  const storedHash = parts[2];

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(storedHash, "hex")
  );
}

// =====================================================
// DATABASE TABLES
// =====================================================

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      age INTEGER NOT NULL,
      gender VARCHAR(50) NOT NULL,
      city VARCHAR(100) NOT NULL,
      bio VARCHAR(500) DEFAULT '',
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
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL,
      message TEXT NOT NULL,
      read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reported_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log("PostgreSQL database iko tayari.");
}

// =====================================================
// USER FORMAT
// =====================================================

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    age: user.age,
    gender: user.gender,
    city: user.city,
    bio: user.bio || "",
    photo: user.photo || "",
    createdAt: user.created_at
  };
}

// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// =====================================================
// REGISTER
// =====================================================

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
        error: "Jina linahitajika."
      });
    }

    if (!email || !email.includes("@")) {
      return res.status(400).json({
        ok: false,
        error: "Weka email sahihi."
      });
    }

    if (!password || password.length < 6) {
      return res.status(400).json({
        ok: false,
        error: "Password iwe na angalau herufi 6."
      });
    }

    const userAge = Number(age);

    if (!userAge || userAge < 18 || userAge > 100) {
      return res.status(400).json({
        ok: false,
        error: "Umri lazima uwe kati ya miaka 18 na 100."
      });
    }

    if (!gender) {
      return res.status(400).json({
        ok: false,
        error: "Chagua jinsia."
      });
    }

    if (!city || !city.trim()) {
      return res.status(400).json({
        ok: false,
        error: "Weka mji."
      });
    }

    if (bio && bio.length > 500) {
      return res.status(400).json({
        ok: false,
        error: "Bio isiwe zaidi ya herufi 500."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const existing = await pool.query(
      `SELECT id FROM users WHERE LOWER(email) = $1 LIMIT 1`,
      [cleanEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({
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
        name.trim(),
        cleanEmail,
        hashedPassword,
        userAge,
        gender,
        city.trim(),
        bio ? bio.trim() : "",
        photo || ""
      ]
    );

    const user = result.rows[0];

    const sessionToken = createSession(user.id);

    res.setHeader(
      "Set-Cookie",
      `session=${sessionToken}; HttpOnly; Path=/; SameSite=Lax`
    );

    return res.json({
      ok: true,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Tatizo limetokea wakati wa kujisajili."
    });
  }
});

// =====================================================
// LOGIN
// =====================================================

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        error: "Weka email na password."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const result = await pool.query(
      `SELECT * FROM users WHERE LOWER(email) = $1 LIMIT 1`,
      [cleanEmail]
    );

    if (result.rows.length === 0) {
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

    // Upgrade old password ikiwa ilikuwa plain text
    if (!user.password.startsWith("scrypt:")) {
      const newPassword = hashPassword(password);

      await pool.query(
        `UPDATE users SET password = $1 WHERE id = $2`,
        [newPassword, user.id]
      );
    }

    const sessionToken = createSession(user.id);

    res.setHeader(
      "Set-Cookie",
      `session=${sessionToken}; HttpOnly; Path=/; SameSite=Lax`
    );

    return res.json({
      ok: true,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Tatizo limetokea wakati wa kuingia."
    });
  }
});

// =====================================================
// LOGOUT
// =====================================================

app.post("/api/logout", (req, res) => {
  const token = req.headers.cookie
    ?.split(";")
    .map(x => x.trim())
    .find(x => x.startsWith("session="))
    ?.split("=")[1];

  if (token) {
    sessions.delete(token);
  }

  res.setHeader(
    "Set-Cookie",
    "session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax"
  );

  res.json({
    ok: true
  });
});

// =====================================================
// CURRENT USER
// =====================================================

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, name, email, age, gender, city, bio, photo, created_at
      FROM users
      WHERE id = $1
      `,
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "Mtumiaji hajapatikana."
      });
    }

    res.json({
      ok: true,
      user: publicUser(result.rows[0])
    });

  } catch (error) {
    console.error("ME ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata taarifa zako."
    });
  }
});

// =====================================================
// DISCOVER
// HAPA NDIPO WATU WAPYA WANAONEKANA
// =====================================================

app.get("/api/discover", requireAuth, async (req, res) => {
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
      WHERE u.id <> $1
      AND u.id NOT IN (
        SELECT to_user
        FROM likes
        WHERE from_user = $1
      )
      ORDER BY u.created_at DESC
      LIMIT 100
      `,
      [req.userId]
    );

    res.json({
      ok: true,
      users: result.rows.map(publicUser)
    });

  } catch (error) {
    console.error("DISCOVER ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata watu wapya."
    });
  }
});

// =====================================================
// LIKE
// =====================================================

app.post("/api/like", requireAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const { userId } = req.body;

    const targetId = Number(userId);

    if (!targetId) {
      return res.status(400).json({
        ok: false,
        error: "User ID haipo."
      });
    }

    if (targetId === req.userId) {
      return res.status(400).json({
        ok: false,
        error: "Huwezi kujipenda mwenyewe."
      });
    }

    await client.query("BEGIN");

    const target = await client.query(
      `SELECT id, name FROM users WHERE id = $1`,
      [targetId]
    );

    if (target.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        ok: false,
        error: "Mtumiaji huyo hayupo."
      });
    }

    await client.query(
      `
      INSERT INTO likes (from_user, to_user)
      VALUES ($1,$2)
      ON CONFLICT (from_user,to_user) DO NOTHING
      `,
      [req.userId, targetId]
    );

    await client.query(
      `
      INSERT INTO notifications
      (user_id, title, message)
      VALUES ($1,$2,$3)
      `,
      [
        targetId,
        "❤️ Umepewa Like",
        "Mtu amekupenda kwenye Tanzania Dating."
      ]
    );

    const mutual = await client.query(
      `
      SELECT id
      FROM likes
      WHERE from_user = $1
      AND to_user = $2
      LIMIT 1
      `,
      [targetId, req.userId]
    );

    let match = false;

    if (mutual.rows.length > 0) {
      match = true;

      await client.query(
        `
        INSERT INTO notifications
        (user_id, title, message)
        VALUES
        ($1,'❤️ Match mpya!','Mme-match na mtu mpya.'),
        ($2,'❤️ Match mpya!','Mme-match na mtu mpya.')
        `,
        [req.userId, targetId]
      );
    }

    await client.query("COMMIT");

    res.json({
      ok: true,
      match
    });

  } catch (error) {
    await client.query("ROLLBACK");

    console.error("LIKE ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kutuma Like."
    });

  } finally {
    client.release();
  }
});

// =====================================================
// MATCHES
// =====================================================

app.get("/api/matches", requireAuth, async (req, res) => {
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
      INNER JOIN likes l1
        ON l1.to_user = u.id
       AND l1.from_user = $1
      INNER JOIN likes l2
        ON l2.from_user = u.id
       AND l2.to_user = $1
      ORDER BY u.created_at DESC
      `,
      [req.userId]
    );

    res.json({
      ok: true,
      users: result.rows.map(publicUser)
    });

  } catch (error) {
    console.error("MATCHES ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata matches."
    });
  }
});

// =====================================================
// UPDATE PROFILE
// =====================================================

app.post("/api/profile", requireAuth, async (req, res) => {
  try {
    const {
      name,
      age,
      gender,
      city,
      bio,
      photo
    } = req.body;

    const userAge = Number(age);

    if (!name || !name.trim()) {
      return res.status(400).json({
        ok: false,
        error: "Jina linahitajika."
      });
    }

    if (!userAge || userAge < 18 || userAge > 100) {
      return res.status(400).json({
        ok: false,
        error: "Umri lazima uwe kati ya 18 na 100."
      });
    }

    if (!gender || !city) {
      return res.status(400).json({
        ok: false,
        error: "Jaza taarifa zote."
      });
    }

    if (bio && bio.length > 500) {
      return res.status(400).json({
        ok: false,
        error: "Bio isiwe zaidi ya herufi 500."
      });
    }

    const result = await pool.query(
      `
      UPDATE users
      SET
        name = $1,
        age = $2,
        gender = $3,
        city = $4,
        bio = $5,
        photo = COALESCE($6, photo)
      WHERE id = $7
      RETURNING id, name, email, age, gender, city, bio, photo, created_at
      `,
      [
        name.trim(),
        userAge,
        gender,
        city.trim(),
        bio ? bio.trim() : "",
        photo || null,
        req.userId
      ]
    );

    res.json({
      ok: true,
      user: publicUser(result.rows[0])
    });

  } catch (error) {
    console.error("PROFILE ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kubadilisha profile."
    });
  }
});

// =====================================================
// NOTIFICATIONS
// =====================================================

app.get("/api/notifications", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        title,
        message,
        read,
        created_at
      FROM notifications
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [req.userId]
    );

    const unread = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM notifications
      WHERE user_id = $1
      AND read = FALSE
      `,
      [req.userId]
    );

    res.json({
      ok: true,
      notifications: result.rows,
      unread: unread.rows[0].count
    });

  } catch (error) {
    console.error("NOTIFICATIONS ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata notifications."
    });
  }
});

// =====================================================
// MARK NOTIFICATIONS AS READ
// =====================================================

app.post("/api/notifications/read-all", requireAuth, async (req, res) => {
  try {
    await pool.query(
      `
      UPDATE notifications
      SET read = TRUE
      WHERE user_id = $1
      `,
      [req.userId]
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

// =====================================================
// MESSAGES
// =====================================================

app.get("/api/messages/:id", requireAuth, async (req, res) => {
  try {
    const otherUserId = Number(req.params.id);

    if (!otherUserId) {
      return res.status(400).json({
        ok: false,
        error: "User ID si sahihi."
      });
    }

    const result = await pool.query(
      `
      SELECT
        id,
        sender_id,
        receiver_id,
        message,
        created_at
      FROM messages
      WHERE
        (sender_id = $1 AND receiver_id = $2)
        OR
        (sender_id = $2 AND receiver_id = $1)
      ORDER BY created_at ASC
      `,
      [req.userId, otherUserId]
    );

    res.json({
      ok: true,
      messages: result.rows
    });

  } catch (error) {
    console.error("GET MESSAGES ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata messages."
    });
  }
});

// =====================================================
// SEND MESSAGE
// =====================================================

app.post("/api/messages/:id", requireAuth, async (req, res) => {
  try {
    const receiverId = Number(req.params.id);
    const message = String(req.body.message || "").trim();

    if (!receiverId) {
      return res.status(400).json({
        ok: false,
        error: "Receiver ID si sahihi."
      });
    }

    if (!message) {
      return res.status(400).json({
        ok: false,
        error: "Andika message kwanza."
      });
    }

    if (message.length > 2000) {
      return res.status(400).json({
        ok: false,
        error: "Message ni ndefu sana."
      });
    }

    const user = await pool.query(
      `SELECT id FROM users WHERE id = $1`,
      [receiverId]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "Mtumiaji huyo hayupo."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO messages
      (sender_id, receiver_id, message)
      VALUES ($1,$2,$3)
      RETURNING id, sender_id, receiver_id, message, created_at
      `,
      [req.userId, receiverId, message]
    );

    res.json({
      ok: true,
      message: result.rows[0]
    });

  } catch (error) {
    console.error("SEND MESSAGE ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kutuma message."
    });
  }
});

// =====================================================
// REPORT USER
// =====================================================

app.post("/api/report", requireAuth, async (req, res) => {
  try {
    const {
      userId,
      reason
    } = req.body;

    const reportedId = Number(userId);

    if (!reportedId || reportedId === req.userId) {
      return res.status(400).json({
        ok: false,
        error: "User wa kuripoti si sahihi."
      });
    }

    await pool.query(
      `
      INSERT INTO reports
      (reporter_id, reported_id, reason)
      VALUES ($1,$2,$3)
      `,
      [
        req.userId,
        reportedId,
        reason || ""
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

// =====================================================
// DATABASE TEST
// =====================================================

app.get("/api/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS now");

    res.json({
      ok: true,
      database: "PostgreSQL connected",
      time: result.rows[0].now
    });

  } catch (error) {
    console.error("HEALTH ERROR:", error);

    res.status(500).json({
      ok: false,
      database: "PostgreSQL connection failed"
    });
  }
});

// =====================================================
// START SERVER
// =====================================================

async function startServer() {
  try {
    await setupDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Tanzania Dating running on port ${PORT}`);
    });

  } catch (error) {
    console.error("SERVER START ERROR:", error);
    process.exit(1);
  }
}

startServer();
