const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

// ======================================================
// DATABASE
// ======================================================

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL haijawekwa kwenye Render Environment.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

// ======================================================
// EXPRESS SETTINGS
// ======================================================

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Zuia watu kufungua mafaili muhimu
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
  res.sendFile(path.join(__dirname, "index.html"));
});

// ======================================================
// DATABASE SETUP
// ======================================================

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
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      from_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reported_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      type TEXT DEFAULT 'general',
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log("Database tables ziko tayari.");
}

// ======================================================
// PASSWORD
// ======================================================

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `scrypt:${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  if (!storedPassword) {
    return false;
  }

  // Password za zamani kama zilikuwa plain text
  if (!storedPassword.startsWith("scrypt:")) {
    return password === storedPassword;
  }

  const parts = storedPassword.split(":");

  if (parts.length !== 3) {
    return false;
  }

  const salt = parts[1];
  const originalHash = parts[2];

  try {
    const hash = crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(originalHash, "hex")
    );
  } catch (error) {
    return false;
  }
}

// ======================================================
// SESSION
// ======================================================

const sessions = new Map();

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    userId,
    createdAt: Date.now()
  });

  return token;
}

function getSessionUserId(req) {
  const cookieHeader = req.headers.cookie || "";

  const cookies = {};

  cookieHeader.split(";").forEach(part => {
    const index = part.indexOf("=");

    if (index === -1) return;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  });

  const session = cookies.session;

  if (!session) {
    return null;
  }

  const data = sessions.get(session);

  if (!data) {
    return null;
  }

  return data.userId;
}

function requireAuth(req, res, next) {
  const userId = getSessionUserId(req);

  if (!userId) {
    return res.status(401).json({
      ok: false,
      error: "Tafadhali ingia kwanza."
    });
  }

  req.userId = userId;
  next();
}

// ======================================================
// PUBLIC USER
// ======================================================

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

// ======================================================
// REGISTER
// ======================================================

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

    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanGender = String(gender || "").trim();
    const cleanCity = String(city || "").trim();
    const cleanBio = String(bio || "").trim();

    if (!cleanName) {
      return res.status(400).json({
        ok: false,
        error: "Tafadhali weka jina."
      });
    }

    if (!cleanEmail || !cleanEmail.includes("@")) {
      return res.status(400).json({
        ok: false,
        error: "Tafadhali weka email sahihi."
      });
    }

    if (!password || String(password).length < 6) {
      return res.status(400).json({
        ok: false,
        error: "Password iwe na angalau characters 6."
      });
    }

    const numericAge = Number(age);

    if (!Number.isInteger(numericAge) || numericAge < 18 || numericAge > 100) {
      return res.status(400).json({
        ok: false,
        error: "Umri lazima uwe kati ya miaka 18 na 100."
      });
    }

    if (!cleanGender) {
      return res.status(400).json({
        ok: false,
        error: "Tafadhali chagua gender."
      });
    }

    if (!cleanCity) {
      return res.status(400).json({
        ok: false,
        error: "Tafadhali weka mji."
      });
    }

    if (cleanBio.length > 500) {
      return res.status(400).json({
        ok: false,
        error: "Bio isiwe zaidi ya characters 500."
      });
    }

    let cleanPhoto = String(photo || "");

    if (cleanPhoto) {
      if (!/^data:image\/(jpeg|png|webp);base64,/i.test(cleanPhoto)) {
        return res.status(400).json({
          ok: false,
          error: "Picha lazima iwe JPG, PNG au WEBP."
        });
      }

      const approximateBytes =
        Math.floor((cleanPhoto.split(",")[1] || "").length * 0.75);

      if (approximateBytes > 5 * 1024 * 1024) {
        return res.status(400).json({
          ok: false,
          error: "Picha ni kubwa. Maximum ni 5MB."
        });
      }
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1 LIMIT 1",
      [cleanEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        ok: false,
        error: "Email hii tayari imesajiliwa."
      });
    }

    const hashedPassword = hashPassword(String(password));

    const result = await pool.query(
      `
      INSERT INTO users
      (name, email, password, age, gender, city, bio, photo)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING *
      `,
      [
        cleanName,
        cleanEmail,
        hashedPassword,
        numericAge,
        cleanGender,
        cleanCity,
        cleanBio,
        cleanPhoto
      ]
    );

    const user = result.rows[0];

    const token = createSession(user.id);

    res.setHeader(
      "Set-Cookie",
      `session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax`
    );

    return res.json({
      ok: true,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      ok: false,
      error: "Imeshindikana kujisajili. Jaribu tena."
    });
  }
});

// ======================================================
// LOGIN
// ======================================================

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        error: "Weka email na password."
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1 LIMIT 1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        ok: false,
        error: "Email au password sio sahihi."
      });
    }

    const user = result.rows[0];

    const valid = verifyPassword(password, user.password);

    if (!valid) {
      return res.status(401).json({
        ok: false,
        error: "Email au password sio sahihi."
      });
    }

    // Upgrade old plain-text password
    if (!user.password.startsWith("scrypt:")) {
      const newPassword = hashPassword(password);

      await pool.query(
        "UPDATE users SET password = $1 WHERE id = $2",
        [newPassword, user.id]
      );
    }

    const token = createSession(user.id);

    res.setHeader(
      "Set-Cookie",
      `session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax`
    );

    return res.json({
      ok: true,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      ok: false,
      error: "Kuna tatizo kwenye server. Jaribu tena."
    });
  }
});

// ======================================================
// LOGOUT
// ======================================================

app.post("/api/logout", (req, res) => {
  const cookieHeader = req.headers.cookie || "";

  const match = cookieHeader.match(/(?:^|;\s*)session=([^;]+)/);

  if (match) {
    const token = decodeURIComponent(match[1]);
    sessions.delete(token);
  }

  res.setHeader(
    "Set-Cookie",
    "session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"
  );

  res.json({
    ok: true
  });
});

// ======================================================
// CURRENT USER
// ======================================================

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE id = $1 LIMIT 1",
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "User hajapatikana."
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
      error: "Imeshindikana kupata profile."
    });
  }
});

// ======================================================
// DISCOVER
// ======================================================

app.get("/api/discover", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE id != $1
      AND id NOT IN (
        SELECT to_user
        FROM likes
        WHERE from_user = $1
      )
      ORDER BY created_at DESC
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
      error: "Imeshindikana kupata watu."
    });
  }
});

// ======================================================
// LIKE
// ======================================================

app.post("/api/like", requireAuth, async (req, res) => {
  try {
    const toUser = Number(
      req.body.userId ||
      req.body.toUser ||
      req.body.id
    );

    if (!Number.isInteger(toUser)) {
      return res.status(400).json({
        ok: false,
        error: "User ID sio sahihi."
      });
    }

    if (toUser === req.userId) {
      return res.status(400).json({
        ok: false,
        error: "Huwezi kujipenda mwenyewe."
      });
    }

    const target = await pool.query(
      "SELECT * FROM users WHERE id = $1 LIMIT 1",
      [toUser]
    );

    if (target.rows.length === 0) {
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
      [req.userId, toUser]
    );

    const currentUser = await pool.query(
      "SELECT name FROM users WHERE id = $1",
      [req.userId]
    );

    const senderName = currentUser.rows[0]?.name || "Mtu";

    // Notification ya like
    await pool.query(
      `
      INSERT INTO notifications
      (user_id,title,message,type)
      VALUES ($1,$2,$3,$4)
      `,
      [
        toUser,
        "❤️ Umepewa Like",
        `${senderName} amekupenda.`,
        "like"
      ]
    );

    // Check mutual like
    const mutual = await pool.query(
      `
      SELECT id
      FROM likes
      WHERE from_user = $1
      AND to_user = $2
      LIMIT 1
      `,
      [toUser, req.userId]
    );

    let match = false;

    if (mutual.rows.length > 0) {
      match = true;

      await pool.query(
        `
        INSERT INTO notifications
        (user_id,title,message,type)
        VALUES
        ($1,$2,$3,$4),
        ($5,$6,$7,$8)
        `,
        [
          req.userId,
          "❤️ Match mpya!",
          `Ume-match na ${target.rows[0].name}.`,
          "match",

          toUser,
          "❤️ Match mpya!",
          `Ume-match na ${senderName}.`,
          "match"
        ]
      );
    }

    res.json({
      ok: true,
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

// ======================================================
// MATCHES
// ======================================================

app.get("/api/matches", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT DISTINCT u.*
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
      matches: result.rows.map(publicUser),
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

// ======================================================
// UPDATE PROFILE
// ======================================================

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

    const cleanName = String(name || "").trim();
    const numericAge = Number(age);
    const cleanGender = String(gender || "").trim();
    const cleanCity = String(city || "").trim();
    const cleanBio = String(bio || "").trim();

    if (!cleanName) {
      return res.status(400).json({
        ok: false,
        error: "Jina linahitajika."
      });
    }

    if (!Number.isInteger(numericAge) || numericAge < 18 || numericAge > 100) {
      return res.status(400).json({
        ok: false,
        error: "Umri lazima uwe kati ya 18 na 100."
      });
    }

    if (!cleanGender || !cleanCity) {
      return res.status(400).json({
        ok: false,
        error: "Gender na city vinahitajika."
      });
    }

    if (cleanBio.length > 500) {
      return res.status(400).json({
        ok: false,
        error: "Bio isiwe zaidi ya characters 500."
      });
    }

    let cleanPhoto = null;

    if (photo !== undefined && photo !== null && photo !== "") {
      cleanPhoto = String(photo);

      if (!/^data:image\/(jpeg|png|webp);base64,/i.test(cleanPhoto)) {
        return res.status(400).json({
          ok: false,
          error: "Picha lazima iwe JPG, PNG au WEBP."
        });
      }

      const approximateBytes =
        Math.floor((cleanPhoto.split(",")[1] || "").length * 0.75);

      if (approximateBytes > 5 * 1024 * 1024) {
        return res.status(400).json({
          ok: false,
          error: "Picha ni kubwa. Maximum ni 5MB."
        });
      }
    }

    let query;
    let params;

    if (cleanPhoto !== null) {
      query = `
        UPDATE users
        SET
          name = $1,
          age = $2,
          gender = $3,
          city = $4,
          bio = $5,
          photo = $6
        WHERE id = $7
        RETURNING *
      `;

      params = [
        cleanName,
        numericAge,
        cleanGender,
        cleanCity,
        cleanBio,
        cleanPhoto,
        req.userId
      ];
    } else {
      query = `
        UPDATE users
        SET
          name = $1,
          age = $2,
          gender = $3,
          city = $4,
          bio = $5
        WHERE id = $6
        RETURNING *
      `;

      params = [
        cleanName,
        numericAge,
        cleanGender,
        cleanCity,
        cleanBio,
        req.userId
      ];
    }

    const result = await pool.query(query, params);

    res.json({
      ok: true,
      user: publicUser(result.rows[0])
    });

  } catch (error) {
    console.error("PROFILE ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kusasisha profile."
    });
  }
});

// ======================================================
// NOTIFICATIONS
// ======================================================

app.get("/api/notifications", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        title,
        message,
        type,
        is_read,
        created_at
      FROM notifications
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [req.userId]
    );

    const unreadResult = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM notifications
      WHERE user_id = $1
      AND is_read = FALSE
      `,
      [req.userId]
    );

    res.json({
      ok: true,
      notifications: result.rows,
      unreadCount: unreadResult.rows[0].count
    });

  } catch (error) {
    console.error("NOTIFICATIONS ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Imeshindikana kupata notifications."
    });
  }
});

// ======================================================
// READ ALL NOTIFICATIONS
// ======================================================

app.post("/api/notifications/read-all", requireAuth, async (req, res) => {
  try {
    await pool.query(
      `
      UPDATE notifications
      SET is_read = TRUE
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

// ======================================================
// GET MESSAGES
// ======================================================

app.get("/api/messages/:id", requireAuth, async (req, res) => {
  try {
    const otherUser = Number(req.params.id);

    if (!Number.isInteger(otherUser)) {
      return res.status(400).json({
        ok: false,
        error: "User ID sio sahihi."
      });
    }

    const result = await pool.query(
      `
      SELECT
        id,
        from_user,
        to_user,
        message,
        created_at
      FROM messages
      WHERE
        (from_user = $1 AND to_user = $2)
        OR
        (from_user = $2 AND to_user = $1)
      ORDER BY created_at ASC
      LIMIT 500
      `,
      [req.userId, otherUser]
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

// ======================================================
// SEND MESSAGE
// ======================================================

app.post("/api/messages/:id", requireAuth, async (req, res) => {
  try {
    const otherUser = Number(req.params.id);

    const message = String(
      req.body.message ||
      req.body.text ||
      ""
    ).trim();

    if (!Number.isInteger(otherUser)) {
      return res.status(400).json({
        ok: false,
        error: "User ID sio sahihi."
      });
    }

    if (!message) {
      return res.status(400).json({
        ok: false,
        error: "Message haiwezi kuwa tupu."
      });
    }

    if (message.length > 2000) {
      return res.status(400).json({
        ok: false,
        error: "Message ni ndefu sana."
      });
    }

    const target = await pool.query(
      "SELECT id,name FROM users WHERE id = $1 LIMIT 1",
      [otherUser]
    );

    if (target.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "User hajapatikana."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO messages
      (from_user,to_user,message)
      VALUES ($1,$2,$3)
      RETURNING *
      `,
      [req.userId, otherUser, message]
    );

    // Notification
    const sender = await pool.query(
      "SELECT name FROM users WHERE id = $1 LIMIT 1",
      [req.userId]
    );

    const senderName = sender.rows[0]?.name || "Mtu";

    await pool.query(
      `
      INSERT INTO notifications
      (user_id,title,message,type)
      VALUES ($1,$2,$3,$4)
      `,
      [
        otherUser,
        "💬 Ujumbe mpya",
        `${senderName} amekutumia ujumbe.`,
        "message"
      ]
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

// ======================================================
// REPORT USER
// ======================================================

app.post("/api/report", requireAuth, async (req, res) => {
  try {
    const reportedUser = Number(
      req.body.userId ||
      req.body.reportedUser ||
      req.body.id
    );

    const reason = String(
      req.body.reason || ""
    ).trim();

    if (!Number.isInteger(reportedUser)) {
      return res.status(400).json({
        ok: false,
        error: "User ID sio sahihi."
      });
    }

    if (reportedUser === req.userId) {
      return res.status(400).json({
        ok: false,
        error: "Huwezi kujiripoti mwenyewe."
      });
    }

    const user = await pool.query(
      "SELECT id FROM users WHERE id = $1 LIMIT 1",
      [reportedUser]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "User hajapatikana."
      });
    }

    await pool.query(
      `
      INSERT INTO reports
      (from_user,reported_user,reason)
      VALUES ($1,$2,$3)
      `,
      [req.userId, reportedUser, reason]
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

// ======================================================
// HEALTH CHECK
// ======================================================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: "connected",
      service: "Tanzania Dating"
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      database: "error"
    });
  }
});

// ======================================================
// ERROR HANDLER
// ======================================================

app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err);

  res.status(500).json({
    ok: false,
    error: "Server error."
  });
});

// ======================================================
// START SERVER
// ======================================================

async function startServer() {
  try {
    await setupDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Tanzania Dating running on port ${PORT}`);
    });

  } catch (error) {
    console.error("DATABASE STARTUP ERROR:");
    console.error(error);

    process.exit(1);
  }
}

startServer();
