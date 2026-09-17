const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

// ======================================================
// POSTGRESQL
// ======================================================

if (!process.env.DATABASE_URL) {
  console.error("ERROR: DATABASE_URL haijawekwa kwenye Environment.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

// ======================================================
// EXPRESS
// ======================================================

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Zuia watu kuona files za siri
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
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      age INTEGER NOT NULL,
      gender TEXT NOT NULL,
      city TEXT NOT NULL,
      bio TEXT DEFAULT '',
      photo TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS likes (
      id TEXT PRIMARY KEY,
      from_user TEXT NOT NULL,
      to_user TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(from_user, to_user)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      from_user TEXT NOT NULL,
      to_user TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      reporter_id TEXT NOT NULL,
      reported_id TEXT NOT NULL,
      reason TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_likes_from
      ON likes(from_user);

    CREATE INDEX IF NOT EXISTS idx_likes_to
      ON likes(to_user);

    CREATE INDEX IF NOT EXISTS idx_messages_users
      ON messages(from_user, to_user);

    CREATE INDEX IF NOT EXISTS idx_notifications_user
      ON notifications(user_id);
  `);

  console.log("PostgreSQL database iko tayari.");
}

// ======================================================
// PASSWORD SECURITY
// ======================================================

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `scrypt:${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  if (!storedPassword) return false;

  // Password za zamani kama zilikuwa plaintext
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

  try {
    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(storedHash, "hex")
    );
  } catch {
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
  const cookies = req.headers.cookie || "";

  const match = cookies.match(
    /(?:^|;\s*)session=([^;]+)/
  );

  if (!match) return null;

  const session = sessions.get(match[1]);

  if (!session) return null;

  return session.userId;
}

async function auth(req, res, next) {
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
// COOKIE
// ======================================================

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `session=${token}; HttpOnly; Path=/; SameSite=Lax`
  );
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

    const numericAge = Number(age);

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
        error: "Password iwe na angalau herufi 6."
      });
    }

    if (
      !Number.isInteger(numericAge) ||
      numericAge < 18 ||
      numericAge > 100
    ) {
      return res.status(400).json({
        ok: false,
        error: "Umri lazima uwe kati ya miaka 18 na 100."
      });
    }

    if (!cleanGender) {
      return res.status(400).json({
        ok: false,
        error: "Tafadhali chagua jinsia."
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
        error: "Bio isiwe zaidi ya herufi 500."
      });
    }

    // Hakikisha email haipo
    const existing = await pool.query(
      `SELECT id FROM users WHERE email = $1 LIMIT 1`,
      [cleanEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({
        ok: false,
        error: "Email hii tayari imesajiliwa."
      });
    }

    // Picha
    let cleanPhoto = String(photo || "");

    if (cleanPhoto) {
      const allowed =
        /^data:image\/(jpeg|jpg|png|webp);base64,/i;

      if (!allowed.test(cleanPhoto)) {
        return res.status(400).json({
          ok: false,
          error: "Aina ya picha hairuhusiwi."
        });
      }

      const base64Part = cleanPhoto.split(",")[1] || "";

      // Takribani 5MB
      const estimatedBytes =
        Math.floor(base64Part.length * 0.75);

      if (estimatedBytes > 5 * 1024 * 1024) {
        return res.status(400).json({
          ok: false,
          error: "Picha ni kubwa sana. Maximum ni 5MB."
        });
      }
    }

    const userId = crypto.randomUUID();
    const hashedPassword = hashPassword(String(password));

    const result = await pool.query(
      `
      INSERT INTO users
      (
        id,
        name,
        email,
        password,
        age,
        gender,
        city,
        bio,
        photo
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING *
      `,
      [
        userId,
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

    // Login automatically baada ya registration
    const sessionToken = createSession(user.id);

    setSessionCookie(res, sessionToken);

    return res.json({
      ok: true,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      ok: false,
      error: "Imeshindikana kusajili akaunti."
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
      `SELECT * FROM users WHERE email = $1 LIMIT 1`,
      [email]
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

    // Kama password ilikuwa ya zamani/plaintext,
    // ibadilishe kuwa secure hash
    if (!user.password.startsWith("scrypt:")) {
      const newPassword = hashPassword(password);

      await pool.query(
        `UPDATE users SET password = $1 WHERE id = $2`,
        [newPassword, user.id]
      );

      user.password = newPassword;
    }

    const sessionToken = createSession(user.id);

    setSessionCookie(res, sessionToken);

    return res.json({
      ok: true,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      ok: false,
      error: "Tatizo limetokea wakati wa login."
    });
  }
});

// ======================================================
// LOGOUT
// ======================================================

app.post("/api/logout", (req, res) => {
  const cookies = req.headers.cookie || "";

  const match = cookies.match(
    /(?:^|;\s*)session=([^;]+)/
  );

  if (match) {
    sessions.delete(match[1]);
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

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM users WHERE id = $1 LIMIT 1`,
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        ok: false,
        error: "Akaunti haipo."
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
      error: "Imeshindikana kupata taarifa za akaunti."
    });
  }
});

// ======================================================
// DISCOVER
// ======================================================

app.get("/api/discover", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE id <> $1
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
      error: "Imeshindikana kupata profiles."
    });
  }
});

// ======================================================
// LIKE
// ======================================================

app.post("/api/like", auth, async (req, res) => {
  try {
    const targetId = String(
      req.body.userId ||
      req.body.toUser ||
      req.body.id ||
      ""
    ).trim();

    if (!targetId) {
      return res.status(400).json({
        ok: false,
        error: "User ID haipo."
      });
    }

    if (targetId === req.userId) {
      return res.status(400).json({
        ok: false,
        error: "Huwezi kujipa like mwenyewe."
      });
    }

    const target = await pool.query(
      `SELECT id, name FROM users WHERE id = $1 LIMIT 1`,
      [targetId]
    );

    if (target.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "User huyo hayupo."
      });
    }

    const existing = await pool.query(
      `
      SELECT id
      FROM likes
      WHERE from_user = $1 AND to_user = $2
      LIMIT 1
      `,
      [req.userId, targetId]
    );

    if (existing.rows.length > 0) {
      return res.json({
        ok: true,
        liked: true,
        match: false
      });
    }

    await pool.query(
      `
      INSERT INTO likes
      (id, from_user, to_user)
      VALUES ($1,$2,$3)
      `,
      [
        crypto.randomUUID(),
        req.userId,
        targetId
      ]
    );

    // Notification ya like
    await pool.query(
      `
      INSERT INTO notifications
      (id, user_id, title, message)
      VALUES ($1,$2,$3,$4)
      `,
      [
        crypto.randomUUID(),
        targetId,
        "❤️ Umepewa Like",
        "Mtu amekupenda kwenye Tanzania Dating."
      ]
    );

    // Angalia kama ni match
    const mutual = await pool.query(
      `
      SELECT id
      FROM likes
      WHERE from_user = $1
      AND to_user = $2
      LIMIT 1
      `,
      [targetId, req.userId]
    );

    let isMatch = false;

    if (mutual.rows.length > 0) {
      isMatch = true;

      await pool.query(
        `
        INSERT INTO notifications
        (id, user_id, title, message)
        VALUES ($1,$2,$3,$4)
        `,
        [
          crypto.randomUUID(),
          req.userId,
          "❤️ Match mpya!",
          "Mme-match! Sasa mnaweza kuanza kuwasiliana."
        ]
      );

      await pool.query(
        `
        INSERT INTO notifications
        (id, user_id, title, message)
        VALUES ($1,$2,$3,$4)
        `,
        [
          crypto.randomUUID(),
          targetId,
          "❤️ Match mpya!",
          "Mme-match! Sasa mnaweza kuanza kuwasiliana."
        ]
      );
    }

    res.json({
      ok: true,
      liked: true,
      match: isMatch
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

app.get("/api/matches", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT u.*
      FROM users u
      WHERE u.id IN (
        SELECT l1.to_user
        FROM likes l1
        INNER JOIN likes l2
          ON l2.from_user = l1.to_user
         AND l2.to_user = l1.from_user
        WHERE l1.from_user = $1
      )
      ORDER BY u.created_at DESC
      `,
      [req.userId]
    );

    res.json({
      ok: true,
      matches: result.rows.map(publicUser)
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

app.post("/api/profile", auth, async (req, res) => {
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
    const cleanGender = String(gender || "").trim();
    const cleanCity = String(city || "").trim();
    const cleanBio = String(bio || "").trim();

    const numericAge = Number(age);

    if (!cleanName) {
      return res.status(400).json({
        ok: false,
        error: "Jina linahitajika."
      });
    }

    if (
      !Number.isInteger(numericAge) ||
      numericAge < 18 ||
      numericAge > 100
    ) {
      return res.status(400).json({
        ok: false,
        error: "Umri lazima uwe kati ya 18 na 100."
      });
    }

    if (!cleanGender || !cleanCity) {
      return res.status(400).json({
        ok: false,
        error: "Jinsia na mji vinahitajika."
      });
    }

    if (cleanBio.length > 500) {
      return res.status(400).json({
        ok: false,
        error: "Bio isiwe zaidi ya herufi 500."
      });
    }

    let photoValue = null;

    if (typeof photo === "string" && photo.trim()) {
      const cleanPhoto = photo.trim();

      const allowed =
        /^data:image\/(jpeg|jpg|png|webp);base64,/i;

      if (!allowed.test(cleanPhoto)) {
        return res.status(400).json({
          ok: false,
          error: "Aina ya picha hairuhusiwi."
        });
      }

      const base64Part = cleanPhoto.split(",")[1] || "";

      const estimatedBytes =
        Math.floor(base64Part.length * 0.75);

      if (estimatedBytes > 5 * 1024 * 1024) {
        return res.status(400).json({
          ok: false,
          error: "Picha ni kubwa sana. Maximum ni 5MB."
        });
      }

      photoValue = cleanPhoto;
    }

    let result;

    if (photoValue !== null) {
      result = await pool.query(
        `
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
        `,
        [
          cleanName,
          numericAge,
          cleanGender,
          cleanCity,
          cleanBio,
          photoValue,
          req.userId
        ]
      );
    } else {
      result = await pool.query(
        `
        UPDATE users
        SET
          name = $1,
          age = $2,
          gender = $3,
          city = $4,
          bio = $5
        WHERE id = $6
        RETURNING *
        `,
        [
          cleanName,
          numericAge,
          cleanGender,
          cleanCity,
          cleanBio,
          req.userId
        ]
      );
    }

    if (result.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "Akaunti haipo."
      });
    }

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

// ======================================================
// NOTIFICATIONS
// ======================================================

app.get("/api/notifications", auth, async (req, res) => {
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

    const unread = result.rows.filter(
      n => !n.read
    ).length;

    res.json({
      ok: true,
      notifications: result.rows,
      unread
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

app.post(
  "/api/notifications/read-all",
  auth,
  async (req, res) => {
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
      console.error(
        "READ NOTIFICATIONS ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error: "Imeshindikana kusoma notifications."
      });
    }
  }
);

// ======================================================
// MESSAGES - GET
// ======================================================

app.get(
  "/api/messages/:id",
  auth,
  async (req, res) => {
    try {
      const otherUserId = String(req.params.id);

      // Hakikisha user mwingine yupo
      const other = await pool.query(
        `SELECT id FROM users WHERE id = $1 LIMIT 1`,
        [otherUserId]
      );

      if (other.rows.length === 0) {
        return res.status(404).json({
          ok: false,
          error: "User huyo hayupo."
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
        [
          req.userId,
          other
