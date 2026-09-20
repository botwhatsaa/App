const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
  process.env.JWT_SECRET || "tanzania-dating-secret-2026";

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL haijawekwa kwenye Render Environment.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

app.use(express.static(path.join(__dirname, "public")));

// ===============================
// DATABASE
// ===============================

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      age INTEGER,
      gender VARCHAR(30),
      city VARCHAR(100),
      bio TEXT,
      photo TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS likes (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      liked_user_id INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, liked_user_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL,
      receiver_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log("Database tables ready");
}

// ===============================
// HOME
// ===============================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ===============================
// HEALTH
// ===============================

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      server: "online",
      database: "connected"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      server: "online",
      database: "error",
      message: error.message
    });
  }
});

// ===============================
// REGISTER
// ===============================

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
        success: false,
        message: "Jina, email na password vinahitajika."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password iwe na angalau characters 6."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const exists = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [cleanEmail]
    );

    if (exists.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Email hii tayari imesajiliwa."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (name,email,password,age,gender,city,bio,photo)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING id,name,email,age,gender,city,bio,photo
      `,
      [
        name.trim(),
        cleanEmail,
        hashedPassword,
        age || null,
        gender || null,
        city || null,
        bio || null,
        photo || null
      ]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      JWT_SECRET,
      {
        expiresIn: "30d"
      }
    );

    res.status(201).json({
      success: true,
      message: "Usajili umefanikiwa.",
      token,
      user
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Registration failed.",
      error: error.message
    });
  }
});

// ===============================
// LOGIN
// ===============================

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email na password vinahitajika."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [cleanEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Email au password sio sahihi."
      });
    }

    const user = result.rows[0];

    const correct = await bcrypt.compare(
      password,
      user.password
    );

    if (!correct) {
      return res.status(401).json({
        success: false,
        message: "Email au password sio sahihi."
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      JWT_SECRET,
      {
        expiresIn: "30d"
      }
    );

    delete user.password;

    res.json({
      success: true,
      message: "Login imefanikiwa.",
      token,
      user
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Login failed.",
      error: error.message
    });
  }
});

// ===============================
// AUTH
// ===============================

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({
      success: false,
      message: "Token haipo."
    });
  }

  const parts = header.split(" ");

  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({
      success: false,
      message: "Invalid authorization."
    });
  }

  try {
    const decoded = jwt.verify(
      parts[1],
      JWT_SECRET
    );

    req.user = decoded;

    next();

  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Token sio sahihi au ime-expire."
    });
  }
}

// ===============================
// CURRENT USER
// ===============================

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id,name,email,age,gender,city,bio,photo
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User hakupatikana."
      });
    }

    res.json({
      success: true,
      user: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ===============================
// ALL USERS
// ===============================

app.get("/api/users", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id,name,age,gender,city,bio,photo
      FROM users
      WHERE id != $1
      ORDER BY created_at DESC
      `,
      [req.user.id]
    );

    res.json({
      success: true,
      users: result.rows
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ===============================
// PROFILE
// ===============================

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
        name = COALESCE($1,name),
        age = COALESCE($2,age),
        gender = COALESCE($3,gender),
        city = COALESCE($4,city),
        bio = COALESCE($5,bio),
        photo = COALESCE($6,photo)
      WHERE id = $7
      RETURNING id,name,email,age,gender,city,bio,photo
      `,
      [
        name || null,
        age || null,
        gender || null,
        city || null,
        bio || null,
        photo || null,
        req.user.id
      ]
    );

    res.json({
      success: true,
      user: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ===============================
// LIKE
// ===============================

app.post("/api/like", auth, async (req, res) => {
  try {
    const userId = Number(req.body.userId);

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "userId inahitajika."
      });
    }

    await pool.query(
      `
      INSERT INTO likes(user_id,liked_user_id)
      VALUES($1,$2)
      ON CONFLICT(user_id,liked_user_id)
      DO NOTHING
      `,
      [req.user.id, userId]
    );

    res.json({
      success: true,
      message: "Like imehifadhiwa."
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ===============================
// SEND MESSAGE
// ===============================

app.post("/api/messages", auth, async (req, res) => {
  try {
    const receiverId = Number(req.body.receiverId);
    const message = String(req.body.message || "").trim();

    if (!receiverId || !message) {
      return res.status(400).json({
        success: false,
        message: "Receiver na message vinahitajika."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO messages
      (sender_id,receiver_id,message)
      VALUES($1,$2,$3)
      RETURNING *
      `,
      [
        req.user.id,
        receiverId,
        message
      ]
    );

    res.status(201).json({
      success: true,
      message: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ===============================
// GET MESSAGES
// ===============================

app.get("/api/messages/:id", auth, async (req, res) => {
  try {
    const otherUser = Number(req.params.id);

    const result = await pool.query(
      `
      SELECT *
      FROM messages
      WHERE
        (sender_id=$1 AND receiver_id=$2)
        OR
        (sender_id=$2 AND receiver_id=$1)
      ORDER BY created_at ASC
      `,
      [
        req.user.id,
        otherUser
      ]
    );

    res.json({
      success: true,
      messages: result.rows
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ===============================
// START SERVER
// ===============================

async function start() {
  try {
    await setupDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("================================");
      console.log("TANZANIA DATING SERVER ONLINE");
      console.log("PORT:", PORT);
      console.log("================================");
    });

  } catch (error) {
    console.error("SERVER START ERROR:");
    console.error(error);
    process.exit(1);
  }
}

start();
