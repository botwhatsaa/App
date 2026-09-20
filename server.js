// ============================================================
// TANZANIA DATING - SERVER.JS
// Node.js + Express + PostgreSQL
// ============================================================

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;

// ============================================================
// ENVIRONMENT
// ============================================================

const DATABASE_URL = process.env.DATABASE_URL;

const JWT_SECRET =
  process.env.JWT_SECRET || "tanzania-dating-secret-change-this";

// ============================================================
// DATABASE
// ============================================================

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL haijawekwa kwenye Environment.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Test database connection
pool
  .connect()
  .then((client) => {
    console.log("PostgreSQL connected successfully");
    client.release();
  })
  .catch((error) => {
    console.error("PostgreSQL connection error:", error.message);
  });

// ============================================================
// EXPRESS SETTINGS
// ============================================================

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Serve frontend
app.use(express.static(path.join(__dirname, "public")));

// ============================================================
// DATABASE TABLES
// ============================================================

async function initializeDatabase() {
  try {
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
      );
    `);

    console.log("Users table ready");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("Messages table ready");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS likes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        liked_user_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, liked_user_id)
      );
    `);

    console.log("Likes table ready");

  } catch (error) {
    console.error("Database initialization error:");
    console.error(error);
  }
}

// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/api", (req, res) => {
  res.json({
    success: true,
    message: "Tanzania Dating API is running",
    status: "online",
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      database: "connected",
      server: "online",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      database: "disconnected",
      error: error.message,
    });
  }
});

// ============================================================
// REGISTER
// ============================================================

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
      photo,
    } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Jina, email na password vinahitajika.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password lazima iwe na angalau characters 6.",
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // Check existing email
    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [cleanEmail]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Email hii tayari imesajiliwa.",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Insert user
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
        age || null,
        gender || null,
        city || null,
        bio || null,
        photo || null,
      ]
    );

    const user = result.rows[0];

    // Create token
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      JWT_SECRET,
      {
        expiresIn: "30d",
      }
    );

    res.status(201).json({
      success: true,
      message: "Usajili umefanikiwa.",
      token,
      user,
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kusajili account.",
      error: error.message,
    });
  }
});

// ============================================================
// LOGIN
// ============================================================

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email na password vinahitajika.",
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
        message: "Email au password sio sahihi.",
      });
    }

    const user = result.rows[0];

    // Compare password
    const passwordCorrect = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        message: "Email au password sio sahihi.",
      });
    }

    // Token
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      JWT_SECRET,
      {
        expiresIn: "30d",
      }
    );

    // Never send password to frontend
    delete user.password;

    res.json({
      success: true,
      message: "Login imefanikiwa.",
      token,
      user,
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Tatizo limetokea wakati wa login.",
      error: error.message,
    });
  }
});

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      success: false,
      message: "Token haipo.",
    });
  }

  const parts = authHeader.split(" ");

  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({
      success: false,
      message: "Authorization format sio sahihi.",
    });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();

  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Token ime-expire au sio sahihi.",
    });
  }
}

// ============================================================
// CURRENT USER
// ============================================================

app.get("/api/me", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, name, email, age, gender, city, bio, photo, created_at
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User hakupatikana.",
      });
    }

    res.json({
      success: true,
      user: result.rows[0],
    });

  } catch (error) {
    console.error("ME ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Server error.",
    });
  }
});

// ============================================================
// GET USERS / DISCOVER
// ============================================================

app.get("/api/users", authenticateToken, async (req, res) => {
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
      WHERE id != $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [req.user.id]
    );

    res.json({
      success: true,
      users: result.rows,
    });

  } catch (error) {
    console.error("USERS ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kupata users.",
    });
  }
});

// ============================================================
// GET USER PROFILE
// ============================================================

app.get("/api/users/:id", authenticateToken, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (isNaN(userId)) {
      return res.status(400).json({
        success: false,
        message: "User ID sio sahihi.",
      });
    }

    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        age,
        gender,
        city,
        bio,
        photo,
        created_at
      FROM users
      WHERE id = $1
      `,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User hakupatikana.",
      });
    }

    res.json({
      success: true,
      user: result.rows[0],
    });

  } catch (error) {
    console.error("PROFILE ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Server error.",
    });
  }
});

// ============================================================
// UPDATE PROFILE
// ============================================================

app.put("/api/profile", authenticateToken, async (req, res) => {
  try {
    const {
      name,
      age,
      gender,
      city,
      bio,
      photo,
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
      RETURNING id, name, email, age, gender, city, bio, photo
      `,
      [
        name || null,
        age || null,
        gender || null,
        city || null,
        bio || null,
        photo || null,
        req.user.id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User hakupatikana.",
      });
    }

    res.json({
      success: true,
      message: "Profile imebadilishwa.",
      user: result.rows[0],
    });

  } catch (error) {
    console.error("UPDATE PROFILE ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kubadilisha profile.",
    });
  }
});

// ============================================================
// LIKE USER
// ============================================================

app.post("/api/like", authenticateToken, async (req, res) => {
  try {
    const likedUserId = parseInt(req.body.userId);

    if (isNaN(likedUserId)) {
      return res.status(400).json({
        success: false,
        message: "User ID sio sahihi.",
      });
    }

    if (likedUserId === req.user.id) {
      return res.status(400).json({
        success: false,
        message: "Huwezi kujilike mwenyewe.",
      });
    }

    await pool.query(
      `
      INSERT INTO likes (user_id, liked_user_id)
      VALUES ($1, $2)
      ON CONFLICT (user_id, liked_user_id)
      DO NOTHING
      `,
      [req.user.id, likedUserId]
    );

    res.json({
      success: true,
      message: "Like imehifadhiwa.",
    });

  } catch (error) {
    console.error("LIKE ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kuhifadhi like.",
    });
  }
});

// ============================================================
// SEND MESSAGE
// ============================================================

app.post("/api/messages", authenticateToken, async (req, res) => {
  try {
    const {
      receiverId,
      message,
    } = req.body;

    if (!receiverId || !message) {
      return res.status(400).json({
        success: false,
        message: "Receiver na message vinahitajika.",
      });
    }

    const receiver = await pool.query(
      "SELECT id FROM users WHERE id = $1",
      [receiverId]
    );

    if (receiver.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Receiver hakupatikana.",
      });
    }

    const result = await pool.query(
      `
      INSERT INTO messages
      (sender_id, receiver_id, message)
      VALUES ($1,$2,$3)
      RETURNING id, sender_id, receiver_id, message, created_at
      `,
      [
        req.user.id,
        receiverId,
        message.trim(),
      ]
    );

    res.status(201).json({
      success: true,
      message: "Ujumbe umetumwa.",
      data: result.rows[0],
    });

  } catch (error) {
    console.error("MESSAGE ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kutuma ujumbe.",
    });
  }
});

// ============================================================
// GET CHAT
// ============================================================

app.get(
 
