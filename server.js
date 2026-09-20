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
  console.error(
    "ERROR: DATABASE_URL haijawekwa kwenye Environment Variables."
  );
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
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
    "Content-Type, Authorization, X-Session-Token"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

/* =========================================================
   COOKIE HELPERS
========================================================= */

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};

  header.split(";").forEach((part) => {
    const index = part.indexOf("=");

    if (index === -1) return;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (key) {
      cookies[key] = decodeURIComponent(value);
    }
  });

  return cookies;
}

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `session_token=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "session_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
  );
}

/* =========================================================
   SESSION
========================================================= */

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function createSession(userId) {
  const token = createToken();

  await pool.query(
    `
    INSERT INTO sessions
    (token, user_id, expires_at)
    VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '30 days')
    `,
    [token, Number(userId)]
  );

  return token;
}

function getToken(req) {
  const auth = req.headers.authorization || "";

  if (auth.startsWith("Bearer ")) {
    return auth.substring(7).trim();
  }

  if (req.headers["x-session-token"]) {
    return String(req.headers["x-session-token"]);
  }

  const cookies = parseCookies(req);

  if (cookies.session_token) {
    return cookies.session_token;
  }

  return null;
}

/* =========================================================
   AUTH
========================================================= */

async function auth(req, res, next) {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({
        ok: false,
        message: "Hujaingia kwenye akaunti.",
        error: "Hujaingia kwenye akaunti."
      });
    }

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
        u.latitude,
        u.longitude,
        u.created_at

      FROM sessions s

      JOIN users u
        ON u.id = s.user_id

      WHERE
        s.token = $1
        AND s.expires_at > CURRENT_TIMESTAMP
      `,
      [token]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        ok: false,
        message: "Session imeisha. Ingia tena.",
        error: "Session imeisha. Ingia tena."
      });
    }

    req.user = result.rows[0];
    req.token = token;

    next();
  } catch (error) {
    console.error("AUTH ERROR:", error);

    return res.status(500).json({
      ok: false,
      message: "Tatizo la server.",
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
    .pbkdf2Sync(
      password,
      salt,
      100000,
      64,
      "sha512"
    )
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
      .pbkdf2Sync(
        password,
        salt,
        100000,
        64,
        "sha512"
      )
      .toString("hex");

    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(storedHash, "hex");

    if (a.length !== b.length) {
      return false;
    }

    return crypto.timingSafeEqual(a, b);
  } catch (error) {
    return false;
  }
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initDatabase() {

  /* USERS */

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
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  /* MIGRATION FOR OLD DATABASE */

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION
  `);

  /* LIKES */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS likes (
      id SERIAL PRIMARY KEY,

      from_user INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      to_user INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      UNIQUE(from_user, to_user)
    );
  `);

  /* MESSAGES */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,

      from_user INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      to_user INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      message TEXT NOT NULL,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  /* NOTIFICATIONS */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,

      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      type TEXT DEFAULT 'general',

      title TEXT DEFAULT '',

      message TEXT DEFAULT '',

      related_user INTEGER,

      is_read BOOLEAN DEFAULT FALSE,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  /* REPORTS */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,

      reporter INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      reported INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      reason TEXT NOT NULL,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  /* SESSIONS */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,

      token TEXT UNIQUE NOT NULL,

      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      expires_at TIMESTAMP NOT NULL,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  /* INDEXES */

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_users_location
    ON users(latitude, longitude)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_likes_from
    ON likes(from_user)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_likes_to
    ON likes(to_user)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_messages_users
    ON messages(from_user, to_user)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_notifications_user
    ON notifications(user_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_sessions_token
    ON sessions(token)
  `);

  /* CLEAN EXPIRED SESSIONS */

  await pool.query(`
    DELETE FROM sessions
    WHERE expires_at < CURRENT_TIMESTAMP
  `);

  console.log("Database tables ready.");
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
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

    /* VALIDATION */

    if (!name || !email || !password) {

      return res.status(400).json({
        ok: false,
        message: "Jaza jina, email na password.",
        error: "Jaza jina, email na password."
      });

    }

    if (String(name).trim().length < 2) {

      return res.status(400).json({
        ok: false,
        message: "Jina liwe na angalau characters 2.",
        error: "Jina liwe na angalau characters 2."
      });

    }

    if (String(password).length < 6) {

      return res.status(400).json({
        ok: false,
        message: "Password iwe na angalau characters 6.",
        error: "Password iwe na angalau characters 6."
      });

    }

    const cleanEmail =
      String(email)
        .trim()
        .toLowerCase();

    const cleanName =
      String(name).trim();

    const cleanCity =
      String(city || "").trim();

    const cleanGender =
      String(gender || "").trim();

    const cleanBio =
      String(bio || "").trim();

    const cleanPhoto =
      String(photo || "").trim();

    let cleanAge = null;

    if (age !== undefined && age !== null && age !== "") {

      cleanAge = Number(age);

      if (
        !Number.isInteger(cleanAge) ||
        cleanAge < 18 ||
        cleanAge > 100
      ) {

        return res.status(400).json({
          ok: false,
          message: "Umri lazima uwe kati ya miaka 18 na 100.",
          error: "Umri lazima uwe kati ya miaka 18 na 100."
        });

      }
    }

    /* CHECK EMAIL */

    const exists = await pool.query(
      `
      SELECT id
      FROM users
      WHERE email = $1
      `,
      [cleanEmail]
    );

    if (exists.rows.length) {

      return res.status(409).json({
        ok: false,
        message: "Email hii tayari imesajiliwa.",
        error: "Email hii tayari imesajiliwa."
      });

    }

    /* PASSWORD */

    const hashedPassword =
      hashPassword(password);

    /* INSERT */

    const result = await pool.query(
      `
      INSERT INTO users
      (
        name,
        email,
        password,
        age,
        gender,
        city,
        bio,
        photo
      )

      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8)

      RETURNING
        id,
        name,
        email,
        age,
        gender,
        city,
        bio,
        photo,
        latitude,
        longitude,
        created_at
      `,
      [
        cleanName,
        cleanEmail,
        hashedPassword,
        cleanAge,
        cleanGender,
        cleanCity,
        cleanBio,
        cleanPhoto
      ]
    );

    const user = result.rows[0];

    /* CREATE SESSION */

    const token =
      await createSession(user.id);

    /* COOKIE */

    setSessionCookie(
      res,
      token
    );

    /* RESPONSE */

    return res.status(201).json({
      ok: true,
      token,
      user
    });

  } catch (error) {

    console.error(
      "REGISTER ERROR:",
      error
    );

    return res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kusajili akaunti: " +
        error.message,
      error:
        "Imeshindikana kusajili akaunti: " +
        error.message
    });

  }

});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {

  try {

    const {
      email,
      password
    } = req.body;

    if (!email || !password) {

      return res.status(400).json({
        ok: false,
        message: "Weka email na password.",
        error: "Weka email na password."
      });

    }

    const cleanEmail =
      String(email)
        .trim()
        .toLowerCase();

    const result =
      await pool.query(
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
        message: "Email au password sio sahihi.",
        error: "Email au password sio sahihi."
      });

    }

    const user =
      result.rows[0];

    if (
      !verifyPassword(
        password,
        user.password
      )
    ) {

      return res.status(401).json({
        ok: false,
        message: "Email au password sio sahihi.",
        error: "Email au password sio sahihi."
      });

    }

    delete user.password;

    const token =
      await createSession(user.id);

    setSessionCookie(
      res,
      token
    );

    return res.json({
      ok: true,
      token,
      user
    });

  } catch (error) {

    console.error(
      "LOGIN ERROR:",
      error
    );

    return res.status(500).json({
      ok: false,
      message: "Imeshindikana kuingia.",
      error: "Imeshindikana kuingia."
    });

  }

});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", auth, async (req, res) => {

  try {

    await pool.query(
      `
      DELETE FROM sessions
      WHERE token = $1
      `,
      [req.token]
    );

    clearSessionCookie(res);

    res.json({
      ok: true,
      message: "Umetoka kwenye akaunti."
    });

  } catch (error) {

    console.error(
      "LOGOUT ERROR:",
      error
    );

    clearSessionCookie(res);

    res.json({
      ok: true
    });

  }

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

    const result =
      await pool.query(
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

        LIMIT 100
        `,
        [req.user.id]
      );

    res.json({
      ok: true,
      users: result.rows
    });

  } catch (error) {

    console.error(
      "USERS ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message: "Imeshindikana kupata users.",
      error: "Imeshindikana kupata users."
    });

  }

});

/* =========================================================
   UPDATE LOCATION
========================================================= */

app.post("/api/location", auth, async (req, res) => {

  try {

    const latitude =
      Number(req.body.latitude);

    const longitude =
      Number(req.body.longitude);

    if (
      !Number.isFinite(latitude) ||
      !Number.isFinite(longitude)
    ) {

      return res.status(400).json({
        ok: false,
        message: "Location si sahihi.",
        error: "Location si sahihi."
      });

    }

    if (
      latitude < -90 ||
      latitude > 90 ||
      longitude < -180 ||
      longitude > 180
    ) {

      return res.status(400).json({
        ok: false,
        message: "Coordinates si sahihi.",
        error: "Coordinates si sahihi."
      });

    }

    await pool.query(
      `
      UPDATE users

      SET
        latitude = $1,
        longitude = $2

      WHERE id = $3
      `,
      [
        latitude,
        longitude,
        req.user.id
      ]
    );

    res.json({
      ok: true,
      message: "Location imehifadhiwa."
    });

  } catch (error) {

    console.error(
      "LOCATION ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message: "Imeshindikana kuhifadhi location.",
      error: "Imeshindikana kuhifadhi location."
    });

  }

});

/* =========================================================
   NEARBY
========================================================= */

app.get("/api/nearby", auth, async (req, res) => {

  try {

    let radius =
      Number(req.query.radius);

    if (!Number.isFinite(radius)) {
      radius = 25;
    }

    /* Minimum 1km, maximum 100km */

    radius =
      Math.min(
        Math.max(radius, 1),
        100
      );

    /* GET CURRENT LOCATION */

    const me =
      await pool.query(
        `
        SELECT
          latitude,
          longitude

        FROM users

        WHERE id = $1
        `,
        [req.user.id]
      );

    if (!me.rows.length) {

      return res.status(404).json({
        ok: false,
        message: "Profile haijapatikana.",
        error: "Profile haijapatikana."
      });

    }

    const latitude =
      Number(me.rows[0].latitude);

    const longitude =
      Number(me.rows[0].longitude);

    if (
      !Number.isFinite(latitude) ||
      !Number.isFinite(longitude)
    ) {

      return res.status(400).json({
        ok: false,
        message:
          "Washa location kwenye simu yako kwanza.",
        error:
          "Washa location kwenye simu yako kwanza."
      });

    }

    /*
      HAVERSINE FORMULA

      Distance calculated in KM.
    */

    const result =
      await pool.query(
        `
        SELECT *
        FROM (
          SELECT

            id,
            name,
            age,
            gender,
            city,
            bio,
            photo,

            ROUND(
              (
                6371 *
                acos(
                  LEAST(
                    1,
                    GREATEST(
                      -1,

                      cos(radians($1))
                      *
                      cos(radians(latitude))
                      *
                      cos(
                        radians(longitude)
                        -
                        radians($2)
                      )

                      +

                      sin(radians($1))
                      *
                      sin(radians(latitude))
                    )
                  )
                )
              )::numeric,
              2
            ) AS distance_km

          FROM users

          WHERE
            id <> $3

            AND latitude IS NOT NULL
            AND longitude IS NOT NULL

        ) nearby

        WHERE distance_km <= $4

        ORDER BY distance_km ASC

        LIMIT 100
        `,
        [
          latitude,
          longitude,
          req.user.id,
          radius
        ]
      );

    res.json({
      ok: true,
      radius_km: radius,
      users: result.rows
    });

  } catch (error) {

    console.error(
      "NEARBY ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kupata watu walio karibu.",
      error:
        "Imeshindikana kupata watu walio karibu."
    });

  }

});

/* =========================================================
   PROFILE
========================================================= */

app.get("/api/profile", auth, async (req, res) => {

  try {

    const result =
      await pool.query(
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
          latitude,
          longitude,
          created_at

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

    console.error(
      "PROFILE ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kupata profile.",
      error:
        "Imeshindikana kupata profile."
    });

  }

});

/* =========================================================
   UPDATE PROFILE
========================================================= */

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

    let cleanAge = null;

    if (
      age !== undefined &&
      age !== null &&
      age !== ""
    ) {

      cleanAge =
        Number(age);

      if (
        !Number.isInteger(cleanAge) ||
        cleanAge < 18 ||
        cleanAge > 100
      ) {

        return res.status(400).json({
          ok: false,
          message:
            "Umri lazima uwe kati ya 18 na 100.",
          error:
            "Umri lazima uwe kati ya 18 na 100."
        });

      }

    }

    const result =
      await pool.query(
        `
        UPDATE users

        SET
          name =
            COALESCE(NULLIF($1,''), name),

          age =
            COALESCE($2, age),

          gender =
            COALESCE(NULLIF($3,''), gender),

          city =
            COALESCE(NULLIF($4,''), city),

          bio =
            COALESCE($5, bio),

          photo =
            COALESCE($6, photo)

        WHERE id = $7

        RETURNING
          id,
          name,
          email,
          age,
          gender,
          city,
          bio,
          photo,
          latitude,
          longitude,
          created_at
        `,
        [
          name !== undefined
            ? String(name).trim()
            : null,

          cleanAge,

          gender !== undefined
            ? String(gender).trim()
            : null,

          city !== undefined
            ? String(city).trim()
            : null,

          bio !== undefined
            ? String(bio)
            : null,

          photo !== undefined
            ? String(photo)
            : null,

          req.user.id
        ]
      );

    res.json({
      ok: true,
      user: result.rows[0]
    });

  } catch (error) {

    console.error(
      "UPDATE PROFILE ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kusasisha profile.",
      error:
        "Imeshindikana kusasisha profile."
    });

  }

});

/* =========================================================
   LIKE
========================================================= */

app.post("/api/like/:id", auth, async (req, res) => {

  try {

    const toUser =
      Number(req.params.id);

    if (
      !Number.isInteger(toUser) ||
      toUser <= 0 ||
      toUser === Number(req.user.id)
    ) {

      return res.status(400).json({
        ok: false,
        message: "User si sahihi.",
        error: "User si sahihi."
      });

    }

    const userExists =
      await pool.query(
        `
        SELECT id, name
        FROM users
        WHERE id = $1
        `,
        [toUser]
      );

    if (!userExists.rows.length) {

      return res.status(404).json({
        ok: false,
        message: "User hajapatikana.",
        error: "User hajapatikana."
      });

    }

    await pool.query(
      `
      INSERT INTO likes
      (from_user, to_user)

      VALUES
      ($1,$2)

      ON CONFLICT
      (from_user,to_user)
      DO NOTHING
      `,
      [
        req.user.id,
        toUser
      ]
    );

    const mutual =
      await pool.query(
        `
        SELECT id
        FROM likes

        WHERE
          from_user = $1
          AND to_user = $2
        `,
        [
          toUser,
          req.user.id
        ]
      );

    const match =
      mutual.rows.length > 0;

    if (match) {

      /* NOTIFICATION TO OTHER USER */

      try {

        await pool.query(
          `
          INSERT INTO notifications
          (
            user_id,
            type,
            title,
            message,
            related_user
          )

          VALUES
          ($1,$2,$3,$4,$5)
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
          notificationError
        );

      }

    }

    res.json({
      ok: true,
      liked: true,
      match
    });

  } catch (error) {

    console.error(
      "LIKE ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kuweka like.",
      error:
        "Imeshindikana kuweka like."
    });

  }

});

/* =========================================================
   MATCHES
========================================================= */

app.get("/api/matches", auth, async (req, res) => {

  try {

    const result =
      await pool.query(
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

        WHERE
          l1.from_user = $1

        ORDER BY u.name
        `,
        [req.user.id]
      );

    res.json({
      ok: true,
      matches: result.rows
    });

  } catch (error) {

    console.error(
      "MATCHES ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kupata matches.",
      error:
        "Imeshindikana kupata matches."
    });

  }

});

/* =========================================================
   CHATS
========================================================= */

app.get("/api/chats", auth, async (req, res) => {

  try {

    const result =
      await pool.query(
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
              (
                m.from_user = $1
                AND
                m.to_user = u.id
              )

              OR

              (
                m.from_user = u.id
                AND
                m.to_user = $1
              )

            ORDER BY
              m.created_at DESC

            LIMIT 1

          ) AS last_message,

          (
            SELECT m.created_at

            FROM messages m

            WHERE
              (
                m.from_user = $1
                AND
                m.to_user = u.id
              )

              OR

              (
                m.from_user = u.id
                AND
                m.to_user = $1
              )

            ORDER BY
              m.created_at DESC

            LIMIT 1

          ) AS last_message_time

        FROM users u

        WHERE u.id IN (

          SELECT DISTINCT

            CASE

              WHEN from_user = $1
              THEN to_user

              ELSE from_user

            END

          FROM messages

          WHERE
            from_user = $1
            OR
            to_user = $1
        )

        ORDER BY
          last_message_time DESC NULLS LAST
        `,
        [req.user.id]
      );

    res.json({
      ok: true,
      chats: result.rows
    });

  } catch (error) {

    console.error(
      "CHATS ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kupata chats.",
      error:
        "Imeshindikana kupata chats."
    });

  }

});

/* =========================================================
   GET MESSAGES
========================================================= */

app.get("/api/messages/:id", auth, async (req, res) => {

  try {

    const otherUser =
      Number(req.params.id);

    if (!otherUser) {

      return res.status(400).json({
        ok: false,
        message:
          "User wa chat hajapatikana.",
        error:
          "User wa chat hajapatikana."
      });

    }

    const result =
      await pool.query(
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

          (
            m.from_user = $1
            AND
            m.to_user = $2
          )

          OR

          (
            m.from_user = $2
            AND
            m.to_user = $1
          )

        ORDER BY
          m.created_at ASC
        `,
        [
          req.user.id,
          otherUser
        ]
      );

    res.json({
      ok: true,
      messages: result.rows
    });

  } catch (error) {

    console.error(
      "GET MESSAGES ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kupata ujumbe.",
      error:
        "Imeshindikana kupata ujumbe."
    });

  }

});

/* =========================================================
   SEND MESSAGE
========================================================= */

app.post("/api/messages/:id", auth, async (req, res) => {

  try {

    const toUser =
      Number(req.params.id);

    const message =
      String(
        req.body.message || ""
      ).trim();

    if (!toUser) {

      return res.status(400).json({
        ok: false,
        message:
          "Mtumiaji hajapatikana.",
        error:
          "Mtumiaji hajapatikana."
      });

    }

    if (
      toUser === Number(req.user.id)
    ) {

      return res.status(400).json({
        ok: false,
        message:
          "Huwezi kujitumia ujumbe.",
        error:
          "Huwezi kujitumia ujumbe."
      });

    }

    if (!message) {

      return res.status(400).json({
        ok: false,
        message:
          "Andika ujumbe kwanza.",
        error:
          "Andika ujumbe kwanza."
      });

    }

    if (message.length > 5000) {

      return res.status(400).json({
        ok: false,
        message:
          "Ujumbe ni mrefu sana.",
        error:
          "Ujumbe ni mrefu sana."
      });

    }

    const recipient =
      await pool.query(
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
        message:
          "Mtumiaji huyo hajapatikana.",
        error:
          "Mtumiaji huyo hajapatikana."
      });

    }

    /* SAVE MESSAGE */

    const result =
      await pool.query(
        `
        INSERT INTO messages
        (
          from_user,
          to_user,
          message
        )

        VALUES
        ($1,$2,$3)

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

    const savedMessage =
      result.rows[0];

    /* NOTIFICATION */

    try {

      await pool.query(
        `
        INSERT INTO notifications
        (
          user_id,
          type,
          title,
          message,
          related_user
        )

        VALUES
        ($1,$2,$3,$4,$5)
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
        notificationError
      );

    }

    res.json({
      ok: true,
      success: true,
      message: savedMessage
    });

  } catch (error) {

    console.error(
      "SEND MESSAGE ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      success: false,
      message:
        "Imeshindikana kutuma ujumbe.",
      error:
        "Imeshindikana kutuma ujumbe."
    });

  }

});

/* =========================================================
   NOTIFICATIONS
========================================================= */

app.get("/api/notifications", auth, async (req, res) => {

  try {

    const result =
      await pool.query(
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

        ORDER BY
          created_at DESC

        LIMIT 100
        `,
        [req.user.id]
      );

    res.json({
      ok: true,
      notifications: result.rows
    });

  } catch (error) {

    console.error(
      "NOTIFICATIONS ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kupata notifications.",
      error:
        "Imeshindikana kupata notifications."
    });

  }

});

/* =========================================================
   NOTIFICATION COUNT
========================================================= */

app.get("/api/notifications/count", auth, async (req, res) => {

  try {

    const result =
      await pool.query(
        `
        SELECT COUNT(*)::integer AS count

        FROM notifications

        WHERE
          user_id = $1
          AND is_read = FALSE
        `,
        [req.user.id]
      );

    res.json({
      ok: true,
      count: result.rows[0].count
    });

  } catch (error) {

    console.error(
      "NOTIFICATION COUNT ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      count: 0
    });

  }

});

/* =========================================================
   MARK NOTIFICATIONS READ
========================================================= */

app.post(
  "/api/notifications/read",
  auth,
  async (req, res) => {

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

      console.error(
        "READ NOTIFICATIONS ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Imeshindikana kusoma notifications.",
        error:
          "Imeshindikana kusoma notifications."
      });

    }

  }
);

/* =========================================================
   REPORT USER
========================================================= */

app.post("/api/report/:id", auth, async (req, res) => {

  try {

    const reported =
      Number(req.params.id);

    const reason =
      String(
        req.body.reason || ""
      ).trim();

    if (!reported) {

      return res.status(400).json({
        ok: false,
        message: "User si sahihi.",
        error: "User si sahihi."
      });

    }

    if (
      reported === Number(req.user.id)
    ) {

      return res.status(400).json({
        ok: false,
        message:
          "Huwezi kujireport.",
        error:
          "Huwezi kujireport."
      });

    }

    if (!reason) {

      return res.status(400).json({
        ok: false,
        message:
          "Andika sababu ya report.",
        error:
          "Andika sababu ya report."
      });

    }

    await pool.query(
      `
      INSERT INTO reports
      (
        reporter,
        reported,
        reason
      )

      VALUES
      ($1,$2,$3)
      `,
      [
        Number(req.user.id),
        reported,
        reason
      ]
    );

    res.json({
      ok: true,
      message:
        "Report imetumwa."
    });

  } catch (error) {

    console.error(
      "REPORT ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kutuma report.",
      error:
        "Imeshindikana kutuma report."
    });

  }

});

/* =========================================================
   DELETE ACCOUNT
========================================================= */

app.delete("/api/account", auth, async (req, res) => {

  try {

    await pool.query(
      `
      DELETE FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    clearSessionCookie(res);

    res.json({
      ok: true,
      message:
        "Account imefutwa."
    });

  } catch (error) {

    console.error(
      "DELETE ACCOUNT ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Imeshindikana kufuta account.",
      error:
        "Imeshindikana kufuta account."
    });

  }

});

/* =========================================================
   API 404
========================================================= */

app.use("/api", (req, res) => {

  res.status(404).json({
    ok: false,
    message:
      "API endpoint haijapatikana.",
    error:
      "API endpoint haijapatikana."
  });

});

/* =========================================================
   GLOBAL ERROR
========================================================= */

app.use(
  (err, req, res, next) => {

    console.error(
      "GLOBAL ERROR:",
      err
    );

    if (res.headersSent) {
      return next(err);
    }

    res.status(500).json({
      ok: false,
      message:
        "Server error.",
      error:
        "Server error."
    });

  }
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {

  try {

    if (!process.env.DATABASE_URL) {

      console.error(
        "DATABASE_URL haipo."
      );

    }

    await initDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          "----------------------------------------"
        );

        console.log(
          "Tanzania Dating server is running"
        );

        console.log(
          `PORT: ${PORT}`
        );

        console.log(
          "Nearby: ENABLED"
        );

        console.log(
          "PostgreSQL: ENABLED"
        );

        console.log(
          "Sessions: ENABLED"
        );

        console.log(
          "----------------------------------------"
        );

      }
    );

  } catch (error) {

    console.error(
      "SERVER START ERROR:",
      error
    );

    process.exit(1);

  }

}

startServer();
