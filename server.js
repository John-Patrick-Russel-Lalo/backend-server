const express = require("express");
const http = require("http");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const server = http.createServer(app);

// Initialize WebSocket server
const { initWebSocket } = require("./websocket");

app.use(express.json());

// CORS: Allow specific origins for dev/prod with credentials
const allowedOrigins = [
  "http://localhost:5500", // If using localhost:5500
  "http://127.0.0.1:5500", // Your current frontend (VS Code Live Server)
  "http://localhost:8080", // If using npx http-server
  // Add more if needed, e.g., 'https://yourdomain.com' for prod
];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g., mobile apps) or matching origins
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true, // Required for cookies
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

const cookieParser = require("cookie-parser");
app.use(cookieParser());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const JWT_SECRET = process.env.JWT_SECRET || "supersecret"; // Use strong secret in .env
const REFRESH_SECRET = process.env.REFRESH_SECRET || "refreshsecret"; // Use strong secret in .env
const NODE_ENV = process.env.NODE_ENV || "development";

// Helper to create tokens
function createTokens(user) {
  const accessToken = jwt.sign(
    { userId: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "15m" } // Consistent 15m expiry
  );

  const refreshToken = jwt.sign(
    { userId: user.id },
    REFRESH_SECRET,
    { expiresIn: "7d" } // 7 days, aligned with cookie
  );

  return { accessToken, refreshToken };
}

// --- SIGNUP ---
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ error: "Name, email, and password are required" });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, 'customer') RETURNING id, email, role",
      [name, email, hashed]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    if (err.code === "23505") {
      // PostgreSQL unique violation
      return res
        .status(400)
        .json({ error: "User  with this email already exists" });
    }
    res.status(500).json({ error: "Signup failed - server error" });
  }
});

// --- LOGIN ---
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rowCount === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Cleanup old refresh tokens for this user
    await pool.query("DELETE FROM refresh_tokens WHERE user_id = $1", [
      user.id,
    ]);

    const { accessToken, refreshToken } = createTokens(user);

    // Save new refresh token in DB with expiry
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await pool.query(
      "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
      [user.id, refreshToken, expiresAt]
    );

    // Send refresh token as HttpOnly cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true, // false in development (http://localhost)
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Send access token in JSON
    res.json({ accessToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed - server error" });
  }
});

// --- REFRESH TOKEN ---
app.post("/refresh", async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ error: "No refresh token provided" });
  }

  try {
    // Verify in DB first (including expiry)
    const stored = await pool.query(
      "SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()",
      [refreshToken]
    );
    if (stored.rowCount === 0) {
      return res
        .status(403)
        .json({ error: "Invalid or expired refresh token" });
    }

    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);

    // Fetch user to verify existence and get role
    const userResult = await pool.query(
      "SELECT id, role FROM users WHERE id = $1",
      [decoded.userId]
    );
    if (userResult.rowCount === 0) {
      // Cleanup invalid token
      await pool.query("DELETE FROM refresh_tokens WHERE token = $1", [
        refreshToken,
      ]);
      return res.status(403).json({ error: "User  not found" });
    }
    const user = userResult.rows[0];

    // Delete old refresh token (rotation)
    await pool.query("DELETE FROM refresh_tokens WHERE token = $1", [
      refreshToken,
    ]);

    // Create NEW access and refresh tokens
    const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
      createTokens(user);

    // Save new refresh token in DB with expiry
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await pool.query(
      "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
      [user.id, newRefreshToken, expiresAt]
    );

    // Set new refresh cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    console.error(err);
    if (err.name === "TokenExpiredError" || err.name === "JsonWebTokenError") {
      // Cleanup invalid token
      pool
        .query("DELETE FROM refresh_tokens WHERE token = $1", [refreshToken])
        .catch(console.error);
      return res
        .status(403)
        .json({ error: "Invalid or expired refresh token" });
    }
    res.status(403).json({ error: "Refresh failed - server error" });
  }
});

// --- LOGOUT ---
app.post("/logout", async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  if (refreshToken) {
    try {
      await pool.query("DELETE FROM refresh_tokens WHERE token = $1", [
        refreshToken,
      ]);
    } catch (err) {
      console.error("Logout DB error:", err);
    }
  }

  // Clear cookie
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });

  res.json({ message: "Logged out successfully" });
});

// Middleware to check access token
function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
}

// Example protected endpoints
app.get("/protected", authenticate, (req, res) => {
  res.json({
    message: "✅ You accessed a protected route!",
    user: req.user,
  });
});

app.get("/dashboard", authenticate, (req, res) => {
  res.json({
    message: `Welcome to your dashboard, user ${req.user.userId}!`,
    role: req.user.role,
    tips: [
      "Don’t forget to drink water 💧",
      "Access tokens expire in 15m, refresh wisely 🔄",
      "Hackers are allergic to bcrypt 🧄",
    ],
  });
});

initWebSocket(server);

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
});
