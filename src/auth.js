
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const router = express.Router();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const NODE_ENV = process.env.NODE_ENV || "development";

function createTokens(user) {
  const accessToken = jwt.sign(
    { userId: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "15m" }
  );

  const refreshToken = jwt.sign(
    { userId: user.id },
    REFRESH_SECRET,
    { expiresIn: "7d" }
  );

  return { accessToken, refreshToken };
}

// --- SIGNUP ---
router.post("/signup", async (req, res) => {
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
router.post("/login", async (req, res) => {
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
router.post("/refresh", async (req, res) => {
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
router.post("/logout", async (req, res) => {
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
router.get("/protected", authenticate, (req, res) => {
  res.json({
    message: "✅ You accessed a protected route!",
    user: req.user,
  });
});

router.get("/dashboard", authenticate, (req, res) => {
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

module.exports = router;

