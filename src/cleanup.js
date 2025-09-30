const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});
const JWT_SECRET = process.env.JWT_SECRET
const REFRESH_SECRET = process.env.REFRESH_SECRET

// for refresh token stored from database
function cleanUpDatabase() {
  setInterval(async () => {
    try {
      const result = await pool.query("SELECT token FROM refresh_tokens");
      for (const row of result.rows) {
        try {
          jwt.verify(row.token, REFRESH_SECRET);
          console.log(`Refresh token is still valid: ${row.token}`);
          // Token is valid, do nothing
        } catch (err) {
          // Token is expired or invalid, delete it
          await pool.query("DELETE FROM refresh_tokens WHERE token = $1", [
            row.token,
          ]);
          console.log(`Deleted expired refresh token: ${row.token}`);
        }
      }
    } catch (err) {
      console.error("Error during refresh token cleanup:", err);
    }
  }, 60 * 60 * 1000); // Every hour
}

module.exports = { cleanUpDatabase };
