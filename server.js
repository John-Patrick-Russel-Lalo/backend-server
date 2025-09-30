const express = require("express");
const http = require("http");
const cors = require("cors");
require("dotenv").config();

const { initWebSocket } = require("./src/websocket");
const { cleanUpDatabase } = require("./src/cleanup");
const authRouter = require("./src/auth");

const app = express();
app.use(express.json());
const server = http.createServer(app);

// CORS Config
const allowedOrigins = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:8080",
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

app.use(authRouter);

initWebSocket(server);
cleanUpDatabase();

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
