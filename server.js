require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const admin = require("./firebase");
const auth = require("./middleware/auth");

const db = admin.firestore();
const app = express();

/* 🔥 REQUIRED FOR RENDER SECURE COOKIES */
app.set("trust proxy", 1);

/* ================= CORS ================= */
/* Allow your Vercel frontend + localhost */

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://leecoste.vercel.app",
    ],
    credentials: true,
  })
);

/* ================= MIDDLEWARE ================= */

app.use(express.json());
app.use(cookieParser());

/* ================= JWT HELPERS ================= */

const generateAccessToken = (user) => {
  return jwt.sign(user, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign(user, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
};

/* ================= AUTH ================= */

// LOGIN (used after Firebase login)
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const snapshot = await db
      .collection("users")
      .where("email", "==", email)
      .get();

    if (snapshot.empty) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const user = snapshot.docs[0].data();

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const payload = { email };

    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    /* 🔥 CROSS-SITE COOKIE SETTINGS */
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ accessToken });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ msg: "Login failed" });
  }
});

/* ================= REFRESH ================= */

app.post("/api/refresh", (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    const accessToken = generateAccessToken({
      email: user.email,
    });

    res.json({ accessToken });
  });
});

/* ================= LOGOUT ================= */

app.post("/api/logout", (req, res) => {
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });

  res.json({ msg: "Logged out" });
});

/* ================= STATS ================= */

app.get("/api/stats", auth, async (req, res) => {
  try {
    let total = 0;
    let verified = 0;
    let nextPageToken;

    do {
      const result = await admin.auth().listUsers(1000, nextPageToken);

      result.users.forEach((user) => {
        total++;
        if (user.emailVerified) verified++;
      });

      nextPageToken = result.pageToken;
    } while (nextPageToken);

    res.json({
      totalUsers: total,
      verifiedUsers: verified,
      unverifiedUsers: total - verified,
      systemStatus: "Active",
      security: "Protected",
    });

  } catch (err) {
    console.error("Stats error:", err);
    res.status(500).json({ msg: "Failed to fetch stats" });
  }
});

/* ================= DASHBOARD ================= */

app.get("/api/dashboard", auth, (req, res) => {
  res.json({
    msg: "Welcome to dashboard",
    user: req.user.email,
  });
});

/* ================= USER STATS ================= */

app.get("/api/user-stats", auth, async (req, res) => {
  try {
    const { range } = req.query;

    let users = [];
    let nextPageToken;

    do {
      const result = await admin.auth().listUsers(1000, nextPageToken);

      result.users.forEach((user) => {
        users.push({
          createdAt: new Date(user.metadata.creationTime),
          emailVerified: user.emailVerified,
        });
      });

      nextPageToken = result.pageToken;
    } while (nextPageToken);

    // Simple monthly example (you can expand)
    const data = [];

    const now = new Date();

    for (let i = 11; i >= 0; i--) {
      const d = new Date();
      d.setMonth(now.getMonth() - i);

      const month = d.toLocaleString("default", { month: "short" });

      const count = users.filter(
        (u) =>
          u.createdAt.getMonth() === d.getMonth() &&
          u.createdAt.getFullYear() === d.getFullYear()
      ).length;

      data.push({
        name: month,
        users: count,
      });
    }

    res.json(data);

  } catch (err) {
    console.error("User stats error:", err);
    res.status(500).json({ msg: "Failed to load stats" });
  }
});

/* ================= SERVER ================= */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
