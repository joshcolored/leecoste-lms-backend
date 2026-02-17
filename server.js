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

app.use(
  cors({
    origin: [
      "http://localhost:5173", // local
      "https://leecoste.vercel.app", // CHANGE THIS
    ],
    credentials: true,
  })
);

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

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const snapshot = await db
      .collection("users")
      .where("email", "==", email)
      .get();

    if (!snapshot.empty) {
      return res.status(400).json({ msg: "User exists" });
    }

    const hash = await bcrypt.hash(password, 10);

    await db.collection("users").doc(email).set({
      email,
      password: hash,
      role: "client",
      status: "active",
      createdAt: new Date(),
    });

    res.json({ msg: "Registered successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Register failed" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const snapshot = await db
      .collection("users")
      .where("email", "==", email)
      .get();

    if (snapshot.empty)
      return res.status(400).json({ msg: "Invalid credentials" });

    const user = snapshot.docs[0].data();

    const match = await bcrypt.compare(password, user.password);

    if (!match)
      return res.status(400).json({ msg: "Invalid credentials" });

    const payload = { email };

    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,        // REQUIRED on Render (HTTPS)
      sameSite: "none",    // REQUIRED for cross-site frontend
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ accessToken });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Login failed" });
  }
});

// REFRESH
app.post("/api/refresh", (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    const accessToken = generateAccessToken({
      email: user.email,
    });

    res.json({ accessToken });
  });
});

// LOGOUT
app.post("/api/logout", (req, res) => {
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });

  res.json({ msg: "Logged out" });
});

/* ================= STATS ================= */

app.get("/api/stats", async (req, res) => {
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
    console.error(err);
    res.status(500).json({ msg: "Failed to fetch stats" });
  }
});

/* ================= USER STATS (CHART) ================= */

app.get("/api/user-stats", auth, async (req, res) => {
  try {
    const { range, from, to, type } = req.query;

    let users = [];
    let nextPageToken;

    // Load users from Firebase Auth
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

    let filteredUsers = [...users];

    // Date range filter
    if (from && to) {
      const fromDate = new Date(from);
      const toDate = new Date(to);
      toDate.setHours(23, 59, 59, 999);

      filteredUsers = filteredUsers.filter(
        (u) => u.createdAt >= fromDate && u.createdAt <= toDate
      );
    }

    // Type filter
    if (type === "verified") {
      filteredUsers = filteredUsers.filter((u) => u.emailVerified);
    }

    if (type === "unverified") {
      filteredUsers = filteredUsers.filter((u) => !u.emailVerified);
    }

    const now = new Date();
    let data = [];

    /* ===== 12 MONTHS ===== */
    if (range === "12m") {
      for (let i = 11; i >= 0; i--) {
        const d = new Date();
        d.setMonth(now.getMonth() - i);

        const month = d.toLocaleString("default", { month: "short" });

        const count = filteredUsers.filter(
          (u) =>
            u.createdAt.getMonth() === d.getMonth() &&
            u.createdAt.getFullYear() === d.getFullYear()
        ).length;

        data.push({ name: month, users: count });
      }
    }

    /* ===== 30 DAYS ===== */
    if (range === "30d") {
      for (let i = 29; i >= 0; i--) {
        const d = new Date();
        d.setDate(now.getDate() - i);

        const label = d.toLocaleDateString("en-US", {
          month: "short",
          day: "numeric",
        });

        const count = filteredUsers.filter(
          (u) => u.createdAt.toDateString() === d.toDateString()
        ).length;

        data.push({ name: label, users: count });
      }
    }

    /* ===== 7 DAYS ===== */
    if (range === "7d") {
      for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(now.getDate() - i);

        const label = d.toLocaleDateString("en-US", {
          weekday: "short",
        });

        const count = filteredUsers.filter(
          (u) => u.createdAt.toDateString() === d.toDateString()
        ).length;

        data.push({ name: label, users: count });
      }
    }

    /* ===== 24 HOURS ===== */
    if (range === "24h") {
      for (let i = 23; i >= 0; i--) {
        const d = new Date();
        d.setHours(now.getHours() - i);

        const label = d.getHours() + ":00";

        const count = filteredUsers.filter(
          (u) =>
            u.createdAt.getHours() === d.getHours() &&
            u.createdAt.toDateString() === d.toDateString()
        ).length;

        data.push({ name: label, users: count });
      }
    }

    res.json(data);

  } catch (err) {
    console.error("User stats error:", err);
    res.status(500).json({ msg: "Failed to load stats" });
  }
});


/* ================= DASHBOARD ================= */

app.get("/api/dashboard", auth, (req, res) => {
  res.json({
    msg: "Welcome to dashboard",
    user: req.user.email,
  });
});

/* ================= DELETE USER ================= */

app.delete("/api/users/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const docRef = db.collection("users").doc(id);
    const snap = await docRef.get();

    if (!snap.exists) {
      return res.status(404).json({ msg: "User not found" });
    }

    const data = snap.data();

    try {
      const user = await admin.auth().getUserByEmail(data.email);
      await admin.auth().deleteUser(user.uid);
    } catch {
      console.log("Auth delete skipped");
    }

    await docRef.delete();

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Delete failed" });
  }
});

/* ================= SERVER ================= */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
