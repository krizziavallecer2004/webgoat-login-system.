const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  session({
    secret: "replace-this-with-a-strong-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

// Demo user record with hashed password ("Student123!")
const users = [
  {
    username: "student1",
    passwordHash: "$2b$10$dbt22jUoICWjNzjyv6Mw6O3juljiU664xb1.ktFBnf46tQI9rcx.W"
  }
];

function isSafeInput(value) {
  return /^[a-zA-Z0-9_!@#$%^&*.\-]{3,50}$/.test(value);
}

app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.post("/login", async (req, res) => {
  try {
    let { username, password } = req.body;

    // Sanitize and trim inputs to prevent common login failures
    username = (username || "").trim();
    password = (password || "").trim();

    if (
      !username ||
      typeof password !== "string" ||
      !isSafeInput(username) ||
      !isSafeInput(password)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid username or password format."
      });
    }

    // Case-insensitive lookup for better user experience
    const user = users.find((u) => u.username.toLowerCase() === username.toLowerCase());

    if (!user) {
      console.log(`Login attempt failed: User "${username}" not found.`);
      return res.status(401).json({
        success: false,
        message: "Invalid username or password."
      });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      console.log(`Login attempt failed: Incorrect password for "${username}".`);
      return res.status(401).json({
        success: false,
        message: "Invalid username or password."
      });
    }

    req.session.user = { username: user.username };
    return res.json({ success: true, redirectTo: "/dashboard" });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Login failed. Please try again."
    });
  }
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }
  next();
}

app.get("/dashboard", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/whoami", requireAuth, (req, res) => {
  res.json({ username: req.session.user.username });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
