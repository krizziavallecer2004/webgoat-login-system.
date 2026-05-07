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
    passwordHash: "$2b$10$z3bb1ykGs94VfWp4a9IGQuG59FeaebcVCno6fgyUuvL8rphAqB.by"
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
    const { username, password } = req.body;

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      !isSafeInput(username) ||
      !isSafeInput(password)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid username or password format."
      });
    }

    const user = users.find((u) => u.username === username);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password."
      });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
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
