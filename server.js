const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;
const path = require("path");

const app = express();
const db = new sqlite3.Database("./db.sqlite");

// Middlewares
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret: "supersecretkey",
  resave: false,
  saveUninitialized: false
}));

// Passport Discord
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_CALLBACK_URL,
    scope: ["identify"]
}, (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));

// Création des tables SQLite
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS confessions (id INTEGER PRIMARY KEY, user_id TEXT, text TEXT, FOREIGN KEY(user_id) REFERENCES users(id))");
});

// Middleware pour vérifier la connexion
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/auth/discord");
  next();
}

// Routes
app.get("/", (req, res) => res.render("index"));

app.get("/auth/discord", passport.authenticate("discord"));
app.get("/auth/discord/callback",
    passport.authenticate("discord", { failureRedirect: "/" }),
    (req, res) => {
        db.run("INSERT OR IGNORE INTO users (id, username) VALUES (?, ?)", [req.user.id, req.user.username]);
        req.session.userId = req.user.id;
        res.redirect("/dashboard");
    }
);

app.get("/logout", (req, res) => {
    req.logout(() => {
        req.session.destroy();
        res.redirect("/");
    });
});

app.get("/dashboard", requireLogin, (req, res) => {
  db.get("SELECT username FROM users WHERE id = ?", [req.session.userId], (err, user) => {
    if (err || !user) return res.redirect("/");
    db.all("SELECT * FROM confessions WHERE user_id = ?", [req.session.userId], (err, rows) => {
      res.render("dashboard", { username: user.username, confessions: rows });
    });
  });
});

app.get("/confess/:username", (req, res) => {
  res.render("confess", { username: req.params.username });
});

app.post("/confess/:username", (req, res) => {
  const { text } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [req.params.username], (err, user) => {
    if (!user) return res.send("Utilisateur non trouvé");
    db.run("INSERT INTO confessions (user_id, text) VALUES (?, ?)", [user.id, text], () => {
      res.send("✅ Confession envoyée !");
    });
  });
});

app.post("/delete/:id", requireLogin, (req, res) => {
  db.run("DELETE FROM confessions WHERE id = ? AND user_id = ?", [req.params.id, req.session.userId], function(err) {
    if (err) return res.send("Erreur lors de la suppression");
    res.redirect("/dashboard");
  });
});

// ===================== API pour bot =====================
app.get("/api/confessions/:userid", (req, res) => {
  const token = req.headers["authorization"];
  if (!token || token !== process.env.API_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = req.params.userid;
  db.all("SELECT text FROM confessions WHERE user_id = ?", [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json({ confessions: rows.map(r => r.text) });
  });
});

// Serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));
