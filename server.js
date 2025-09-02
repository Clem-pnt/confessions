const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy");
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
    clientID: "1364998645329690745",          // Remplace par ton Client ID Discord
    clientSecret: "C8qVcOcBTitlZX_igaqbZjGooHfYpRbX",  // Remplace par ton Client Secret Discord
    callbackURL: "https://ton-app.onrender.com/auth/discord/callback",
    scope: ["identify"]
}, (accessToken, refreshToken, profile, done) => {
    // profile contient les infos Discord
    return done(null, profile);
}));

// Création de la table users si tu veux stocker Discord IDs
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS confessions (id INTEGER PRIMARY KEY, user_id TEXT, text TEXT, FOREIGN KEY(user_id) REFERENCES users(id))");
});

// Middleware pour vérifier la connexion
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/auth/discord");
  next();
}

// ================= ROUTES ==================

// Page d'accueil
app.get("/", (req, res) => res.render("index"));

// ----------------- Discord OAuth -----------------
app.get("/auth/discord", passport.authenticate("discord"));
app.get("/auth/discord/callback",
    passport.authenticate("discord", { failureRedirect: "/" }),
    (req, res) => {
        // Stocke l'utilisateur dans SQLite si nouveau
        db.run("INSERT OR IGNORE INTO users (id, username) VALUES (?, ?)", [req.user.id, req.user.username]);
        req.session.userId = req.user.id;
        res.redirect("/dashboard");
    }
);

// Déconnexion
app.get("/logout", (req, res) => {
    req.logout(() => {
        req.session.destroy();
        res.redirect("/");
    });
});

// ----------------- Dashboard -----------------
app.get("/dashboard", requireLogin, (req, res) => {
  db.get("SELECT username FROM users WHERE id = ?", [req.session.userId], (err, user) => {
    if (err || !user) return res.redirect("/");
    db.all("SELECT * FROM confessions WHERE user_id = ?", [req.session.userId], (err, rows) => {
      res.render("dashboard", { username: user.username, confessions: rows });
    });
  });
});

// ----------------- Confessions publiques -----------------
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

// ----------------- Suppression d'une confession -----------------
app.post("/delete/:id", requireLogin, (req, res) => {
  db.run("DELETE FROM confessions WHERE id = ? AND user_id = ?", [req.params.id, req.session.userId], function(err) {
    if (err) return res.send("Erreur lors de la suppression");
    res.redirect("/dashboard");
  });
});

// ================= Lancer le serveur ==================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));
