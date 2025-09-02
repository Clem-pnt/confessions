const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const session = require("express-session");
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

// Création des tables si elles n'existent pas
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS confessions (id INTEGER PRIMARY KEY, user_id INTEGER, text TEXT, FOREIGN KEY(user_id) REFERENCES users(id))");
});

// Middleware pour vérifier la connexion
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}

// Routes principales
app.get("/", (req, res) => res.render("index"));

// ----------------- INSCRIPTION -----------------
app.get("/register", (req, res) => res.render("register"));
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], function(err) {
    if (err) return res.send("Erreur: " + err.message);
    res.redirect("/login");
  });
});

// ----------------- CONNEXION -----------------
app.get("/login", (req, res) => res.render("login"));
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.send("Identifiants invalides");
    }
    req.session.userId = user.id;
    res.redirect("/dashboard");
  });
});

// ----------------- DECONNEXION -----------------
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// ----------------- DASHBOARD -----------------
app.get("/dashboard", requireLogin, (req, res) => {
  db.get("SELECT username FROM users WHERE id = ?", [req.session.userId], (err, user) => {
    if (err || !user) return res.redirect("/login");

    db.all("SELECT * FROM confessions WHERE user_id = ?", [req.session.userId], (err, rows) => {
      res.render("dashboard", { username: user.username, confessions: rows });
    });
  });
});

// ----------------- CONFESSIONS PUBLIQUES -----------------
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

// ----------------- SUPPRESSION D'UNE CONFESSION -----------------
app.post("/delete/:id", requireLogin, (req, res) => {
  db.run("DELETE FROM confessions WHERE id = ? AND user_id = ?", [req.params.id, req.session.userId], function(err) {
    if (err) return res.send("Erreur lors de la suppression");
    res.redirect("/dashboard");
  });
});


// Lancer le serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));

