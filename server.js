const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const flash = require('connect-flash');

const app = express();

// Config EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
    secret: 'secret_key', // ⚠️ change cette clé en valeur sécurisée
    resave: false,
    saveUninitialized: false
}));

app.use(flash());

// Middleware global : rendre "user" + messages dispo dans toutes les vues
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    next();
});

// Connexion MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // ton utilisateur MySQL
    password: '', // ton mot de passe MySQL
    database: 'auth_db'
});

db.connect(err => {
    if (err) throw err;
    console.log('✅ Connecté à MySQL');
});

// ===================== ROUTES =====================

// Page accueil
app.get('/', (req, res) => {
    res.render('index', { title: "Bienvenue" });
});

// Page inscription
app.get('/register', (req, res) => {
    res.render('register', { title: "Inscription" });
});

// Page connexion
app.get('/login', (req, res) => {
    res.render('login', { title: "Connexion" });
});

// Page profil protégée
app.get('/profile', (req, res) => {
    if (!req.session.user) {
        req.flash('error_msg', 'Veuillez vous connecter pour accéder à votre profil.');
        return res.redirect('/login');
    }
    res.render('profile', { title: "Profil" });
});

// Déconnexion
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// ===================== API POST =====================

// Inscription
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            req.flash('error_msg', "Nom d'utilisateur déjà pris.");
            return res.redirect('/register');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.query('INSERT INTO users (username, password) VALUES (?, ?)', 
        [username, hashedPassword], (err) => {
            if (err) throw err;
            req.flash('success_msg', "Inscription réussie, vous pouvez vous connecter.");
            res.redirect('/login');
        });
    });
});

// Connexion
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) throw err;
        if (results.length === 0) {
            req.flash('error_msg', "Utilisateur introuvable.");
            return res.redirect('/login');
        }

        const isMatch = await bcrypt.compare(password, results[0].password);
        if (!isMatch) {
            req.flash('error_msg', "Mot de passe incorrect.");
            return res.redirect('/login');
        }

        req.session.user = results[0];
        res.redirect('/profile');
    });
});

// ===================== LANCEMENT =====================
app.listen(3000, () => {
    console.log("🚀 Serveur sur http://localhost:3000");
});
