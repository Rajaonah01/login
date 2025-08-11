require('dotenv').config(); // Charge les variables d'environnement depuis .env

const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const flash = require('connect-flash');

const app = express();

// Configuration EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware pour fichiers statiques & corps de requêtes
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session express
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret_key_change_me', // Change la clé secrète dans .env !
    resave: false,
    saveUninitialized: false
}));

// Flash messages (pour afficher erreurs/succès)
app.use(flash());

// Middleware global : variables accessibles dans toutes les vues
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    next();
});

// Connexion MySQL sécurisée via variables d’environnement
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'auth_db'
});

db.connect(err => {
    if (err) {
        console.error('❌ Erreur de connexion à MySQL:', err);
        process.exit(1); // Arrête le serveur si pas de connexion
    }
    console.log('✅ Connecté à MySQL');
});

// ========== ROUTES ==========

// Accueil
app.get('/', (req, res) => {
    res.render('index', { title: "Bienvenue" });
});

// Inscription
app.get('/register', (req, res) => {
    res.render('register', { title: "Inscription" });
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        req.flash('error_msg', 'Veuillez fournir un nom d’utilisateur et un mot de passe.');
        return res.redirect('/register');
    }

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) {
            req.flash('error_msg', 'Erreur serveur, réessayez plus tard.');
            return res.redirect('/register');
        }

        if (results.length > 0) {
            req.flash('error_msg', "Nom d'utilisateur déjà pris.");
            return res.redirect('/register');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.query('INSERT INTO users (username, password) VALUES (?, ?)', 
        [username, hashedPassword], (err) => {
            if (err) {
                req.flash('error_msg', 'Erreur lors de l’inscription.');
                return res.redirect('/register');
            }
            req.flash('success_msg', "Inscription réussie, vous pouvez vous connecter.");
            res.redirect('/login');
        });
    });
});

// Connexion
app.get('/login', (req, res) => {
    res.render('login', { title: "Connexion" });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        req.flash('error_msg', 'Veuillez fournir un nom d’utilisateur et un mot de passe.');
        return res.redirect('/login');
    }

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) {
            req.flash('error_msg', 'Erreur serveur, réessayez plus tard.');
            return res.redirect('/login');
        }
        if (results.length === 0) {
            req.flash('error_msg', "Utilisateur introuvable.");
            return res.redirect('/login');
        }

        const isMatch = await bcrypt.compare(password, results[0].password);
        if (!isMatch) {
            req.flash('error_msg', "Mot de passe incorrect.");
            return res.redirect('/login');
        }

        req.session.user = { id: results[0].id, username: results[0].username }; // Stocke seulement l'info utile
        res.redirect('/profile');
    });
});

// Profil protégé
app.get('/profile', (req, res) => {
    if (!req.session.user) {
        req.flash('error_msg', 'Veuillez vous connecter pour accéder à votre profil.');
        return res.redirect('/login');
    }
    res.render('profile', { title: "Profil", user: req.session.user });
});

// Déconnexion
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// Lancement serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Serveur lancé sur http://localhost:${PORT}`);
});
