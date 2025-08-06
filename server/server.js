import express from 'express';
import session from 'express-session';
import cors from 'cors';
import bodyParser from 'body-parser';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// Dummy users
const USERS = [{ id: 1, username: 'test', password: 'pass123' }];

// CORS config
app.use(cors({
    origin: IS_PROD ? 'https://iwanttohelp.io' : 'http://localhost:5173',
    credentials: true
}));

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session config
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: IS_PROD,                      // true = HTTPS only (production)
        sameSite: IS_PROD ? 'none' : 'lax',   // allow cross-site only in prod
        domain: IS_PROD ? '.ineedhelp.io' : undefined
    }
}));

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy((username, password, done) => {
    const user = USERS.find(u => u.username === username && u.password === password);
    return user ? done(null, user) : done(null, false);
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    const user = USERS.find(u => u.id === id);
    done(null, user || false);
});

// Routes
app.get('/', (req, res) => res.send('API is up!'));

app.post('/login', passport.authenticate('local'), (req, res) => {
    res.json({ message: 'Logged in', user: req.user });
});

app.get('/me', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ user: req.user });
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});

app.get('/logout', (req, res) => {
    req.logout(() => {
        res.json({ message: 'Logged out' });
    });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
