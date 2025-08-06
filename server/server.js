import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import 'dotenv/config';
import { getUserByUsername, createUser, getUserByGoogleId, createUserFromGoogleProfile, getUserByFacebookId, createUserFromFacebook } from './db.js';

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const FE_URL = IS_PROD ? 'https://iwanttohelp.io' : 'http://localhost:5173'
const API_URL = IS_PROD ? 'https://api.iwanttohelp.io' : 'http://localhost:3000'
const DOMAIN = IS_PROD ? '.iwanttohelp.io' : undefined;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret';
const COOKIE_MAX_AGE = 15 * 60 * 1000; // 15 minutes
const JWT_MAX_AGE = '15m';

// CORS config
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) {
            return callback(null, false);
        }

        try {
            const parsedOrigin = new URL(origin).origin;
            const allowedOrigins = [FE_URL];

            if (allowedOrigins.includes(parsedOrigin)) {
                return callback(null, parsedOrigin);
            } else {
                return callback(new Error('Not allowed by CORS'));
            }
        }
        catch (err) {
            return callback(new Error('Invalid origin'));
        }
    },
    credentials: true
}));

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// JWT generator
function generateToken(user) {
    return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: JWT_MAX_AGE });
}

// Auth middleware
function authenticateJWT(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// ======================================================================
// Begin Local Auth
// ======================================================================
passport.use(new LocalStrategy(async (username, password, done) => {
    const user = await getUserByUsername(username);
    if (!user) {
        return done(null, false, { message: 'Invalid username or password' });
    }

    const match = await bcrypt.compare(password, user.hashedPassword);
    return match ?
        done(null, user) :
        done(null, false, { message: 'Invalid username or password' });
}));

// Route: Register
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const existing = await getUserByUsername(username);
    if (existing) {
        return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await createUser(username, hashedPassword);

    const token = generateToken(newUser);
    res.cookie('token', token, {
        httpOnly: true,
        secure: IS_PROD,
        sameSite: IS_PROD ? 'None' : 'Lax',
        domain: DOMAIN,
        maxAge: COOKIE_MAX_AGE
    });

    res.json({ user: { id: newUser.id, username: newUser.username } });
});

app.post('/login',
    passport.authenticate('local', { session: false }),
    (req, res) => {
        const token = generateToken(req.user);
        res.cookie('token', token, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? 'None' : 'Lax',
            domain: DOMAIN,
            maxAge: COOKIE_MAX_AGE
        });

        res.json({ user: { id: req.user.id, username: req.user.username } });
    }
);
// ======================================================================
// End Local Auth
// ======================================================================

// ======================================================================
// Begin Google Auth
// ======================================================================
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${API_URL}/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
    const existingUser = await getUserByGoogleId(profile.id);
    if (existingUser) {
        return done(null, existingUser);
    }

    const newUser = await createUserFromGoogleProfile(profile);
    return done(null, newUser);
}));

// Route: Google OAuth entry point
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'], session: false })
);

// Route: Google OAuth callback
app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/', session: false }),
    (req, res) => {
        const token = generateToken(req.user);

        res.cookie('token', token, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? 'None' : 'Lax',
            domain: DOMAIN,
            maxAge: COOKIE_MAX_AGE
        });

        res.redirect(`${FE_URL}/default.html`);
    }
);
// ======================================================================
// End Google Auth
// ======================================================================

// ======================================================================
// Begin Facebook Auth
// ======================================================================
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: `${API_URL}/auth/facebook/callback`,
    profileFields: ['id', 'emails', 'name'] // get email + name
}, async (accessToken, refreshToken, profile, done) => {
    const facebookId = profile.id;
    const email = profile.emails?.[0]?.value;

    const existingUser = await getUserByFacebookId(facebookId);
    if (existingUser) {
        return done(null, existingUser);
    }

    const newUser = await createUserFromFacebook({ facebookId, email });
    return done(null, newUser);
}));

// Start Facebook login
app.get('/auth/facebook',
    passport.authenticate('facebook', { scope: ['email'], session: false })
);

// Handle callback
app.get('/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/', session: false }),
    (req, res) => {
        const token = generateToken(req.user);

        res.cookie('token', token, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? 'None' : 'Lax',
            domain: DOMAIN,
            maxAge: COOKIE_MAX_AGE
        });
        
        res.redirect(`${FE_URL}/default.html`);
    }
);

// ======================================================================
// End Facebook Auth
// ======================================================================

// Route: Logout
app.post('/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        secure: IS_PROD,
        sameSite: IS_PROD ? 'None' : 'Lax',
        domain: DOMAIN
    });

    res.json({ message: 'Logged out' });
});

// Route: Get current user
app.get('/me', authenticateJWT, (req, res) => {
    res.json({ user: req.user });
});

// Test route
app.get('/', (req, res) => res.send('Auth server is running!'));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
