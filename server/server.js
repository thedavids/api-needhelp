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
import rateLimit from 'express-rate-limit';
import 'dotenv/config';
import validator from 'validator';
import { Resend } from 'resend';
import { v4 as uuidv4 } from 'uuid';
import {
    getUserByEmail, getUserById, createUser, updateUserPassword, getUserByGoogleId,
    setUserIsVerified, createUserFromGoogleProfile, getUserByFacebookId, createUserFromFacebook
} from './db.js';
import { injectAccessTokens, clearAccessTokens } from './utils/tokens.js';
import { sendEmailVerification, sendPasswordResetEmail } from './services/emails.js';

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const FE_URL = IS_PROD ? 'https://iwanttohelp.io' : 'http://localhost:5173'
const API_URL = IS_PROD ? 'https://api.iwanttohelp.io' : 'http://localhost:3000'
const DOMAIN = IS_PROD ? '.iwanttohelp.io' : undefined;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret';

const EMAIL_SECRET = process.env.EMAIL_SECRET_ACTIVATION_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'dev_jwt_refresh_secret';

const resend = new Resend(process.env.EMAIL_RESEND_API_KEY);

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

app.post('/refresh-token', async (req, res) => {
    const token = req.cookies.refreshToken;
    if (!token) {
        return res.status(401).json({ error: 'No refresh token provided' });
    }

    try {
        const payload = jwt.verify(token, REFRESH_TOKEN_SECRET);
        const user = await getUserById(payload.id);
        if (!user) {
            return res.status(401).json({ error: 'Invalid refresh token' });
        }

        injectAccessTokens(user, res);

        res.json({ message: 'Tokens refreshed' });
    } 
    catch (err) {
        console.error('Refresh token error:', err);
        res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
});

// ======================================================================
// Begin Local Auth
// ======================================================================
passport.use(new LocalStrategy(
    {
        usernameField: 'email',
        passwordField: 'password'
    },
    async (email, password, done) => {
        const user = await getUserByEmail(email);
        if (!user) {
            return done(null, false, { message: 'Invalid email or password' });
        }

        if (!user.isVerified) {
            return done(null, false, { message: 'Email not verified' });
        }

        const match = await bcrypt.compare(password, user.password);
        return match ? done(null, user) : done(null, false, { message: 'Invalid email or password' });
    }
));

function generateVerificationToken(userId) {
    return jwt.sign({ id: userId }, EMAIL_SECRET, { expiresIn: '1d' });
}

const signUpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: { error: 'Too many register attempts from this IP. Please try again later.' }
});

// Route: Register
app.post('/register', signUpLimiter, async (req, res) => {
    const { email, displayName, password } = req.body;

    if (!email || !displayName || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    const existing = await getUserByEmail(email);
    if (existing) {
        return res.status(400).json({ error: 'User already exists' });
    }

    const id = uuidv4();

    const token = generateVerificationToken(id);
    await sendEmailVerification({ email, token });

    const hashedPassword = await bcrypt.hash(password, 10);
    await createUser({ id, email, displayName, hashedPassword });

    res.status(201).json({ message: 'Verification email sent' });
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 30, // Limit each IP to 30 requests per windowMs
    message: { error: 'Too many login attempts from this IP. Please try again later.' }
});

app.post('/login', loginLimiter, (req, res, next) => {
    passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err) {
            return next(err);
        }

        if (!user) {
            return res.status(401).json({ error: info?.message || 'Authentication failed' });
        }

        injectAccessTokens(user, res);

        res.json({
            user: {
                id: user.id,
                email: user.email,
                displayName: user.displayName
            }
        });
    })(req, res, next);
});

app.post('/verify', async (req, res) => {
    const { token } = req.body;
    try {
        const payload = jwt.verify(token, EMAIL_SECRET);
        await setUserIsVerified(payload.id);
        res.status(201).json({ message: 'Email verified!' });
    }
    catch (err) {
        console.error('Verification failed:', err);
        throw err;
    }
});

const forgotPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // Limit each IP to 5 requests per windowMs
    message: { error: 'Too many forgot passwords attempts from this IP. Please try again later.' }
});

app.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
    const { email } = req.body;

    if (!email || !validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid or missing email' });
    }

    const user = await getUserByEmail(email);
    if (!user) {
        return res.status(200).json({ message: 'If the email exists, a reset link will be sent' });
    }

    const token = jwt.sign({ id: user.id }, EMAIL_SECRET, { expiresIn: '1h' });

    await sendPasswordResetEmail({ email, token });

    return res.status(201).json({ message: 'Password reset link sent' });
});

app.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;

    if (!token || !password) {
        return res.status(400).json({ error: 'Missing token or password' });
    }

    try {
        const payload = jwt.verify(token, EMAIL_SECRET);
        const user = await getUserById(payload.id);

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        const hashed = await bcrypt.hash(password, 10);
        await updateUserPassword(user.id, hashed);

        res.status(200).json({ message: 'Password updated successfully' });
    }
    catch (err) {
        console.error('Reset failed:', err);
        return res.status(400).json({ error: 'Invalid or expired token' });
    }
});
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

    const id = uuidv4();
    const newUser = await createUserFromGoogleProfile(id, profile);
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
        injectAccessTokens(req.user, res);
        res.redirect(`${FE_URL}`);
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

    const id = uuidv4();
    const newUser = await createUserFromFacebook({ id, facebookId, email });
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
        injectAccessTokens(req.user, res);
        res.redirect(`${FE_URL}`);
    }
);

// ======================================================================
// End Facebook Auth
// ======================================================================

// Route: Logout
app.post('/logout', (req, res) => {
    clearAccessTokens(res);
    res.json({ message: 'Logged out' });
});

// Route: Get current user
app.get('/me', authenticateJWT, (req, res) => {
    res.json({ user: req.user });
});

// Test route
app.get('/', (req, res) => res.send('Auth server is running!'));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
