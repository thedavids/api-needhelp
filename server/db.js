import pool from './dbConnection.js';
import validator from 'validator';

const NAME_MAX_LENGTH = 254;

export async function getUserByEmail(email) {
    const result = await pool.query('SELECT * FROM "User" WHERE email = $1', [email]);
    return result.rows[0];
}

export async function getUserById(id) {
    const result = await pool.query('SELECT * FROM "User" WHERE id = $1', [id]);
    return result.rows[0];
}

export async function createUser({ id, email, displayName, hashedPassword }) {
    const cleanName = validator.escape(displayName.trim().slice(0, NAME_MAX_LENGTH));

    const result = await pool.query(
        `INSERT INTO "User" (id, email, "displayName", password, "isVerified")
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, email, "displayName"`,
        [id, email, cleanName, hashedPassword, false]
    );

    return result.rows[0];
}

export async function updateUserPassword(userId, hashedPassword) {
    await pool.query(
        `UPDATE "User" SET password = $1 WHERE id = $2`,
        [hashedPassword, userId]
    );
}

export async function setUserIsVerified(id) {
    const res = await pool.query(`UPDATE "User" SET "isVerified" = true WHERE id = $1`, [id]);
    return res.rows[0];
}

export async function getUserByGoogleId(googleId) {
    const res = await pool.query('SELECT * FROM "User" WHERE "googleId" = $1', [googleId]);
    return res.rows[0] || null;
}

export async function createUserFromGoogleProfile(id, profile) {
    const displayName = profile.displayName;
    const cleanName = validator.escape(displayName.trim().slice(0, NAME_MAX_LENGTH));
    const email = profile.emails?.[0]?.value || null;
    const googleId = profile.id;

    const res = await pool.query(
        'INSERT INTO "User" (id, "displayName", email, "googleId", "isVerified") VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [id, cleanName, email, googleId, true]
    );
    return res.rows[0];
}

export async function getUserByFacebookId(facebookId) {
    const res = await pool.query('SELECT * FROM "User" WHERE "facebookId" = $1', [facebookId]);
    return res.rows[0] || null;
}

export async function createUserFromFacebook({ id, facebookId, email }) {
    const displayName = `fb_user_${facebookId.slice(-6)}`;
    const cleanName = validator.escape(displayName.trim().slice(0, NAME_MAX_LENGTH));

    const res = await pool.query(
        'INSERT INTO "User" (id, "displayName", email, "facebookId", "isVerified") VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [id, cleanName, email || null, facebookId, true]
    );
    return res.rows[0];
}
