// services/email.js
import { Resend } from 'resend';

const resend = new Resend(process.env.EMAIL_RESEND_API_KEY);

const FE_URL = process.env.NODE_ENV === 'production'
    ? 'https://iwanttohelp.io'
    : 'http://localhost:5173';

const EMAIL_FROM = process.env.EMAIL_FROM;

/**
 * Send verification email after user registers.
 */
export async function sendEmailVerification({ email, token }) {
    const link = `${FE_URL}/verify?token=${token}`;

    try {
        const result = await resend.emails.send({
            from: EMAIL_FROM,
            to: email,
            subject: 'Verify your email address',
            html: `
        <h2>Welcome to IWantToHelp</h2>
        <p>Click the link below to verify your email:</p>
        <a href="${link}">${link}</a>
        <p>This link expires in 24 hours.</p>
      `
        });

        if (result.error) {
            console.error('Resend error:', result.error);
            throw new Error(result.error.error || 'Failed to send verification email');
        }

        return result;
    }
    catch (err) {
        console.error('Verification email failed:', err);
        throw err;
    }
}

/**
 * Send password reset email.
 */
export async function sendPasswordResetEmail({ email, token }) {
    const link = `${FE_URL}/reset-password?token=${token}`;

    try {
        const result = await resend.emails.send({
            from: EMAIL_FROM,
            to: email,
            subject: 'Reset your password',
            html: `
        <h2>Password Reset</h2>
        <p>Click the link below to set a new password:</p>
        <a href="${link}">${link}</a>
        <p>This link expires in 1 hour.</p>
      `
        });

        if (result.error) {
            console.error('Resend error:', result.error);
            throw new Error(result.error.error || 'Failed to send password reset email');
        }

        return result;
    }
    catch (err) {
        console.error('Reset email failed:', err);
        throw err;
    }
}
