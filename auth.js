const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const { z } = require('zod')
const pool = require('./db')
const dotenv = require('dotenv')
const { randomUUID } = require('crypto')

dotenv.config()
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
if (!ACCESS_SECRET || !REFRESH_SECRET) {
    throw new Error('JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be set.')
}

// Time To Live (TTL)
const ACCESS_TTL = process.env.JWT_ACCESS_TTL || '15m';
const REFRESH_TTL = process.env.JWT_REFRESH_TTL || '7d';
const ACCESS_MS = 15 * 60 * 1000;
const REFRESH_MS = 7 * 24 * 60 * 60 * 1000;

// ---------- cookie settings (multi-domain clients) ----------
// Clients live on different domains than the API, so the cookies are
// third-party cookies: SameSite=None + Secure is required in production.
// No `domain` is set on purpose: a cookie can only belong to the API's own host.
const isProd = process.env.NODE_ENV === 'production';
const sameSite = process.env.COOKIE_SAMESITE || (isProd ? 'none' : 'lax');
const cookieBase = {
    httpOnly: true, // JS in the frontend cannot read the cookie
    secure: isProd || sameSite === 'none', // SameSite=None requires Secure
    sameSite,
    path: '/',
};
// CHIPS (Partitioned cookies): helps against third-party cookie restrictions in
// Chrome. Needs the `cookie` package >= 1.0; older versions ignore it harmlessly.
if (sameSite === 'none') cookieBase.partitioned = true;

const REFRESH_PATH = '/api/auth'; // refresh cookie is only sent to the auth endpoints

const router = express.Router();

// ---------- helper functions ----------
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });

const bearer = (req) => {
    const h = req.headers.authorization || '';
    return h.startsWith('Bearer ') ? h.slice(7) : null;
};

const parse = (schema, body, res) => {
    const r = schema.safeParse(body);
    if (r.success) return r.data;
    const errors = {};
    for (const i of r.error.issues) (errors[i.path.join('.') || '_form'] ||= []).push(i.message);
    res.status(400).json({ success: false, errors });
    return null;
};

// Attributes must match the ones used when setting the cookie, or the browser ignores the clear
const clearCookies = (res) => {
    res.clearCookie('access_token', cookieBase);
    res.clearCookie('refresh_token', { ...cookieBase, path: REFRESH_PATH });
};

// Create new Access and Refresh tokens and send them to the user
const respondWithTokens = (req, res, user, sid, refreshJti) => {
    const accessToken = jwt.sign({ role: user.role, sid }, ACCESS_SECRET, {
        subject: String(user.id), expiresIn: ACCESS_TTL, jwtid: randomUUID(),
    });
    const refreshToken = jwt.sign({ sid }, REFRESH_SECRET, {
        subject: String(user.id), expiresIn: REFRESH_TTL, jwtid: refreshJti,
    });

    const body = { success: true, data: publicUser(user) };

    if (req.get('X-Token-Mode') === 'bearer') {
        body.access_token = accessToken;   // non-browser clients (mobile/Postman) and Safari fallback
        body.refresh_token = refreshToken;
    } else {
        res.cookie('access_token', accessToken, { ...cookieBase, maxAge: ACCESS_MS });
        res.cookie('refresh_token', refreshToken, { ...cookieBase, path: REFRESH_PATH, maxAge: REFRESH_MS });
    }
    res.json(body);
};

const rotate = async (req, res, user, sid) => {
    const jti = randomUUID();
    await pool.query(
        `UPDATE sessions SET prev_jti = refresh_jti, refresh_jti = $1, expires_at = $2 WHERE id = $3`,
        [jti, new Date(Date.now() + REFRESH_MS), sid]
    );
    respondWithTokens(req, res, user, sid, jti);
};

const sidFrom = (req) => {
    const candidates = [
        [bearer(req) || req.cookies?.access_token, ACCESS_SECRET],
        [req.cookies?.refresh_token || req.body?.refresh_token, REFRESH_SECRET],
    ];
    for (const [token, secret] of candidates) {
        if (!token) continue;
        try { return jwt.verify(token, secret, { ignoreExpiration: true }).sid; } catch { /* next */ }
    }
    return null;
};

// ---------- middleware ----------
// CSRF protection: a custom header forces a CORS preflight, and the preflight
// only succeeds for origins in CLIENT_ORIGIN (see server.js).
const csrfGuard = (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    if (req.get('X-Requested-With') || req.get('X-Token-Mode') || req.headers.authorization) return next();
    res.status(403).json({ success: false, message: 'Missing required header' });
};

const requireAuth = async (req, res, next) => {
    const token = bearer(req) || req.cookies?.access_token;
    if (!token) return res.status(401).json({ success: false, message: 'Not authenticated' });
    try {
        const p = jwt.verify(token, ACCESS_SECRET);
        const s = await pool.query('SELECT 1 FROM sessions WHERE id = $1 AND expires_at > NOW()', [p.sid]);
        if (!s.rowCount) return res.status(401).json({ success: false, message: 'Session ended' });
        req.user = { id: Number(p.sub), role: p.role, sid: p.sid };
        next();
    } catch (err) {
        if (err instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ success: false, message: 'Invalid or expired token' });
        }
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

const requireRole = (...roles) => (req, res, next) =>
    roles.includes(req.user?.role)
        ? next()
        : res.status(403).json({ success: false, message: 'Forbidden: insufficient permissions' });

// ---------- schemas ----------
const email = z.string().trim().toLowerCase().email({ message: 'Invalid email address.' });
const registerSchema = z.object({
    name: z.string().trim().min(2, { message: 'Name must be at least 2 characters long.' }),
    email,
    password: z.string()
        .min(8, { message: 'Password must be at least 8 characters long.' })
        .max(72, { message: 'Password must be at most 72 characters long.' }),
});
const loginSchema = z.object({
    email,
    password: z.string().min(1, { message: 'Password is required.' }),
});

// ---------- routes ----------
router.post('/register', async (req, res) => {
    const data = parse(registerSchema, req.body, res);
    if (!data) return;
    try {
        const hash = await bcrypt.hash(data.password, 12);
        const r = await pool.query(
            `INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3)
       RETURNING id, name, email, role`,
            [data.name, data.email, hash]
        );
        res.status(201).json({ success: true, data: r.rows[0] });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ success: false, errors: { email: ['Email is already registered.'] } });
        }
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

router.post('/login', async (req, res) => {
    const data = parse(loginSchema, req.body, res);
    if (!data) return;
    try {
        const r = await pool.query('SELECT * FROM users WHERE email = $1', [data.email]);
        const user = r.rows[0];
        const ok = user && (await bcrypt.compare(data.password, user.password_hash));
        if (!ok) {
            return res.status(401).json({ success: false, errors: { _form: ['Invalid email or password.'] } });
        }
        const sid = randomUUID();
        const jti = randomUUID();
        await pool.query(
            'INSERT INTO sessions (id, user_id, refresh_jti, expires_at) VALUES ($1, $2, $3, $4)',
            [sid, user.id, jti, new Date(Date.now() + REFRESH_MS)]
        );
        respondWithTokens(req, res, user, sid, jti);
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Get the current user's data
router.post('/me', requireAuth, async (req, res) => {
    try {
        const r = await pool.query('SELECT id, name, email, role FROM users WHERE id = $1', [req.user.id]);
        if (!r.rowCount) return res.status(401).json({ success: false, message: 'User not found' });
        await rotate(req, res, r.rows[0], req.user.sid);
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Fallback when the access token has expired (e.g. after 15 minutes)
router.post('/refresh', async (req, res) => {
    const token = req.cookies?.refresh_token || req.body?.refresh_token;
    if (!token) return res.status(401).json({ success: false, message: 'No refresh token' });
    try {
        const p = jwt.verify(token, REFRESH_SECRET);
        const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND expires_at > NOW()', [p.sid]);
        const session = s.rows[0];
        if (!session) return res.status(401).json({ success: false, message: 'Session ended' });

        if (session.refresh_jti !== p.jti && session.prev_jti !== p.jti) {
            // An old refresh token was reused -> possibly stolen, kill the session
            await pool.query('DELETE FROM sessions WHERE id = $1', [p.sid]);
            clearCookies(res);
            return res.status(401).json({ success: false, message: 'Refresh token reuse detected' });
        }
        const u = await pool.query('SELECT id, name, email, role FROM users WHERE id = $1', [session.user_id]);
        if (!u.rowCount) return res.status(401).json({ success: false, message: 'User not found' });
        await rotate(req, res, u.rows[0], session.id);
    } catch (err) {
        if (err instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
        }
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

router.post('/logout', async (req, res) => {
    const sid = sidFrom(req);
    if (sid) await pool.query('DELETE FROM sessions WHERE id = $1', [sid]).catch(console.error);
    clearCookies(res);
    res.json({ success: true });
});

module.exports = { router, requireAuth, requireRole, csrfGuard };