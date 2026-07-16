// netlify/functions/auth.js
//
// Verifies passwords on the SERVER, not in browser JS. Handles two kinds:
//   "edit"      - unlocks Edit Mode (can add/remove PDFs, writes to GitHub)
//   "portfolio" - unlocks the private Portfolio page (view-only)
// On success, returns a short-lived signed token proving which kind of
// access was granted, without ever exposing the real passwords to visitors.
//
// Required Netlify environment variables (Site settings → Environment variables):
//   EDIT_PASSWORD        - the password for Edit Mode
//   PORTFOLIO_PASSWORD   - the password for the private Portfolio page
//   SESSION_SECRET       - any long random string, used to sign tokens (make one up,
//                          e.g. run: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

const crypto = require('crypto');

const TOKEN_LIFETIME_MS = 8 * 60 * 60 * 1000; // 8 hours, matches old session length

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const { EDIT_PASSWORD, PORTFOLIO_PASSWORD, SESSION_SECRET } = process.env;
  if (!EDIT_PASSWORD || !PORTFOLIO_PASSWORD || !SESSION_SECRET) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Server not configured. Missing EDIT_PASSWORD, PORTFOLIO_PASSWORD, or SESSION_SECRET.' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Bad request' }) };
  }

  const { password, kind } = body;
  if (kind !== 'edit' && kind !== 'portfolio') {
    return { statusCode: 400, body: JSON.stringify({ error: 'Bad request' }) };
  }

  const expectedPassword = kind === 'edit' ? EDIT_PASSWORD : PORTFOLIO_PASSWORD;

  // Constant-time compare to avoid leaking timing information about the password.
  const a = Buffer.from(String(password || ''));
  const b = Buffer.from(expectedPassword);
  const same = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!same) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Incorrect password.' }) };
  }

  const expires = Date.now() + TOKEN_LIFETIME_MS;
  const payload = `${kind}:${expires}`;
  const signature = sign(payload, SESSION_SECRET);
  const token = Buffer.from(`${payload}.${signature}`).toString('base64');

  return {
    statusCode: 200,
    body: JSON.stringify({ token, expires })
  };
};
