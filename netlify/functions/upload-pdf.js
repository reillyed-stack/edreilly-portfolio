// netlify/functions/upload-pdf.js
//
// Receives a base64-encoded PDF from the browser (sent from Edit Mode),
// checks the caller has a valid session token from auth.js, then commits
// the file straight into your GitHub repo's /documents folder using the
// GitHub Contents API. Netlify's GitHub integration then auto-redeploys
// your site with the new file included.
//
// Required Netlify environment variables (Site settings → Environment variables):
//   SESSION_SECRET   - same value used in auth.js
//   GITHUB_TOKEN      - a GitHub fine-grained Personal Access Token, scoped to
//                        ONLY this one repository, with "Contents: Read and write"
//                        permission and nothing else. Never a classic all-repo token.
//   GITHUB_OWNER      - your GitHub username or org, e.g. "edreilly"
//   GITHUB_REPO       - the repo name, e.g. "edreilly-portfolio"
//   GITHUB_BRANCH     - the branch Netlify deploys from, usually "main"

const crypto = require('crypto');

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function verifyToken(token, secret) {
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const [payload, signature] = decoded.split('.');
    const expected = sign(payload, secret);
    const sigOk = signature.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
    if (!sigOk) return false;
    const [kind, expires] = payload.split(':');
    if (kind !== 'edit') return false; // only Edit Mode sessions may write to GitHub
    return Date.now() < Number(expires);
  } catch (e) {
    return false;
  }
}

// Only allow simple, safe filenames inside documents/ — blocks path traversal
// (e.g. "../../.env") and anything that isn't a .pdf.
const SAFE_FILENAME = /^[A-Za-z0-9._-]+\.pdf$/i;

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST' && event.httpMethod !== 'DELETE') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const { SESSION_SECRET, GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO, GITHUB_BRANCH } = process.env;
  if (!SESSION_SECRET || !GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Server not configured. Check environment variables.' }) };
  }
  const branch = GITHUB_BRANCH || 'main';

  const authHeader = event.headers.authorization || event.headers.Authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  if (!token || !verifyToken(token, SESSION_SECRET)) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Not authorized. Please unlock edit mode again.' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Bad request' }) };
  }

  const { filename, contentBase64 } = body;
  if (!filename || !SAFE_FILENAME.test(filename)) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid filename.' }) };
  }

  const path = `documents/${filename}`;
  const apiUrl = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${encodeURIComponent(path).replace(/%2F/g, '/')}`;
  const ghHeaders = {
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': 'edreilly-portfolio-upload-function'
  };

  if (event.httpMethod === 'DELETE') {
    try {
      const existing = await fetch(`${apiUrl}?ref=${encodeURIComponent(branch)}`, { headers: ghHeaders });
      if (existing.status === 404) {
        return { statusCode: 200, body: JSON.stringify({ ok: true, note: 'File was already gone.' }) };
      }
      if (!existing.ok) {
        const errText = await existing.text();
        return { statusCode: 502, body: JSON.stringify({ error: 'GitHub lookup failed', details: errText }) };
      }
      const existingJson = await existing.json();

      const delRes = await fetch(apiUrl, {
        method: 'DELETE',
        headers: { ...ghHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: `Remove ${filename} via site edit mode`,
          sha: existingJson.sha,
          branch
        })
      });
      if (!delRes.ok) {
        const errText = await delRes.text();
        return { statusCode: 502, body: JSON.stringify({ error: 'GitHub delete failed', details: errText }) };
      }
      return { statusCode: 200, body: JSON.stringify({ ok: true }) };
    } catch (e) {
      return { statusCode: 500, body: JSON.stringify({ error: 'Unexpected server error', details: String(e) }) };
    }
  }

  if (!contentBase64) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing file content' }) };
  }
  // Rough size guard: GitHub's Contents API tops out around 100MB (25MB is the
  // more reliable practical ceiling without extra steps). Base64 is ~33% larger
  // than the raw file, so this checks the encoded size.
  const approxBytes = Math.ceil(contentBase64.length * 0.75);
  if (approxBytes > 25 * 1024 * 1024) {
    return { statusCode: 400, body: JSON.stringify({ error: 'File is larger than 25MB. Compress it before uploading.' }) };
  }

  try {
    // Check whether the file already exists, so we can update it instead of
    // creating a duplicate (GitHub requires the existing file's "sha" to update it).
    let sha;
    const existing = await fetch(`${apiUrl}?ref=${encodeURIComponent(branch)}`, { headers: ghHeaders });
    if (existing.status === 200) {
      const existingJson = await existing.json();
      sha = existingJson.sha;
    } else if (existing.status !== 404) {
      const errText = await existing.text();
      return { statusCode: 502, body: JSON.stringify({ error: 'GitHub lookup failed', details: errText }) };
    }

    const putRes = await fetch(apiUrl, {
      method: 'PUT',
      headers: { ...ghHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: sha ? `Update ${filename} via site edit mode` : `Add ${filename} via site edit mode`,
        content: contentBase64,
        branch,
        ...(sha ? { sha } : {})
      })
    });

    if (!putRes.ok) {
      const errText = await putRes.text();
      return { statusCode: 502, body: JSON.stringify({ error: 'GitHub upload failed', details: errText }) };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ ok: true, path: `documents/${filename}` })
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Unexpected server error', details: String(e) }) };
  }
};
