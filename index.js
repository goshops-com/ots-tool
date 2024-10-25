const express = require('express');
const { createClient } = require('@libsql/client');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());

// Serve static files from public directory
app.use(express.static('public'));

const client = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN
});

// Initialize database
async function initDb() {
  await client.execute(`
    CREATE TABLE IF NOT EXISTS secrets (
      id TEXT PRIMARY KEY,
      encrypted_content TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      expires_at INTEGER NOT NULL,
      is_viewed BOOLEAN DEFAULT FALSE
    )
  `);
}
initDb();

// Create secret
app.post('/api/secrets', async (req, res) => {
  const { content } = req.body;
  const id = crypto.randomBytes(16).toString('hex');
  const secretKey = crypto.randomBytes(32).toString('hex');
  
  // Encrypt
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(secretKey, 'hex'), iv);
  const encrypted = Buffer.concat([cipher.update(content, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  const expiresAt = Math.floor(Date.now() / 1000) + (24 * 60 * 60); // 24 hours
  
  await client.execute({
    sql: 'INSERT INTO secrets (id, encrypted_content, expires_at) VALUES (?, ?, ?)',
    args: [id, JSON.stringify({
      encrypted: encrypted.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    }), expiresAt]
  });

  res.json({ id, key: secretKey });
});

// Get secret
app.get('/api/secrets/:id', async (req, res) => {
  const { id } = req.params;
  const { key } = req.query;

  const result = await client.execute({
    sql: 'SELECT * FROM secrets WHERE id = ?',
    args: [id]
  });

  if (!result.rows.length) {
    return res.status(404).json({ error: 'Secret not found' });
  }

  const secret = result.rows[0];
  const { encrypted, iv, authTag } = JSON.parse(secret.encrypted_content);

  // Decrypt
  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      Buffer.from(key, 'hex'),
      Buffer.from(iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted, 'hex')),
      decipher.final()
    ]);

    // Delete after viewing
    await client.execute({
      sql: 'DELETE FROM secrets WHERE id = ?',
      args: [id]
    });

    res.json({ content: decrypted.toString() });
  } catch (error) {
    res.status(400).json({ error: 'Invalid key' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

