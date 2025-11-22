require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const fs = require('fs');
const multer = require('multer');

// Global diagnostic hook to capture top-level crashes
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Promise Rejection:', reason);
});

const app = express();
app.use(cors());
app.use(express.json());

// Trust Heroku's proxy so we can read X-Forwarded-* headers
app.enable('trust proxy');

// Enforce canonical host and HTTPS with HSTS
const CANONICAL_HOST = String(process.env.CANONICAL_HOST || '').trim().toLowerCase();
app.use((req, res, next) => {
  const rawHost = req.headers.host || '';
  const host = rawHost.split(':')[0].toLowerCase();
  const xfProto = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
  const isHttps = req.secure === true || xfProto.includes('https');

  // 1) Force HTTPS on same host to avoid loops
  if (!isHttps) {
    return res.redirect(301, `https://${host || CANONICAL_HOST || 'localhost'}${req.originalUrl}`);
  }

  // 2) Normalize host to canonical once on HTTPS
  if (CANONICAL_HOST && host && host !== CANONICAL_HOST) {
    return res.redirect(301, `https://${CANONICAL_HOST}${req.originalUrl}`);
  }

  // 3) HSTS after we are on HTTPS and canonical host
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  next();
});

// Use a sane default in development so login doesn't 500 if JWT_SECRET is unset
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-123';

// --- DB connection (fallback to local dev DB if env not set)
const DATABASE_URL = process.env.DATABASE_URL || 'postgres://localhost:5432/vmapp';
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: false } : false,
});

let ensuredDutyDate = false;
async function ensureDutyDateColumn() {
  if (ensuredDutyDate) return;
  try {
    await pool.query('ALTER TABLE IF EXISTS time_tracking ADD COLUMN IF NOT EXISTS duty_date DATE NULL');
    ensuredDutyDate = true;
  } catch (err) {
    console.error('Failed ensuring time_tracking.duty_date column:', err?.message || err);
  }
}

let ensuredTimeTrackingConstraints = false;
async function ensureTimeTrackingConstraints() {
  if (ensuredTimeTrackingConstraints) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`
      CREATE TABLE IF NOT EXISTS volunteer_lookup (
        id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    await client.query(`
      INSERT INTO volunteer_lookup (id)
      SELECT id FROM users WHERE LOWER(role) = 'volunteer'
      ON CONFLICT (id) DO NOTHING
    `);
    await client.query(`
      ALTER TABLE time_tracking
      ALTER COLUMN volunteer_id TYPE INTEGER USING volunteer_id::INTEGER
    `);
    await client.query('ALTER TABLE time_tracking DROP CONSTRAINT IF EXISTS time_tracking_volunteer_id_fkey');
    await client.query(`
      ALTER TABLE time_tracking
      ADD CONSTRAINT time_tracking_volunteer_id_fkey
      FOREIGN KEY (volunteer_id) REFERENCES volunteer_lookup(id) ON DELETE CASCADE
    `);
    await client.query('ALTER TABLE time_tracking DROP CONSTRAINT IF EXISTS time_tracking_duty_id_fkey');
    await client.query(`
      ALTER TABLE time_tracking
      ADD CONSTRAINT time_tracking_duty_id_fkey
      FOREIGN KEY (duty_id) REFERENCES duties(id) ON DELETE SET NULL
    `);
    await client.query('COMMIT');
    ensuredTimeTrackingConstraints = true;
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Failed ensuring time_tracking constraints:', err?.message || err);
  } finally {
    client.release();
  }
}

// Ensure optional event link on duties exists
(async () => {
  try {
    await pool.query(
      'ALTER TABLE IF EXISTS duties ADD COLUMN IF NOT EXISTS event_id INTEGER REFERENCES events(id) ON DELETE SET NULL'
    );
    // Add soft-archive support for duties
    await pool.query(
      'ALTER TABLE IF EXISTS duties ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP NULL'
    );
    // Soft-archive support for events
    await pool.query(
      'ALTER TABLE IF EXISTS events ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP NULL'
    );
    // Event date range support
    await pool.query(
      'ALTER TABLE IF EXISTS events ADD COLUMN IF NOT EXISTS start_date DATE NULL'
    );
    await pool.query(
      'ALTER TABLE IF EXISTS events ADD COLUMN IF NOT EXISTS end_date DATE NULL'
    );
    // Event time of day support
    await pool.query(
      'ALTER TABLE IF EXISTS events ADD COLUMN IF NOT EXISTS start_time TIME NULL'
    );
    await pool.query(
      'ALTER TABLE IF EXISTS events ADD COLUMN IF NOT EXISTS end_time TIME NULL'
    );
    // Time tracking duty_date ensure
    await pool.query(
      'ALTER TABLE IF EXISTS time_tracking ADD COLUMN IF NOT EXISTS duty_date DATE NULL'
    );
    // Archive orphan duties that have no event
    try {
      await pool.query("UPDATE duties SET archived_at = COALESCE(archived_at, NOW()) WHERE event_id IS NULL");
    } catch (_) {}
    // RSVP table
    await pool.query(
      `CREATE TABLE IF NOT EXISTS event_attendees (
         id SERIAL PRIMARY KEY,
         event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
         user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
         created_at TIMESTAMP NOT NULL DEFAULT NOW(),
         UNIQUE (event_id, user_id)
       )`
    );
    // Fallback profile storage when users table lacks optional columns
    await pool.query(
      `CREATE TABLE IF NOT EXISTS user_profile (
         user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
         name TEXT NULL,
         phone TEXT NULL,
         address TEXT NULL,
         updated_at TIMESTAMP NOT NULL DEFAULT NOW()
       )`
    );
    // Ensure a permanent users.name column exists
    await pool.query(
      `ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS name TEXT`
    );
    await pool.query(
      `ALTER TABLE IF EXISTS groups ADD COLUMN IF NOT EXISTS time_zone TEXT DEFAULT 'UTC'`
    );
  } catch (e) {
    console.error('Schema ensure failed (duties.event_id):', e?.message || e);
  }
})();

// --- Middleware
function authRequired(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ message: 'Missing token' });
  try {
    const token = auth.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (!['admin','superadmin'].includes(req.user.role)) {
    return res.status(403).json({ message: 'Admins only' });
  }
  next();
}

function superadminOnly(req, res, next) {
  if (req.user.role !== 'superadmin') {
    return res.status(403).json({ message: 'Superadmins only' });
  }
  next();
}

// --- Helpers
function isAdmin(user) {
  return user && (user.role === 'admin' || user.role === 'superadmin');
}

// --- Auth Routes
app.post('/register', authRequired, adminOnly, async (req, res) => {
  try {
    const { name, email, phone, address, password, role, group_id } = req.body || {};
    if (!email || !password || !role) return res.status(400).json({ message: 'Missing required fields' });
    // Enforce: Admins cannot create superadmins
    if (req.user.role === 'admin' && String(role).toLowerCase() === 'superadmin') {
      return res.status(403).json({ message: 'Admins cannot create superadmins' });
    }

    const hash = await bcrypt.hash(password, 10);

    // Detect available columns on the current database schema (works across envs)
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='users'");
    const has = new Set(colsRes.rows.map(r => r.column_name));

    const fields = [];
    const values = [];
    const params = [];
    let idx = 1;

    // Optional fields if present in schema
    if (has.has('name') && name !== undefined) { fields.push('name'); params.push(`$${idx++}`); values.push(name); }
    if (has.has('phone') && phone !== undefined) { fields.push('phone'); params.push(`$${idx++}`); values.push(phone); }
    if (has.has('address') && address !== undefined) { fields.push('address'); params.push(`$${idx++}`); values.push(address); }

    // Required fields
    fields.push('email'); params.push(`$${idx++}`); values.push(email);
    fields.push('password'); params.push(`$${idx++}`); values.push(hash);
    fields.push('role'); params.push(`$${idx++}`); values.push(role);

    // group_id if schema supports it
    if (has.has('group_id')) { fields.push('group_id'); params.push(`$${idx++}`); values.push(group_id ?? null); }

    const sql = `INSERT INTO users (${fields.join(',')}) VALUES (${params.join(',')}) RETURNING id`;
    const result = await pool.query(sql, values);

    // Also upsert optional profile fields so Name always persists even if users table lacks it
    try {
      await pool.query(
        `INSERT INTO user_profile (user_id,name,phone,address,updated_at)
         VALUES ($1,$2,$3,$4,NOW())
         ON CONFLICT (user_id) DO UPDATE SET
           name=COALESCE(EXCLUDED.name,user_profile.name),
           phone=COALESCE(EXCLUDED.phone,user_profile.phone),
           address=COALESCE(EXCLUDED.address,user_profile.address),
           updated_at=NOW()`,
        [result.rows[0].id, (name ?? null), (phone ?? null), (address ?? null)]
      );
    } catch (_) { /* profile table may not exist; ignore */ }

    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Public signup: create a volunteer under a selected group (or none)
app.post('/signup', async (req, res) => {
  try {
    let { name, email, password, phone, address, group_id, group_name } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required' });
    const exists = await pool.query('SELECT 1 FROM users WHERE email=$1', [email]);
    if (exists.rowCount > 0) return res.status(400).json({ message: 'Email already registered' });
    const hash = await bcrypt.hash(password, 10);

    // If no group_id provided, try to resolve from group_name (case-insensitive) against DB
    if ((group_id == null || Number.isNaN(Number(group_id))) && typeof group_name === 'string' && group_name.trim()) {
      try {
        const gn = group_name.trim();
        let found = await pool.query('SELECT id FROM groups WHERE LOWER(name) = LOWER($1) LIMIT 1', [gn]);
        if (found.rowCount === 0) {
          // Fallback: try a LIKE match
          found = await pool.query('SELECT id FROM groups WHERE LOWER(name) LIKE LOWER($1) ORDER BY id LIMIT 1', [gn]);
        }
        if (found.rowCount > 0) {
          group_id = found.rows[0].id;
        }
      } catch (_) { /* ignore and continue with null */ }
    }

    // Detect available columns on the current users table
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='users'");
    const has = new Set(colsRes.rows.map(r => r.column_name));

    const fields = [];
    const params = [];
    const values = [];
    let idx = 1;

    // Optional columns, only if present in schema
    if (has.has('name') && name !== undefined) { fields.push('name'); params.push(`$${idx++}`); values.push(name); }
    if (has.has('phone') && phone !== undefined) { fields.push('phone'); params.push(`$${idx++}`); values.push(phone); }
    if (has.has('address') && address !== undefined) { fields.push('address'); params.push(`$${idx++}`); values.push(address); }

    // Required columns
    fields.push('email'); params.push(`$${idx++}`); values.push(email);
    fields.push('password'); params.push(`$${idx++}`); values.push(hash);
    fields.push('role'); params.push(`$${idx++}`); values.push('volunteer');

    // Group if supported
    if (has.has('group_id')) { fields.push('group_id'); params.push(`$${idx++}`); values.push(group_id ?? null); }

    const insertSql = `INSERT INTO users (${fields.join(',')}) VALUES (${params.join(',')}) RETURNING id, role${has.has('group_id') ? ', group_id' : ''}`;
    const result = await pool.query(insertSql, values);
    const newUserId = result.rows[0].id;

    // Persist missing profile fields into user_profile table when users table lacks them
    const profile = {
      name: (!has.has('name') && name !== undefined) ? name : undefined,
      phone: (!has.has('phone') && phone !== undefined) ? phone : undefined,
      address: (!has.has('address') && address !== undefined) ? address : undefined,
    };
    if (profile.name !== undefined || profile.phone !== undefined || profile.address !== undefined) {
      await pool.query(
        `INSERT INTO user_profile (user_id,name,phone,address,updated_at)
         VALUES ($1,$2,$3,$4,NOW())
         ON CONFLICT (user_id) DO UPDATE SET
           name=COALESCE(EXCLUDED.name,user_profile.name),
           phone=COALESCE(EXCLUDED.phone,user_profile.phone),
           address=COALESCE(EXCLUDED.address,user_profile.address),
           updated_at=NOW()`,
        [newUserId, profile.name ?? null, profile.phone ?? null, profile.address ?? null]
      );
    }

    const user = { id: newUserId, role: 'volunteer', group_id: (has.has('group_id') ? result.rows[0].group_id : null) };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, ...user });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Public groups listing for signup dropdown
app.get('/public/groups', async (req, res) => {
  try {
    // Return all organizations for signup typeahead (no status filter)
    const rows = await pool.query("SELECT id, name FROM groups ORDER BY LOWER(name) ASC");
    res.json(rows.rows);
  } catch (err) {
    res.status(500).json({ message: 'Failed to load groups' });
  }
});

// Alias for public org list to match alternate frontend expectations
app.get('/api/groups', async (req, res) => {
  try {
    const rows = await pool.query("SELECT id, name FROM groups ORDER BY LOWER(name) ASC");
    res.json(rows.rows);
  } catch (err) {
    res.status(500).json({ message: 'Failed to load groups' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (result.rowCount === 0) return res.status(400).json({ message: 'Invalid credentials' });
    const user = result.rows[0];
    let match = false;
    try {
      match = await bcrypt.compare(password, user.password);
    } catch (_) {
      match = false;
    }
    if (!match) {
      // Fallback: verify using Postgres crypt() against stored hash (supports pgcrypto seeds)
      const verify = await pool.query('SELECT 1 FROM users WHERE email=$1 AND password = crypt($2, password)', [email, password]);
      if (verify.rowCount === 0) return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user.id, role: user.role, group_id: user.group_id },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token, role: user.role, group_id: user.group_id, id: user.id });
  } catch (err) {
    res.status(500).json({ message: err?.message || 'Error logging in' });
  }
});

// --- Account & Config
app.get('/me', authRequired, async (req, res) => {
  try {
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='users'");
    const has = new Set(colsRes.rows.map(r => r.column_name));
    const selectCols = ['u.id','u.email','u.role','u.group_id'];
    const joins = [];
    if (has.has('name')) selectCols.push('u.name'); else { joins.push('LEFT JOIN user_profile p ON p.user_id = u.id'); selectCols.push('p.name'); }
    if (has.has('phone')) selectCols.push('u.phone'); else if (!joins.find(j=>j.includes('user_profile'))) { joins.push('LEFT JOIN user_profile p ON p.user_id = u.id'); selectCols.push('p.phone'); } else { selectCols.push('p.phone'); }
    if (has.has('address')) selectCols.push('u.address'); else if (!joins.find(j=>j.includes('user_profile'))) { joins.push('LEFT JOIN user_profile p ON p.user_id = u.id'); selectCols.push('p.address'); } else { selectCols.push('p.address'); }
    const sql = `SELECT ${selectCols.join(', ')} FROM users u ${joins.join(' ')} WHERE u.id=$1`;
    const result = await pool.query(sql, [req.user.id]);
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    const row = result.rows[0];
    res.json({ id: row.id, email: row.email, role: row.role, group_id: row.group_id, name: row.name || null, phone: row.phone || null, address: row.address || null });
  } catch (err) {
    res.status(500).json({ message: 'Error loading profile' });
  }
});

app.post('/account', authRequired, async (req, res) => {
  try {
    const t = req.body || {};
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='users'");
    const has = new Set(colsRes.rows.map(r => r.column_name));
    const setClauses = [];
    const params = [];
    let idx = 1;
    if (has.has('name') && t.name !== undefined) { setClauses.push(`name=COALESCE($${idx++},name)`); params.push(t.name); }
    if (t.email !== undefined) { setClauses.push(`email=COALESCE($${idx++},email)`); params.push(t.email); }
    if (has.has('phone') && t.phone !== undefined) { setClauses.push(`phone=COALESCE($${idx++},phone)`); params.push(t.phone); }
    if (has.has('address') && t.address !== undefined) { setClauses.push(`address=COALESCE($${idx++},address)`); params.push(t.address); }
    let updated = false;
    if (setClauses.length > 0) {
      const sql = `UPDATE users SET ${setClauses.join(', ')} WHERE id=$${idx} RETURNING id`;
      const result = await pool.query(sql, [...params, req.user.id]);
      updated = result.rowCount > 0;
    }
    // Persist to user_profile for any fields missing on users table
    const p = {
      name: (!has.has('name') && t.name !== undefined) ? t.name : undefined,
      phone: (!has.has('phone') && t.phone !== undefined) ? t.phone : undefined,
      address: (!has.has('address') && t.address !== undefined) ? t.address : undefined,
    };
    if (p.name !== undefined || p.phone !== undefined || p.address !== undefined) {
      await pool.query(
        `INSERT INTO user_profile (user_id,name,phone,address,updated_at)
         VALUES ($1,$2,$3,$4,NOW())
         ON CONFLICT (user_id) DO UPDATE SET
           name=COALESCE(EXCLUDED.name,user_profile.name),
           phone=COALESCE(EXCLUDED.phone,user_profile.phone),
           address=COALESCE(EXCLUDED.address,user_profile.address),
           updated_at=NOW()`,
        [req.user.id, p.name ?? null, p.phone ?? null, p.address ?? null]
      );
      updated = true;
    }
    res.json({ id: req.user.id, updated });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.get('/config', (req, res) => {
  res.json({
    appName: process.env.APP_NAME || 'Volunteer Time Tracking',
    logoUrl: process.env.LOGO_URL || 'https://i.postimg.cc/Ght5qLQw/TTTC-Logo-Redesign2.jpg',
    primaryColor: process.env.THEME_PRIMARY || '#000000',
    textColor: process.env.THEME_TEXT || '#ffffff',
    accents: [
      process.env.ACCENT1 || '#35b1fb',
      process.env.ACCENT2 || '#0289db',
      process.env.ACCENT3 || '#054a74',
      process.env.ACCENT4 || '#00433a',
      process.env.ACCENT5 || '#ffffff'
    ],
    bgImageUrl: process.env.BG_IMAGE_URL || null,
  });
});

// --- Users listing (admin/superadmin)
app.get('/users', authRequired, async (req, res) => {
  try {
    const roleFilter = req.query.role ? String(req.query.role) : null;
    const groupFilter = req.query.group_id ? Number(req.query.group_id) : null;
    const where = [];
    const params = [];
    let idx = 1;
    if (roleFilter) { where.push(`u.role = $${idx++}`); params.push(roleFilter); }
    if (req.user.role === 'superadmin') {
      if (Number.isFinite(groupFilter)) { where.push(`u.group_id = $${idx++}`); params.push(groupFilter); }
    } else if (req.user.role === 'admin') {
      where.push(`u.group_id = $${idx++}`); params.push(req.user.group_id);
    } else {
      return res.status(403).json({ message: 'Admins only' });
    }
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='users'");
    const has = new Set(colsRes.rows.map(r => r.column_name));
    const selectCols = ['u.id','u.email','u.role','u.group_id'];
    const joins = [];
    if (has.has('name')) selectCols.push('u.name'); else { joins.push('LEFT JOIN user_profile p ON p.user_id = u.id'); selectCols.push('p.name AS name'); }
    if (has.has('phone')) selectCols.push('u.phone'); else if (!joins.find(j=>j.includes('user_profile'))) { joins.push('LEFT JOIN user_profile p ON p.user_id = u.id'); selectCols.push('p.phone AS phone'); } else { selectCols.push('p.phone AS phone'); }
    if (has.has('address')) selectCols.push('u.address'); else if (!joins.find(j=>j.includes('user_profile'))) { joins.push('LEFT JOIN user_profile p ON p.user_id = u.id'); selectCols.push('p.address AS address'); } else { selectCols.push('p.address AS address'); }
    const sql = `SELECT ${selectCols.join(', ')} FROM users u ${joins.join(' ')}${where.length ? ' WHERE ' + where.join(' AND ') : ''} ORDER BY LOWER(COALESCE(${has.has('name') ? 'u.name' : 'p.name'}, u.email)) ASC`;
    const rows = await pool.query(sql, params);
    res.json(rows.rows);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Simple volunteers list endpoint (scoped)
app.get('/volunteers', authRequired, async (req, res) => {
  try {
    const groupFilter = req.query.group_id ? Number(req.query.group_id) : null;
    const where = ['u.role = $1'];
    const params = ['volunteer'];
    let idx = 2;
    if (req.user.role === 'superadmin') {
      if (Number.isFinite(groupFilter)) { where.push(`u.group_id = $${idx++}`); params.push(groupFilter); }
    } else if (req.user.role === 'admin') {
      where.push(`u.group_id = $${idx++}`); params.push(req.user.group_id);
    } else {
      return res.status(403).json({ message: 'Admins only' });
    }
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='users'");
    const has = new Set(colsRes.rows.map(r => r.column_name));
    const selectCols = ['u.id','u.email','u.group_id'];
    const joins = [];
    if (has.has('name')) selectCols.push('u.name'); else { joins.push('LEFT JOIN user_profile p ON p.user_id = u.id'); selectCols.push('p.name AS name'); }
    const sql = `SELECT ${selectCols.join(', ')} FROM users u ${joins.join(' ')} WHERE ${where.join(' AND ')} ORDER BY LOWER(COALESCE(${has.has('name') ? 'u.name' : 'p.name'}, u.email)) ASC`;
    const rows = await pool.query(sql, params);
    res.json(rows.rows);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});
// Edit user (admin/superadmin)
app.patch('/users/:id', authRequired, async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    if (!Number.isFinite(targetId)) return res.status(400).json({ message: 'Invalid id' });
    const t = req.body || {};
    // Load target for checks
    const existing = await pool.query('SELECT id, role, group_id FROM users WHERE id=$1', [targetId]);
    if (existing.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    const target = existing.rows[0];
    if (!isAdmin(req.user)) return res.status(403).json({ message: 'Admins only' });
    if (req.user.role === 'admin') {
      // Admin can only edit within their group and cannot edit superadmins
      if (target.group_id !== req.user.group_id) return res.status(403).json({ message: 'Forbidden' });
      if (target.role === 'superadmin') return res.status(403).json({ message: 'Forbidden' });
      if (t.role && String(t.role).toLowerCase() === 'superadmin') return res.status(403).json({ message: 'Cannot assign superadmin' });
      // Admin cannot move user to another group
      if (t.group_id && Number(t.group_id) !== req.user.group_id) return res.status(403).json({ message: 'Cannot change group' });
    }
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='users'");
    const has = new Set(colsRes.rows.map(r => r.column_name));
    const setClauses = [];
    const params = [];
    let idx = 1;
    if (has.has('name') && t.name !== undefined) { setClauses.push(`name=COALESCE($${idx++},name)`); params.push(t.name); }
    if (t.email !== undefined) { setClauses.push(`email=COALESCE($${idx++},email)`); params.push(t.email); }
    if (has.has('phone') && t.phone !== undefined) { setClauses.push(`phone=COALESCE($${idx++},phone)`); params.push(t.phone); }
    if (has.has('address') && t.address !== undefined) { setClauses.push(`address=COALESCE($${idx++},address)`); params.push(t.address); }
  // Optional password reset/change
  if (t.password !== undefined) {
    if (typeof t.password !== 'string' || t.password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }
    if (has.has('password')) {
      const hash = await bcrypt.hash(String(t.password), 10);
      setClauses.push(`password=$${idx++}`);
      params.push(hash);
    }
  }
    if (t.role !== undefined) {
      const roleVal = String(t.role).toLowerCase();
      if (roleVal === 'superadmin' && req.user.role !== 'superadmin') return res.status(403).json({ message: 'Cannot assign superadmin' });
      setClauses.push(`role=$${idx++}`); params.push(roleVal);
    }
    if (t.group_id !== undefined) {
      const gid = t.group_id == null ? null : Number(t.group_id);
      if (req.user.role === 'admin' && gid !== req.user.group_id) return res.status(403).json({ message: 'Cannot change group' });
      if (has.has('group_id')) { setClauses.push(`group_id=$${idx++}`); params.push(gid); }
    }
    let updated = false;
    if (setClauses.length > 0) {
      const sql = `UPDATE users SET ${setClauses.join(', ')} WHERE id=$${idx} RETURNING id`;
      const result = await pool.query(sql, [...params, targetId]);
      updated = result.rowCount > 0;
    }
    // Persist to user_profile for any missing columns
    const p = {
      name: (!has.has('name') && t.name !== undefined) ? t.name : undefined,
      phone: (!has.has('phone') && t.phone !== undefined) ? t.phone : undefined,
      address: (!has.has('address') && t.address !== undefined) ? t.address : undefined,
    };
    if (p.name !== undefined || p.phone !== undefined || p.address !== undefined) {
      await pool.query(
        `INSERT INTO user_profile (user_id,name,phone,address,updated_at)
         VALUES ($1,$2,$3,$4,NOW())
         ON CONFLICT (user_id) DO UPDATE SET
           name=COALESCE(EXCLUDED.name,user_profile.name),
           phone=COALESCE(EXCLUDED.phone,user_profile.phone),
           address=COALESCE(EXCLUDED.address,user_profile.address),
           updated_at=NOW()`,
        [targetId, p.name ?? null, p.phone ?? null, p.address ?? null]
      );
      updated = true;
    }
    res.json({ id: targetId, updated });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Delete user (superadmin only)
app.delete('/users/:id', authRequired, async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    if (!Number.isFinite(targetId)) return res.status(400).json({ message: 'Invalid id' });
    if (targetId === req.user.id) return res.status(400).json({ message: 'Cannot delete your own account' });
    if (!isAdmin(req.user)) return res.status(403).json({ message: 'Admins only' });
    // Load target role and group
    const existing = await pool.query('SELECT id, role, group_id FROM users WHERE id=$1', [targetId]);
    if (existing.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    const target = existing.rows[0];
    // Admins can only delete volunteers in their org; superadmins can delete anyone except themselves handled above
    if (req.user.role === 'admin') {
      if (target.role !== 'volunteer' || target.group_id !== req.user.group_id) {
        return res.status(403).json({ message: 'Admins can only delete volunteers in their organization' });
      }
    }
    const result = await pool.query('DELETE FROM users WHERE id=$1 RETURNING id', [targetId]);
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    try { await pool.query('DELETE FROM user_profile WHERE user_id=$1', [targetId]); } catch (_) {}
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Delete duty (admin/superadmin)
app.delete('/duties/:id', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    let result;
    if (req.user.role === 'superadmin') {
      result = await pool.query('DELETE FROM duties WHERE id=$1 RETURNING id', [id]);
    } else if (req.user.role === 'admin') {
      // Ensure admin can only delete within their organization
      result = await pool.query('DELETE FROM duties WHERE id=$1 AND group_id=$2 RETURNING id', [id, req.user.group_id]);
    } else {
      return res.status(403).json({ message: 'Admins only' });
    }
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Per-user theme endpoints
app.get('/theme', authRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM user_theme WHERE user_id=$1', [req.user.id]);
    const defaults = {
      primary_color: process.env.THEME_PRIMARY || '#000000',
      text_color: process.env.THEME_TEXT || '#ffffff',
      accent1: process.env.ACCENT1 || '#35b1fb',
      accent2: process.env.ACCENT2 || '#0289db',
      accent3: process.env.ACCENT3 || '#054a74',
      accent4: process.env.ACCENT4 || '#00433a',
      accent5: process.env.ACCENT5 || '#ffffff',
      logo_url: process.env.LOGO_URL || null,
      bg_image_url: process.env.BG_IMAGE_URL || null,
    };
    res.json({ ...defaults, ...(result.rows[0] || {}) });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load theme' });
  }
});

app.post('/theme', authRequired, async (req, res) => {
  try {
    const t = req.body || {};
    const result = await pool.query(
      `INSERT INTO user_theme (user_id, primary_color, text_color, accent1, accent2, accent3, accent4, accent5, logo_url, bg_image_url, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         primary_color=EXCLUDED.primary_color,
         text_color=EXCLUDED.text_color,
         accent1=EXCLUDED.accent1,
         accent2=EXCLUDED.accent2,
         accent3=EXCLUDED.accent3,
         accent4=EXCLUDED.accent4,
         accent5=EXCLUDED.accent5,
         logo_url=EXCLUDED.logo_url,
         bg_image_url=EXCLUDED.bg_image_url,
         updated_at=NOW()
       RETURNING user_id`,
      [
        req.user.id,
        t.primary_color ?? null,
        t.text_color ?? null,
        t.accent1 ?? null,
        t.accent2 ?? null,
        t.accent3 ?? null,
        t.accent4 ?? null,
        t.accent5 ?? null,
        t.logo_url ?? null,
        t.bg_image_url ?? null,
      ]
    );
    res.json({ ok: true, user_id: result.rows[0].user_id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// --- Groups
app.get('/groups', authRequired, async (req, res) => {
  if (req.user.role === 'superadmin') {
    const groups = await pool.query('SELECT * FROM groups ORDER BY LOWER(name) ASC');
    return res.json(groups.rows);
  }
  if (req.user.group_id == null) return res.json([]);
  const groups = await pool.query('SELECT * FROM groups WHERE id=$1 ORDER BY LOWER(name) ASC', [req.user.group_id]);
  res.json(groups.rows);
});

app.post('/groups', authRequired, superadminOnly, async (req, res) => {
  try {
    const { name, status, time_zone } = req.body || {};
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='groups'");
    const has = new Set(colsRes.rows.map(r => r.column_name));
    const fields = ['name'];
    const params = ['$1'];
    const values = [name];
    let nextIdx = 2;
    if (has.has('status')) { fields.push('status'); params.push(`$${nextIdx++}`); values.push((status || 'active')); }
    else if (has.has('group_status')) {
      const normalized = (status || 'Active');
      const mapped = normalized.toLowerCase() === 'active' ? 'Active'
                   : normalized.toLowerCase() === 'inactive' ? 'Inactive'
                   : normalized; // fall back to whatever caller sent
      fields.push('group_status'); params.push(`$${nextIdx++}`); values.push(mapped);
    }
    if (has.has('time_zone')) { fields.push('time_zone'); params.push(`$${nextIdx++}`); values.push(time_zone || 'UTC'); }
    const sql = `INSERT INTO groups (${fields.join(',')}) VALUES (${params.join(',')}) RETURNING id`;
    const result = await pool.query(sql, values);
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete('/groups/:id', authRequired, superadminOnly, async (req, res) => {
  await pool.query('DELETE FROM groups WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// Update group (name/status)
app.patch('/groups/:id', authRequired, superadminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    const { name, status, time_zone } = req.body || {};
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='groups'");
    const has = new Set(colsRes.rows.map(r => r.column_name));
    const setClauses = [];
    const params = [];
    let idx = 1;
    if (name !== undefined) { setClauses.push(`name=$${idx++}`); params.push(name); }
    if (status !== undefined) {
      if (has.has('status')) { setClauses.push(`status=$${idx++}`); params.push(status); }
      else if (has.has('group_status')) {
        const normalized = String(status).toLowerCase();
        const mapped = normalized === 'active' ? 'Active' : normalized === 'inactive' ? 'Inactive' : status;
        setClauses.push(`group_status=$${idx++}`); params.push(mapped);
      }
    }
    if (time_zone !== undefined && has.has('time_zone')) { setClauses.push(`time_zone=$${idx++}`); params.push(time_zone); }
    if (setClauses.length === 0) return res.json({ id });
    const returning = ['id'];
    if (has.has('name')) returning.push('name');
    if (has.has('status')) returning.push('status');
    if (has.has('group_status')) returning.push('group_status');
    if (has.has('time_zone')) returning.push('time_zone');
    const result = await pool.query(`UPDATE groups SET ${setClauses.join(', ')} WHERE id=$${idx} RETURNING ${returning.join(',')}`, [...params, id]);
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// --- Events
app.get('/events', authRequired, async (req, res) => {
  // Return events plus a joined flag for the current user
  if (req.user.role === 'superadmin') {
    const groupFilter = req.query.group_id ? Number(req.query.group_id) : null;
    const params = [req.user.id];
    let where = 'e.archived_at IS NULL';
    if (Number.isFinite(groupFilter)) { where += ' AND e.group_id = $2'; params.push(groupFilter); }
    const events = await pool.query(
      `SELECT e.*, EXISTS(
         SELECT 1 FROM event_attendees a WHERE a.event_id = e.id AND a.user_id = $1
       ) AS joined
       FROM events e
       WHERE ${where}
       ORDER BY COALESCE(e.start_date, e.event_date) DESC`,
      params
    );
    return res.json(events.rows);
  }
  const events = await pool.query(
    `SELECT e.*, EXISTS(
       SELECT 1 FROM event_attendees a WHERE a.event_id = e.id AND a.user_id = $1
     ) AS joined
     FROM events e
     WHERE e.archived_at IS NULL AND e.group_id=$2
     ORDER BY COALESCE(e.start_date, e.event_date) DESC`,
    [req.user.id, req.user.group_id]
  );
  res.json(events.rows);
});

app.post('/events', authRequired, adminOnly, async (req, res) => {
  try {
    const { title, description, event_date, start_date, end_date, start_time, end_time } = req.body || {};
    let { group_id } = req.body || {};
    if (!group_id) group_id = req.user.group_id || null;
    if (!group_id) return res.status(400).json({ message: 'Group is required for events' });
    const result = await pool.query(
      'INSERT INTO events (title,description,event_date,start_date,end_date,start_time,end_time,group_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',
      [title, description ?? null, event_date ?? null, start_date ?? null, end_date ?? null, start_time ?? null, end_time ?? null, group_id]
    );
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Edit event
app.patch('/events/:id', authRequired, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    const { title, description, event_date, start_date, end_date, start_time, end_time, group_id } = req.body || {};
    const setClauses = [];
    const params = [];
    let idx = 1;
    if (title !== undefined) { setClauses.push(`title = $${idx++}`); params.push(title); }
    if (description !== undefined) { setClauses.push(`description = $${idx++}`); params.push(description); }
    if (event_date !== undefined) { setClauses.push(`event_date = $${idx++}`); params.push(event_date); }
    if (start_date !== undefined) { setClauses.push(`start_date = $${idx++}`); params.push(start_date); }
    if (end_date !== undefined) { setClauses.push(`end_date = $${idx++}`); params.push(end_date); }
    if (start_time !== undefined) { setClauses.push(`start_time = $${idx++}`); params.push(start_time); }
    if (end_time !== undefined) { setClauses.push(`end_time = $${idx++}`); params.push(end_time); }
    if (group_id !== undefined) { setClauses.push(`group_id = $${idx++}`); params.push(group_id); }
    if (setClauses.length === 0) return res.json({ id });
    let result;
    if (req.user.role === 'superadmin') {
      result = await pool.query(
        `UPDATE events SET ${setClauses.join(', ')} WHERE id=$${idx} RETURNING id`,
        [...params, id]
      );
    } else {
      result = await pool.query(
        `UPDATE events SET ${setClauses.join(', ')} WHERE id=$${idx} AND group_id=$${idx + 1} RETURNING id`,
        [...params, id, req.user.group_id]
      );
    }
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    // Archive all duties linked to this event
    try { await pool.query('UPDATE duties SET archived_at=NOW() WHERE event_id=$1 AND archived_at IS NULL', [id]); } catch (_) {}
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Archive an event (soft delete)
app.post('/events/:id/archive', authRequired, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    let result;
    if (req.user.role === 'superadmin') {
      result = await pool.query('UPDATE events SET archived_at=NOW() WHERE id=$1 AND archived_at IS NULL RETURNING id', [id]);
    } else {
      result = await pool.query('UPDATE events SET archived_at=NOW() WHERE id=$1 AND group_id=$2 AND archived_at IS NULL RETURNING id', [id, req.user.group_id]);
    }
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Delete an event (hard delete)
app.delete('/events/:id', authRequired, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    let result;
    if (req.user.role === 'superadmin') {
      result = await pool.query('DELETE FROM events WHERE id=$1 RETURNING id', [id]);
    } else {
      result = await pool.query('DELETE FROM events WHERE id=$1 AND group_id=$2 RETURNING id', [id, req.user.group_id]);
    }
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    // Hard delete duties linked to this event (event already verified by role checks)
    try { await pool.query('DELETE FROM duties WHERE event_id=$1', [id]); } catch (_) {}
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// RSVP: join an event
app.post('/events/:id/join', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    // Ensure event visible to user (group scoped unless superadmin)
    const ev = await pool.query('SELECT * FROM events WHERE id=$1 AND archived_at IS NULL', [id]);
    if (ev.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    if (req.user.role !== 'superadmin' && ev.rows[0].group_id && ev.rows[0].group_id !== req.user.group_id) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    await pool.query('INSERT INTO event_attendees(event_id,user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, req.user.id]);
    res.json({ joined: true });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// RSVP: leave an event
app.post('/events/:id/leave', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    await pool.query('DELETE FROM event_attendees WHERE event_id=$1 AND user_id=$2', [id, req.user.id]);
    res.json({ joined: false });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// --- Duties
app.get('/duties', authRequired, async (req, res) => {
  if (req.user.role === 'superadmin') {
    const groupFilter = req.query.group_id ? Number(req.query.group_id) : null;
    if (Number.isFinite(groupFilter)) {
      const duties = await pool.query('SELECT * FROM duties WHERE group_id=$1 AND archived_at IS NULL ORDER BY id', [groupFilter]);
      return res.json(duties.rows);
    }
    const duties = await pool.query('SELECT * FROM duties WHERE archived_at IS NULL ORDER BY id');
    return res.json(duties.rows);
  }
  const duties = await pool.query('SELECT * FROM duties WHERE group_id=$1 AND archived_at IS NULL ORDER BY id', [req.user.group_id]);
  res.json(duties.rows);
});

app.post('/duties', authRequired, async (req, res) => {
  try {
    const { title, description, status, group_id, event_id } = req.body || {};
    let targetGroupId = group_id ?? null;
    if (isAdmin(req.user)) {
      targetGroupId = (targetGroupId ?? req.user.group_id ?? null);
      if (targetGroupId == null) return res.status(400).json({ message: 'Group is required for duties' });
    } else if (req.user.role === 'volunteer') {
      targetGroupId = req.user.group_id;
      if (targetGroupId == null) return res.status(400).json({ message: 'Missing group context' });
    } else {
      return res.status(403).json({ message: 'Forbidden' });
    }
    // Require event for all duties
    if (event_id == null) return res.status(400).json({ message: 'Event is required for duties' });

    // Build insert compatible with varying schemas
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='duties'");
    const has = new Set(colsRes.rows.map(r => r.column_name));
    // Normalize status to match stricter schemas (e.g., pending/in_progress/completed)
    const statusMap = { open: 'pending', closed: 'completed', complete: 'completed', completed: 'completed' };
    let normalizedStatus = (status || 'pending').toLowerCase();
    normalizedStatus = statusMap[normalizedStatus] || normalizedStatus;
    if (!['pending','in_progress','completed'].includes(normalizedStatus)) normalizedStatus = 'pending';
    const fields = [];
    const params = [];
    const values = [];
    let idx = 1;
    fields.push('title'); params.push(`$${idx++}`); values.push(title);
    fields.push('description'); params.push(`$${idx++}`); values.push(description ?? null);
    if (has.has('status')) { fields.push('status'); params.push(`$${idx++}`); values.push(normalizedStatus); }
    if (has.has('group_id')) { fields.push('group_id'); params.push(`$${idx++}`); values.push(targetGroupId); }
    if (has.has('event_id')) { fields.push('event_id'); params.push(`$${idx++}`); values.push(event_id ?? null); }

    const sql = `INSERT INTO duties (${fields.join(',')}) VALUES (${params.join(',')}) RETURNING id`;
    const result = await pool.query(sql, values);
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Edit duty
app.patch('/duties/:id', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    const { title, description, status, event_id, group_id } = req.body || {};
    // Only admins/superadmins can edit duties broadly; volunteers can only edit their own created duty's title/description
    const isAdminish = isAdmin(req.user);
    const colsRes = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='duties'");
    const has = new Set(colsRes.rows.map(r => r.column_name));

    const setClauses = [];
    const params = [];
    let idx = 1;
    if (title !== undefined) { setClauses.push(`title=$${idx++}`); params.push(title); }
    if (description !== undefined) { setClauses.push(`description=$${idx++}`); params.push(description); }
    if (status !== undefined && has.has('status')) {
      const map = { open: 'pending', closed: 'completed', complete: 'completed', completed: 'completed' };
      let s = String(status).toLowerCase();
      s = map[s] || s;
      if (!['pending','in_progress','completed'].includes(s)) s = 'pending';
      setClauses.push(`status=$${idx++}`); params.push(s);
    }
    if (event_id !== undefined && has.has('event_id')) {
      if (event_id == null) return res.status(400).json({ message: 'Event cannot be cleared from a duty' });
      setClauses.push(`event_id=$${idx++}`); params.push(event_id);
    }
    if (group_id !== undefined && has.has('group_id')) { setClauses.push(`group_id=$${idx++}`); params.push(group_id); }
    if (setClauses.length === 0) return res.json({ id });

    let result;
    if (isAdminish) {
      if (req.user.role === 'superadmin') {
        result = await pool.query(`UPDATE duties SET ${setClauses.join(', ')} WHERE id=$${idx} RETURNING id`, [...params, id]);
      } else {
        result = await pool.query(
          `UPDATE duties SET ${setClauses.join(', ')} WHERE id=$${idx} AND group_id=$${idx + 1} RETURNING id`,
          [...params, id, req.user.group_id]
        );
      }
    } else if (req.user.role === 'volunteer' && has.has('volunteer_id')) {
      result = await pool.query(
        `UPDATE duties SET ${setClauses.join(', ')} WHERE id=$${idx} AND volunteer_id=$${idx + 1} RETURNING id`,
        [...params, id, req.user.id]
      );
    } else {
      return res.status(403).json({ message: 'Forbidden' });
    }
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// --- Time tracking
app.post('/duties/:id/time/start', authRequired, async (req, res) => {
  try {
    await ensureDutyDateColumn();
    await ensureTimeTrackingConstraints();
    const { duty_date } = req.body;
    const result = await pool.query(
      'INSERT INTO time_tracking (volunteer_id,duty_id,start_time,duty_date) VALUES ($1,$2,NOW(),$3) RETURNING id',
      [req.user.id, req.params.id, duty_date]
    );
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.post('/duties/:id/time/end', authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE time_tracking
       SET end_time=NOW(),
           duration_hours=EXTRACT(EPOCH FROM (NOW()-start_time))/3600
       WHERE volunteer_id=$1 AND duty_id=$2 AND end_time IS NULL
       RETURNING id`,
      [req.user.id, req.params.id]
    );
    if (result.rowCount === 0) return res.status(400).json({ message: 'No active clock-in' });
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.get('/time-tracking', authRequired, async (req, res) => {
  const volunteerFilter = req.query.volunteer_id ? Number(req.query.volunteer_id) : null;
  const groupFilter = req.query.group_id ? Number(req.query.group_id) : null;
  if (req.user.role === 'superadmin') {
    if (Number.isFinite(volunteerFilter)) {
      const rows = await pool.query('SELECT * FROM time_tracking WHERE volunteer_id=$1 ORDER BY start_time DESC', [volunteerFilter]);
      return res.json(rows.rows);
    }
    if (Number.isFinite(groupFilter)) {
      const rows = await pool.query(
        `SELECT t.*
         FROM time_tracking t
         JOIN users u ON u.id = t.volunteer_id
         WHERE u.group_id = $1
         ORDER BY t.start_time DESC`,
        [groupFilter]
      );
      return res.json(rows.rows);
    }
    const rows = await pool.query('SELECT * FROM time_tracking ORDER BY start_time DESC');
    return res.json(rows.rows);
  }
  if (req.user.role === 'admin') {
    if (Number.isFinite(volunteerFilter)) {
      // Ensure volunteer belongs to admin's group
      const ok = await pool.query('SELECT 1 FROM users WHERE id=$1 AND group_id=$2', [volunteerFilter, req.user.group_id]);
      if (ok.rowCount === 0) return res.status(403).json({ message: 'Forbidden' });
      const rows = await pool.query('SELECT * FROM time_tracking WHERE volunteer_id=$1 ORDER BY start_time DESC', [volunteerFilter]);
      return res.json(rows.rows);
    }
    const rows = await pool.query(
      `SELECT t.*
       FROM time_tracking t
       JOIN users u ON u.id = t.volunteer_id
       WHERE u.group_id = $1
       ORDER BY t.start_time DESC`,
      [req.user.group_id]
    );
    return res.json(rows.rows);
  }
  const rows = await pool.query('SELECT * FROM time_tracking WHERE volunteer_id=$1 ORDER BY start_time DESC', [req.user.id]);
  res.json(rows.rows);
});

// CSV export
app.get('/time-tracking.csv', authRequired, async (req, res) => {
  try {
    let rows;
    if (req.user.role === 'superadmin') {
      rows = (await pool.query('SELECT * FROM time_tracking ORDER BY start_time DESC')).rows;
    } else if (req.user.role === 'admin') {
      rows = (await pool.query(
        `SELECT t.*
         FROM time_tracking t
         JOIN users u ON u.id = t.volunteer_id
         WHERE u.group_id = $1
         ORDER BY t.start_time DESC`,
        [req.user.group_id]
      )).rows;
    } else {
      rows = (await pool.query('SELECT * FROM time_tracking WHERE volunteer_id=$1 ORDER BY start_time DESC', [req.user.id])).rows;
    }
    const header = ['id','volunteer_id','duty_id','event_id','start_time','end_time','duration_hours','duty_date','approved'];
    const body = rows.map(r => header.map(h => r[h] == null ? '' : String(r[h]).replaceAll('"', '""')).map(v => `"${v}"`).join(','));
    const csv = [header.join(','), ...body].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="time-tracking.csv"');
    res.send(csv);
  } catch (err) {
    res.status(500).json({ message: 'Failed to export CSV' });
  }
});

// Edit a time log (admin/superadmin)
app.patch('/time-tracking/:id', authRequired, async (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).json({ message: 'Admins only' });
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
  const { start_time, end_time, duty_date, duration_hours } = req.body || {};
  try {
    await ensureDutyDateColumn();
    await ensureTimeTrackingConstraints();
    // Build update pieces
    const setClauses = [];
    const params = [];
    let idx = 1;
    if (start_time !== undefined) { setClauses.push(`start_time = $${idx++}::timestamp`); params.push(start_time || null); }
    if (end_time !== undefined) { setClauses.push(`end_time = $${idx++}::timestamp`); params.push(end_time || null); }
    if (duty_date !== undefined) { setClauses.push(`duty_date = $${idx++}::date`); params.push(duty_date || null); }
    // duration computed if both times set, else accept manual override when provided
    let computeDuration = false;
    if (start_time !== undefined || end_time !== undefined) computeDuration = true;
    if (!computeDuration && duration_hours !== undefined) {
      setClauses.push(`duration_hours = $${idx++}`); params.push(duration_hours);
    }
    // Always recompute if both timestamps available in DB after update
    // We implement recompute in SQL using CASE when computeDuration true
    if (computeDuration) {
      setClauses.push(`duration_hours = CASE WHEN (COALESCE((SELECT start_time FROM time_tracking WHERE id=$${idx}), start_time) IS NOT NULL AND COALESCE((SELECT end_time FROM time_tracking WHERE id=$${idx}), end_time) IS NOT NULL)
        THEN EXTRACT(EPOCH FROM (COALESCE((SELECT end_time FROM time_tracking WHERE id=$${idx}), end_time) - COALESCE((SELECT start_time FROM time_tracking WHERE id=$${idx}), start_time)))/3600
        ELSE duration_hours END`);
      // Use id multiple times as placeholders
      params.push(id, id, id, id);
      idx += 4;
    }

    if (setClauses.length === 0) return res.json({ id });

    let result;
    if (req.user.role === 'superadmin') {
      result = await pool.query(
        `UPDATE time_tracking SET ${setClauses.join(', ')} WHERE id=$${idx} RETURNING id`,
        [...params, id]
      );
    } else {
      // Admins restricted to their group
      result = await pool.query(
        `UPDATE time_tracking t
         SET ${setClauses.join(', ')}
         FROM users u
         WHERE t.id=$${idx} AND u.id=t.volunteer_id AND u.group_id=$${idx + 1}
         RETURNING t.id`,
        [...params, id, req.user.group_id]
      );
    }
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Delete a time log (admin/superadmin)
app.delete('/time-tracking/:id', authRequired, async (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).json({ message: 'Admins only' });
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
  try {
    let result;
    if (req.user.role === 'superadmin') {
      result = await pool.query('DELETE FROM time_tracking WHERE id=$1 RETURNING id', [id]);
    } else {
      result = await pool.query(
        `DELETE FROM time_tracking t USING users u
         WHERE t.id=$1 AND u.id=t.volunteer_id AND u.group_id=$2
         RETURNING t.id`,
        [id, req.user.group_id]
      );
    }
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Admin create time entry for volunteer
app.post('/admin/time-tracking', authRequired, async (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).json({ message: 'Admins only' });
  try {
    await ensureDutyDateColumn();
    await ensureTimeTrackingConstraints();
    const { volunteer_id, duty_id, start_time, end_time, duty_date } = req.body || {};
    const volunteerIdNum = volunteer_id == null ? null : Number(volunteer_id);
    const dutyIdNum = duty_id == null ? null : Number(duty_id);

    if (!volunteer_id || !duty_id || !start_time) {
      return res.status(400).json({ message: 'volunteer_id, duty_id, start_time required' });
    }
    if (!Number.isFinite(volunteerIdNum) || !Number.isFinite(dutyIdNum)) {
      return res.status(400).json({ message: 'Invalid volunteer_id or duty_id' });
    }

    const volunteerRes = await pool.query('SELECT id, role, group_id FROM users WHERE id=$1', [volunteerIdNum]);
    const volunteerRow = volunteerRes.rows[0];
    const volunteerRole = volunteerRow ? String(volunteerRow.role || '').toLowerCase() : null;
    if (volunteerRes.rowCount === 0 || volunteerRole !== 'volunteer') {
      return res.status(404).json({ message: 'Volunteer not found. Refresh the volunteer list and try again.' });
    }
    const dutyRes = await pool.query('SELECT id, group_id FROM duties WHERE id=$1', [dutyIdNum]);
    if (dutyRes.rowCount === 0) {
      return res.status(404).json({ message: 'Duty not found. Refresh the duty list and try again.' });
    }
    if (req.user.role === 'admin') {
      if (volunteerRow.group_id !== req.user.group_id) {
        return res.status(403).json({ message: 'Admins can only add time for volunteers in their organization.' });
      }
      if (dutyRes.rows[0].group_id != null && dutyRes.rows[0].group_id !== req.user.group_id) {
        return res.status(403).json({ message: 'Admins can only add time for duties in their organization.' });
      }
    }
    const result = await pool.query(
      `INSERT INTO time_tracking (volunteer_id,duty_id,start_time,end_time,duty_date)
       VALUES ($1,$2,$3::timestamp,$4::timestamp,$5::date) RETURNING id`,
      [volunteerIdNum, dutyIdNum, start_time, end_time || null, duty_date || null]
    );
    res.json({ id: result.rows[0].id });
  } catch (err) {
    console.error('Failed to add time entry:', err);
    if (err?.code === '23503') {
      const detail = String(err.detail || '');
      if (detail.includes('(volunteer_id)')) {
        return res.status(404).json({ message: `Volunteer #${volunteerIdNum ?? volunteer_id} no longer exists in the database.` });
      }
      if (detail.includes('(duty_id)')) {
        return res.status(404).json({ message: `Duty #${dutyIdNum ?? duty_id} no longer exists in the database.` });
      }
      return res.status(400).json({ message: 'Volunteer or duty missing in the database.' });
    }
    res.status(400).json({ message: err?.message || 'Failed to add time entry' });
  }
});

// --- Milestones
app.get('/milestones', authRequired, async (req, res) => {
  const rows = await pool.query('SELECT * FROM milestones WHERE volunteer_id=$1', [req.user.id]);
  res.json(rows.rows);
});

// Alias to match frontend call /milestones/:id
app.get('/milestones/:id', authRequired, async (req, res) => {
  const targetId = Number(req.params.id);
  if (!Number.isFinite(targetId)) return res.status(400).json({ message: 'Invalid id' });
  if (req.user.id !== targetId && !isAdmin(req.user)) return res.status(403).json({ message: 'Forbidden' });
  const rows = await pool.query('SELECT * FROM milestones WHERE volunteer_id=$1', [targetId]);
  res.json(rows.rows);
});

app.post('/milestones', authRequired, async (req, res) => {
  try {
    const { goal_hours } = req.body;
    const result = await pool.query(
      'INSERT INTO milestones (volunteer_id,goal_hours) VALUES ($1,$2) RETURNING id',
      [req.user.id, goal_hours]
    );
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// --- Approvals (admins)
app.get('/approvals', authRequired, adminOnly, async (req, res) => {
  const rows = await pool.query('SELECT * FROM time_tracking WHERE approved=false');
  res.json(rows.rows);
});

app.post('/approvals/:id/approve', authRequired, adminOnly, async (req, res) => {
  await pool.query('UPDATE time_tracking SET approved=true WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// Alias to match frontend POST /time-tracking/:id/approve
app.post('/time-tracking/:id/approve', authRequired, adminOnly, async (req, res) => {
  await pool.query('UPDATE time_tracking SET approved=true WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// --- Photo uploads (work evidence)
const uploadDir = require('path').join(__dirname, 'uploads');
try { fs.mkdirSync(uploadDir, { recursive: true }); } catch {}
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = require('path').extname(file.originalname || '');
    cb(null, `${Date.now()}-${Math.round(Math.random()*1e9)}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// Upload photo for a duty
app.post('/duties/:id/photos', authRequired, upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const dutyId = Number(req.params.id);
    const caption = (req.body && req.body.caption) || null;
    const publicPath = `/uploads/${req.file.filename}`;
    const result = await pool.query(
      `INSERT INTO work_photos (volunteer_id, duty_id, file_path, caption, approved)
       VALUES ($1,$2,$3,$4,false) RETURNING id, file_path`,
      [req.user.id, dutyId, publicPath, caption]
    );
    res.json({ id: result.rows[0].id, file_path: result.rows[0].file_path });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// List photos (scoped)
app.get('/photos', authRequired, async (req, res) => {
  const volunteerFilter = req.query.volunteer_id ? Number(req.query.volunteer_id) : null;
  const groupFilter = req.query.group_id ? Number(req.query.group_id) : null;
  if (req.user.role === 'superadmin') {
    if (Number.isFinite(volunteerFilter)) {
      const rows = await pool.query('SELECT * FROM work_photos WHERE volunteer_id=$1 ORDER BY created_at DESC', [volunteerFilter]);
      return res.json(rows.rows);
    }
    if (Number.isFinite(groupFilter)) {
      const rows = await pool.query(
        `SELECT p.*
         FROM work_photos p
         JOIN users u ON u.id = p.volunteer_id
         WHERE u.group_id = $1
         ORDER BY p.created_at DESC`,
        [groupFilter]
      );
      return res.json(rows.rows);
    }
    const all = await pool.query('SELECT * FROM work_photos ORDER BY created_at DESC');
    return res.json(all.rows);
  }
  if (req.user.role === 'admin') {
    if (Number.isFinite(volunteerFilter)) {
      const ok = await pool.query('SELECT 1 FROM users WHERE id=$1 AND group_id=$2', [volunteerFilter, req.user.group_id]);
      if (ok.rowCount === 0) return res.status(403).json({ message: 'Forbidden' });
      const rows = await pool.query('SELECT * FROM work_photos WHERE volunteer_id=$1 ORDER BY created_at DESC', [volunteerFilter]);
      return res.json(rows.rows);
    }
    const rows = await pool.query(
      `SELECT p.*
       FROM work_photos p
       JOIN users u ON u.id = p.volunteer_id
       WHERE u.group_id = $1
       ORDER BY p.created_at DESC`,
      [req.user.group_id]
    );
    return res.json(rows.rows);
  }
  const mine = await pool.query('SELECT * FROM work_photos WHERE volunteer_id=$1 ORDER BY created_at DESC', [req.user.id]);
  res.json(mine.rows);
});

// Approve a photo (admin/superadmin)
app.post('/photos/:id/approve', authRequired, adminOnly, async (req, res) => {
  if (req.user.role === 'superadmin') {
    await pool.query('UPDATE work_photos SET approved=true WHERE id=$1', [req.params.id]);
    return res.json({ ok: true });
  }
  const result = await pool.query(
    `UPDATE work_photos p
     SET approved=true
     FROM users u
     WHERE p.id=$1 AND u.id=p.volunteer_id AND u.group_id=$2
     RETURNING p.id`,
    [req.params.id, req.user.group_id]
  );
  if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
  res.json({ ok: true });
});

// Delete a photo (admin/superadmin)
app.delete('/photos/:id', authRequired, adminOnly, async (req, res) => {
  try {
    const photoId = Number(req.params.id);
    if (!Number.isFinite(photoId)) return res.status(400).json({ message: 'Invalid id' });
    let result;
    if (req.user.role === 'superadmin') {
      result = await pool.query('DELETE FROM work_photos WHERE id=$1 RETURNING id', [photoId]);
    } else {
      result = await pool.query(
        `DELETE FROM work_photos p USING users u
         WHERE p.id=$1 AND u.id=p.volunteer_id AND u.group_id=$2
         RETURNING p.id`,
        [photoId, req.user.group_id]
      );
    }
    if (result.rowCount === 0) return res.status(404).json({ message: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// --- Health
app.get('/health', (req, res) => res.json({ ok: true }));

// --- Serve frontend
const path = require('path');
// Serve index with no-store to avoid stale cached toolbar order
app.get(['/', '/index.html'], (req, res) => {
  try {
    res.set('Cache-Control', 'no-store, max-age=0');
  } catch (_) {}
  return res.sendFile(path.join(__dirname, 'index.html'));
});
app.use(express.static(path.join(__dirname, '/')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API listening on ${PORT}`));
