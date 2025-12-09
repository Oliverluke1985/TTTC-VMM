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

const brandingMemoryUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

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
    const isApiRequest = req.path.startsWith('/time-tracking.csv');
    if (!isApiRequest) {
      return res.redirect(301, `https://${CANONICAL_HOST}${req.originalUrl}`);
    }
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
let ensuredDurationColumn = false;
async function ensureDurationHoursColumn() {
  if (ensuredDurationColumn) return;
  try {
    await pool.query('ALTER TABLE IF EXISTS time_tracking ADD COLUMN IF NOT EXISTS duration_hours DOUBLE PRECISION');
    ensuredDurationColumn = true;
  } catch (err) {
    console.error('Failed ensuring time_tracking.duration_hours column:', err?.message || err);
  }
}

let ensuredTimeTrackingEventColumn = false;
async function ensureTimeTrackingEventColumn() {
  if (ensuredTimeTrackingEventColumn) return;
  try {
    await pool.query(`
      ALTER TABLE IF EXISTS time_tracking
      ADD COLUMN IF NOT EXISTS event_id INTEGER REFERENCES events(id) ON DELETE SET NULL
    `);
    ensuredTimeTrackingEventColumn = true;
  } catch (err) {
    console.error('Failed ensuring time_tracking.event_id column:', err?.message || err);
  }
}

let ensuredTimeTrackingConstraints = false;
let ensuredTimeTrackingApprovedColumn = false;
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

async function ensureTimeTrackingApprovalColumn() {
  if (ensuredTimeTrackingApprovedColumn) return;
  try {
    await pool.query('ALTER TABLE IF EXISTS time_tracking ADD COLUMN IF NOT EXISTS approved BOOLEAN DEFAULT false');
    ensuredTimeTrackingApprovedColumn = true;
  } catch (err) {
    console.error('Failed ensuring time_tracking.approved column:', err?.message || err);
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
    await pool.query(
      'ALTER TABLE IF EXISTS duties ADD COLUMN IF NOT EXISTS location TEXT NULL'
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
    await pool.query(
      'ALTER TABLE IF EXISTS events ADD COLUMN IF NOT EXISTS color_hex TEXT'
    );
    await pool.query(
      'ALTER TABLE IF EXISTS events ADD COLUMN IF NOT EXISTS address TEXT NULL'
    );
    // Time tracking duty_date ensure
    await pool.query(
      'ALTER TABLE IF EXISTS time_tracking ADD COLUMN IF NOT EXISTS duty_date DATE NULL'
    );
    await pool.query(
      'ALTER TABLE IF EXISTS time_tracking ADD COLUMN IF NOT EXISTS event_id INTEGER REFERENCES events(id) ON DELETE SET NULL'
    );
    ensuredTimeTrackingEventColumn = true;
    await ensureTimeTrackingApprovalColumn();
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
    await pool.query(
      'ALTER TABLE IF EXISTS duties ADD COLUMN IF NOT EXISTS max_volunteers INTEGER'
    );
    await pool.query(
      `CREATE TABLE IF NOT EXISTS group_branding (
         group_id INTEGER PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
         logo_url TEXT,
         banner_url TEXT,
         hero_url TEXT,
         footer_url TEXT,
         primary_color TEXT,
         text_color TEXT,
         accent1 TEXT,
         accent2 TEXT,
         accent3 TEXT,
         accent4 TEXT,
         accent5 TEXT,
         logo_blob BYTEA,
         logo_blob_type TEXT,
         logo_blob_updated_at TIMESTAMP,
         banner_blob BYTEA,
         banner_blob_type TEXT,
         banner_blob_updated_at TIMESTAMP,
         hero_blob BYTEA,
         hero_blob_type TEXT,
         hero_blob_updated_at TIMESTAMP,
         footer_blob BYTEA,
         footer_blob_type TEXT,
         footer_blob_updated_at TIMESTAMP,
         updated_at TIMESTAMP NOT NULL DEFAULT NOW()
       )`
    );
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS logo_blob BYTEA`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS logo_blob_type TEXT`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS logo_blob_updated_at TIMESTAMP`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS banner_blob BYTEA`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS banner_blob_type TEXT`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS banner_blob_updated_at TIMESTAMP`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS hero_url TEXT`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS hero_blob BYTEA`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS hero_blob_type TEXT`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS hero_blob_updated_at TIMESTAMP`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS footer_blob BYTEA`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS footer_blob_type TEXT`);
    await pool.query(`ALTER TABLE IF EXISTS group_branding ADD COLUMN IF NOT EXISTS footer_blob_updated_at TIMESTAMP`);
    await pool.query(
      `CREATE TABLE IF NOT EXISTS duty_restrictions (
         duty_id INTEGER NOT NULL REFERENCES duties(id) ON DELETE CASCADE,
         volunteer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
         created_at TIMESTAMP NOT NULL DEFAULT NOW(),
         PRIMARY KEY (duty_id, volunteer_id)
       )`
    );
    await pool.query(
      `CREATE TABLE IF NOT EXISTS duty_templates (
         id SERIAL PRIMARY KEY,
         group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
         title TEXT NOT NULL,
         description TEXT,
         status TEXT DEFAULT 'pending',
         max_volunteers INTEGER,
         created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
         created_at TIMESTAMP NOT NULL DEFAULT NOW(),
         updated_at TIMESTAMP NOT NULL DEFAULT NOW()
       )`
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
    bannerUrl: process.env.BANNER_URL || 'https://i.postimg.cc/t4S6CDjx/cityscape.jpg',
    footerUrl: process.env.FOOTER_URL || 'https://i.postimg.cc/8Cfgxn5P/theater-seats.jpg',
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

const BRANDING_COLUMNS = ['logo_url','banner_url','hero_url','footer_url','primary_color','text_color','accent1','accent2','accent3','accent4','accent5'];

app.get('/branding', authRequired, async (req, res) => {
  try {
    const targetGroupId = Number(req.user.group_id);
    if (!Number.isFinite(targetGroupId)) return res.json({ group_id: null, branding: null });
    const result = await pool.query(
      `
        SELECT ${BRANDING_COLUMNS.join(', ')},
               logo_has_blob,
               banner_has_blob,
               hero_has_blob,
               footer_has_blob,
               logo_blob_updated_at,
               banner_blob_updated_at,
               hero_blob_updated_at,
               footer_blob_updated_at
        FROM (
          SELECT *,
                 (logo_blob IS NOT NULL) AS logo_has_blob,
                 (banner_blob IS NOT NULL) AS banner_has_blob,
                 (hero_blob IS NOT NULL) AS hero_has_blob,
                 (footer_blob IS NOT NULL) AS footer_has_blob
          FROM group_branding
        ) gb
        WHERE gb.group_id=$1
      `,
      [targetGroupId]
    );
    const row = result.rows[0];
    if (!row) return res.json({ group_id: targetGroupId, branding: null });
    const branding = {
      logo_url: row.logo_url,
      banner_url: row.banner_url,
      hero_url: row.hero_url,
      footer_url: row.footer_url,
      primary_color: row.primary_color,
      text_color: row.text_color,
      accent1: row.accent1,
      accent2: row.accent2,
      accent3: row.accent3,
      accent4: row.accent4,
      accent5: row.accent5,
    };
    const versionSuffix = (ts) => ts ? `?v=${new Date(ts).getTime()}` : '';
    if (row.logo_has_blob) {
      branding.logo_url = `/branding/assets/logo?group_id=${targetGroupId}${versionSuffix(row.logo_blob_updated_at)}`;
    }
    if (row.banner_has_blob) {
      branding.banner_url = `/branding/assets/banner?group_id=${targetGroupId}${versionSuffix(row.banner_blob_updated_at)}`;
    }
    if (row.hero_has_blob) {
      branding.hero_url = `/branding/assets/hero?group_id=${targetGroupId}${versionSuffix(row.hero_blob_updated_at)}`;
    }
    if (row.footer_has_blob) {
      branding.footer_url = `/branding/assets/footer?group_id=${targetGroupId}${versionSuffix(row.footer_blob_updated_at)}`;
    }
    res.json({ group_id: targetGroupId, branding });
  } catch (err) {
    res.status(500).json({ message: err?.message || 'Failed to load branding' });
  }
});

app.post('/branding', authRequired, adminOnly, async (req, res) => {
  try {
    let targetGroupId = Number(req.user.group_id);
    if (req.user.role === 'superadmin' && req.body?.group_id != null) {
      const override = Number(req.body.group_id);
      if (Number.isFinite(override)) targetGroupId = override;
    }
    if (!Number.isFinite(targetGroupId)) return res.status(400).json({ message: 'A valid group_id is required for branding.' });
    if (req.user.role === 'admin' && Number(req.user.group_id) !== targetGroupId) {
      return res.status(403).json({ message: 'Admins can only edit branding for their organization.' });
    }
    const payload = BRANDING_COLUMNS.map(col => {
      const val = req.body?.[col];
      if (val == null || val === '') return null;
      return String(val).trim();
    });
    const assignments = BRANDING_COLUMNS.map(col => `${col}=EXCLUDED.${col}`).join(', ');
    await pool.query(
      `INSERT INTO group_branding (group_id, ${BRANDING_COLUMNS.join(', ')})
       VALUES ($1${BRANDING_COLUMNS.map((_, idx) => `,$${idx + 2}`).join('')})
       ON CONFLICT (group_id) DO UPDATE SET ${assignments}, updated_at=NOW()`,
      [targetGroupId, ...payload]
    );
    res.json({ group_id: targetGroupId, branding: req.body || {} });
  } catch (err) {
    res.status(400).json({ message: err?.message || 'Failed to save branding' });
  }
});

app.delete('/branding', authRequired, adminOnly, async (req, res) => {
  try {
    let targetGroupId = Number(req.user.group_id);
    if (req.user.role === 'superadmin' && req.body?.group_id != null) {
      const override = Number(req.body.group_id);
      if (Number.isFinite(override)) targetGroupId = override;
    }
    if (!Number.isFinite(targetGroupId)) return res.status(400).json({ message: 'A valid group_id is required for branding.' });
    if (req.user.role === 'admin' && Number(req.user.group_id) !== targetGroupId) {
      return res.status(403).json({ message: 'Admins can only reset branding for their organization.' });
    }
    await pool.query('DELETE FROM group_branding WHERE group_id=$1', [targetGroupId]);
    res.json({ group_id: targetGroupId, cleared: true });
  } catch (err) {
    res.status(400).json({ message: err?.message || 'Failed to reset branding' });
  }
});

app.post('/branding/upload', authRequired, adminOnly, brandingMemoryUpload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const target = String(req.body?.target || '').toLowerCase();
    const meta = getBrandingAssetColumn(target);
    if (!meta) {
      return res.status(400).json({ message: 'Invalid target. Expected logo, banner, or footer.' });
    }
    let targetGroupId = Number(req.user.group_id);
    if (req.user.role === 'superadmin' && req.body?.group_id != null) {
      const override = Number(req.body.group_id);
      if (Number.isFinite(override)) targetGroupId = override;
    }
    if (!Number.isFinite(targetGroupId)) return res.status(400).json({ message: 'A valid group_id is required.' });
    if (req.user.role === 'admin' && Number(req.user.group_id) !== targetGroupId) {
      return res.status(403).json({ message: 'Admins can only upload branding for their organization.' });
    }
    await pool.query(
      `INSERT INTO group_branding (group_id, ${meta.blob}, ${meta.type}, ${meta.updated})
       VALUES ($1,$2,$3,NOW())
       ON CONFLICT (group_id) DO UPDATE SET
         ${meta.blob}=EXCLUDED.${meta.blob},
         ${meta.type}=EXCLUDED.${meta.type},
         ${meta.updated}=NOW()`,
      [targetGroupId, req.file.buffer, req.file.mimetype || 'application/octet-stream']
    );
    res.json({ ok: true, target });
  } catch (err) {
    console.error('Branding upload failed:', err);
    res.status(400).json({ message: err?.message || 'Failed to upload image' });
  }
});

app.get('/branding/assets/:target', async (req, res) => {
  try {
    const target = String(req.params.target || '').toLowerCase();
    const meta = getBrandingAssetColumn(target);
    if (!meta) return res.status(400).json({ message: 'Invalid asset type' });
    const targetGroupId = Number(req.query.group_id);
    if (!Number.isFinite(targetGroupId)) return res.status(400).json({ message: 'Missing group context' });
    const result = await pool.query(
      `SELECT ${meta.blob} AS blob, ${meta.type} AS mime FROM group_branding WHERE group_id=$1`,
      [targetGroupId]
    );
    if (result.rowCount === 0 || !result.rows[0].blob) return res.status(404).json({ message: 'Asset not found' });
    const row = result.rows[0];
    res.setHeader('Content-Type', row.mime || 'application/octet-stream');
    res.setHeader('Cache-Control', 'private, max-age=604800');
    res.send(row.blob);
  } catch (err) {
    res.status(500).json({ message: err?.message || 'Failed to load asset' });
  }
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
    const { title, description, event_date, start_date, end_date, start_time, end_time, color_hex, address } = req.body || {};
    let { group_id } = req.body || {};
    if (!group_id) group_id = req.user.group_id || null;
    if (!group_id) return res.status(400).json({ message: 'Group is required for events' });
    const result = await pool.query(
      'INSERT INTO events (title,description,event_date,start_date,end_date,start_time,end_time,color_hex,address,group_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id',
      [title, description ?? null, event_date ?? null, start_date ?? null, end_date ?? null, start_time ?? null, end_time ?? null, color_hex ?? null, address ?? null, group_id]
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
    const { title, description, event_date, start_date, end_date, start_time, end_time, group_id, color_hex, address } = req.body || {};
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
    if (color_hex !== undefined) { setClauses.push(`color_hex = $${idx++}`); params.push(color_hex ?? null); }
    if (address !== undefined) { setClauses.push(`address = $${idx++}`); params.push(address ?? null); }
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

// Duty templates (saved duty "pool")
app.get('/duty-templates', authRequired, async (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).json({ message: 'Admins only' });
  try {
    const clauses = [];
    const params = [];
    if (req.user.role === 'admin') {
      const gid = Number(req.user.group_id);
      if (!Number.isFinite(gid)) {
        return res.status(400).json({ message: 'Admins must belong to an organization to use duty templates.' });
      }
      clauses.push(`dt.group_id = $${params.length + 1}`);
      params.push(gid);
    } else {
      const groupFilter = req.query.group_id ? Number(req.query.group_id) : null;
      if (Number.isFinite(groupFilter)) {
        clauses.push(`dt.group_id = $${params.length + 1}`);
        params.push(groupFilter);
      }
    }
    const sql = `
      SELECT dt.*, g.name AS group_name
      FROM duty_templates dt
      LEFT JOIN groups g ON g.id = dt.group_id
      ${clauses.length ? 'WHERE ' + clauses.join(' AND ') : ''}
      ORDER BY g.name NULLS LAST, dt.title, dt.id
    `;
    const templates = await pool.query(sql, params);
    res.json(templates.rows);
  } catch (err) {
    res.status(400).json({ message: err?.message || 'Failed to load duty templates' });
  }
});

app.post('/duty-templates', authRequired, async (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).json({ message: 'Admins only' });
  try {
    const { title, description, status, max_volunteers, group_id } = req.body || {};
    if (!title || !String(title).trim()) {
      return res.status(400).json({ message: 'Title is required' });
    }
    let targetGroupId = req.user.role === 'superadmin' ? (group_id ?? null) : req.user.group_id;
    if (targetGroupId != null) targetGroupId = Number(targetGroupId);
    if (!Number.isFinite(targetGroupId)) {
      return res.status(400).json({ message: 'Organization is required for saved duties' });
    }
    const statusMap = { open: 'pending', closed: 'completed', complete: 'completed', completed: 'completed' };
    let normalizedStatus = String(status ?? '').toLowerCase();
    normalizedStatus = normalizedStatus || 'pending';
    normalizedStatus = statusMap[normalizedStatus] || normalizedStatus;
    if (!['pending','in_progress','completed'].includes(normalizedStatus)) normalizedStatus = 'pending';
    let maxVol = null;
    if (max_volunteers !== undefined && max_volunteers !== null && max_volunteers !== '') {
      maxVol = Number(max_volunteers);
      if (!Number.isFinite(maxVol) || maxVol < 1) {
        return res.status(400).json({ message: 'max_volunteers must be a positive number' });
      }
      maxVol = Math.floor(maxVol);
    }
    const result = await pool.query(
      `INSERT INTO duty_templates (title, description, status, max_volunteers, group_id, created_by, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,NOW())
       RETURNING *`,
      [String(title).trim(), description ?? null, normalizedStatus, maxVol, targetGroupId, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ message: err?.message || 'Failed to save duty template' });
  }
});

// --- Duties
app.get('/duties', authRequired, async (req, res) => {
  const baseSelect = `
    SELECT d.*,
      COALESCE((SELECT COUNT(*) FROM time_tracking t WHERE t.duty_id = d.id AND t.end_time IS NULL), 0) AS active_assignments
    FROM duties d
  `;
  if (req.user.role === 'superadmin') {
    const groupFilter = req.query.group_id ? Number(req.query.group_id) : null;
    if (Number.isFinite(groupFilter)) {
      const duties = await pool.query(`${baseSelect} WHERE d.group_id=$1 AND d.archived_at IS NULL ORDER BY d.id`, [groupFilter]);
      return res.json(duties.rows);
    }
    const duties = await pool.query(`${baseSelect} WHERE d.archived_at IS NULL ORDER BY d.id`);
    return res.json(duties.rows);
  }
  if (req.user.role === 'admin') {
    const duties = await pool.query(
      `${baseSelect} WHERE d.group_id=$1 AND d.archived_at IS NULL ORDER BY d.id`,
      [req.user.group_id]
    );
    return res.json(duties.rows);
  }
  const duties = await pool.query(
    `${baseSelect}
     WHERE d.group_id=$1 AND d.archived_at IS NULL
       AND NOT EXISTS (
         SELECT 1 FROM duty_restrictions dr
         WHERE dr.duty_id = d.id AND dr.volunteer_id = $2
       )
     ORDER BY d.id`,
    [req.user.group_id, req.user.id]
  );
  res.json(duties.rows);
});

app.post('/duties', authRequired, async (req, res) => {
  try {
    const { title, description, status, group_id, event_id, max_volunteers, location } = req.body || {};
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

    let maxVol = null;
    if (max_volunteers !== undefined && max_volunteers !== null && max_volunteers !== '') {
      maxVol = Number(max_volunteers);
      if (!Number.isFinite(maxVol) || maxVol < 1) {
        return res.status(400).json({ message: 'max_volunteers must be a positive number' });
      }
      maxVol = Math.floor(maxVol);
    }

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
    if (has.has('max_volunteers')) { fields.push('max_volunteers'); params.push(`$${idx++}`); values.push(maxVol); }
    if (has.has('location')) { fields.push('location'); params.push(`$${idx++}`); values.push(location ?? null); }

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
    const { title, description, status, event_id, group_id, max_volunteers, location } = req.body || {};
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
    if (max_volunteers !== undefined && has.has('max_volunteers')) {
      let normalized = null;
      if (max_volunteers !== null && max_volunteers !== '') {
        normalized = Number(max_volunteers);
        if (!Number.isFinite(normalized) || normalized < 1) {
          return res.status(400).json({ message: 'max_volunteers must be a positive number' });
        }
        normalized = Math.floor(normalized);
      }
      setClauses.push(`max_volunteers=$${idx++}`); params.push(normalized);
    }
    if (location !== undefined && has.has('location')) {
      setClauses.push(`location=$${idx++}`); params.push(location ?? null);
    }
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
    await ensureDurationHoursColumn();
    await ensureTimeTrackingConstraints();
    await ensureTimeTrackingEventColumn();
    const dutyId = Number(req.params.id);
    if (!Number.isFinite(dutyId)) return res.status(400).json({ message: 'Invalid duty id' });
    const dutyRes = await pool.query('SELECT max_volunteers, event_id FROM duties WHERE id=$1 AND archived_at IS NULL', [dutyId]);
    if (dutyRes.rowCount === 0) return res.status(404).json({ message: 'Duty not found' });
    const maxVol = dutyRes.rows[0].max_volunteers;
    const dutyEventId = dutyRes.rows[0].event_id || null;
    if (maxVol != null && Number.isFinite(Number(maxVol)) && Number(maxVol) > 0) {
      const activeRes = await pool.query('SELECT COUNT(*) FROM time_tracking WHERE duty_id=$1 AND end_time IS NULL', [dutyId]);
      const activeCount = Number(activeRes.rows[0].count || 0);
      if (activeCount >= Number(maxVol)) {
        return res.status(400).json({ message: 'This duty already has the maximum number of volunteers clocked in.' });
      }
    }
    const { duty_date } = req.body;
    const result = await pool.query(
      'INSERT INTO time_tracking (volunteer_id,duty_id,event_id,start_time,duty_date) VALUES ($1,$2,$3,NOW(),$4) RETURNING id',
      [req.user.id, dutyId, dutyEventId, duty_date]
    );
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.post('/duties/:id/time/end', authRequired, async (req, res) => {
  try {
    await ensureDurationHoursColumn();
    await ensureTimeTrackingConstraints();
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
  await ensureTimeTrackingEventColumn();
  const volunteerFilter = req.query.volunteer_id ? Number(req.query.volunteer_id) : null;
  const groupFilter = req.query.group_id ? Number(req.query.group_id) : null;
  const baseSelect = `
    SELECT t.*,
           u.name AS volunteer_name,
           u.email AS volunteer_email,
           d.title AS duty_title,
           d.event_id AS duty_event_id,
           ev.title AS event_title,
           COALESCE(t.event_id, d.event_id) AS resolved_event_id
    FROM time_tracking t
    LEFT JOIN users u ON u.id = t.volunteer_id
    LEFT JOIN duties d ON d.id = t.duty_id
    LEFT JOIN events ev ON ev.id = COALESCE(t.event_id, d.event_id)
  `;

  const orderClause = ' ORDER BY t.start_time DESC';

  if (req.user.role === 'superadmin') {
    if (Number.isFinite(volunteerFilter)) {
      const rows = await pool.query(
        `${baseSelect} WHERE t.volunteer_id=$1${orderClause}`,
        [volunteerFilter]
      );
      return res.json(rows.rows);
    }
    if (Number.isFinite(groupFilter)) {
      const rows = await pool.query(
        `${baseSelect} WHERE u.group_id = $1${orderClause}`,
        [groupFilter]
      );
      return res.json(rows.rows);
    }
    const rows = await pool.query(`${baseSelect}${orderClause}`);
    return res.json(rows.rows);
  }

  if (req.user.role === 'admin') {
    if (Number.isFinite(volunteerFilter)) {
      const ok = await pool.query('SELECT 1 FROM users WHERE id=$1 AND group_id=$2', [volunteerFilter, req.user.group_id]);
      if (ok.rowCount === 0) return res.status(403).json({ message: 'Forbidden' });
      const rows = await pool.query(
        `${baseSelect} WHERE t.volunteer_id=$1${orderClause}`,
        [volunteerFilter]
      );
      return res.json(rows.rows);
    }
    const rows = await pool.query(
      `${baseSelect} WHERE u.group_id = $1${orderClause}`,
      [req.user.group_id]
    );
    return res.json(rows.rows);
  }

  const rows = await pool.query(
    `${baseSelect} WHERE t.volunteer_id=$1${orderClause}`,
    [req.user.id]
  );
  res.json(rows.rows);
});

// CSV export
app.get('/time-tracking.csv', authRequired, async (req, res) => {
  try {
    await ensureTimeTrackingApprovalColumn();
    const volunteerFilters = []
      .concat(req.query.volunteer_id ?? [])
      .concat(req.query.volunteer_ids ?? []);
    const parsedVolunteerIds = volunteerFilters
      .flatMap(val => String(val ?? '')
        .split(',')
        .map(v => Number(v.trim()))
      )
      .filter(id => Number.isFinite(id));
    const approvedOnly = String(req.query.approved_only || '').toLowerCase() === 'true';
    let rows;
    if (req.user.role === 'superadmin') {
      const clauses = [];
      const params = [];
      if (parsedVolunteerIds.length) {
        clauses.push(`t.volunteer_id = ANY($${params.length + 1}::int[])`);
        params.push(parsedVolunteerIds);
      }
      if (approvedOnly) clauses.push('t.approved = true');
      const whereSql = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
      rows = (await pool.query(
        `SELECT t.*, d.event_id AS duty_event_id,
                u.name AS volunteer_name,
                u.email AS volunteer_email,
                d.title AS duty_title,
                ev.title AS event_title
         FROM time_tracking t
         LEFT JOIN duties d ON d.id = t.duty_id
         LEFT JOIN users u ON u.id = t.volunteer_id
         LEFT JOIN events ev ON ev.id = COALESCE(t.event_id, d.event_id)
         ${whereSql}
         ORDER BY t.start_time DESC`,
        params
      )).rows;
    } else if (req.user.role === 'admin') {
      const params = [req.user.group_id];
      const clauses = ['u.group_id = $1'];
      if (parsedVolunteerIds.length) {
        clauses.push(`t.volunteer_id = ANY($${params.length + 1}::int[])`);
        params.push(parsedVolunteerIds);
      }
      if (approvedOnly) clauses.push('t.approved = true');
      rows = (await pool.query(
        `SELECT t.*, d.event_id AS duty_event_id,
                u.name AS volunteer_name,
                u.email AS volunteer_email,
                d.title AS duty_title,
                ev.title AS event_title
         FROM time_tracking t
         JOIN users u ON u.id = t.volunteer_id
         LEFT JOIN duties d ON d.id = t.duty_id
         LEFT JOIN events ev ON ev.id = COALESCE(t.event_id, d.event_id)
         WHERE ${clauses.join(' AND ')}
         ORDER BY t.start_time DESC`,
        params
      )).rows;
    } else {
      const params = [req.user.id];
      const clauses = ['t.volunteer_id = $1'];
      if (approvedOnly) clauses.push('t.approved = true');
      rows = (await pool.query(
        `SELECT t.*, d.event_id AS duty_event_id,
                u.name AS volunteer_name,
                u.email AS volunteer_email,
                d.title AS duty_title,
                ev.title AS event_title
         FROM time_tracking t
         LEFT JOIN duties d ON d.id = t.duty_id
         LEFT JOIN users u ON u.id = t.volunteer_id
         LEFT JOIN events ev ON ev.id = COALESCE(t.event_id, d.event_id)
         WHERE ${clauses.join(' AND ')}
         ORDER BY t.start_time DESC`,
        params
      )).rows;
    }
    if (req.user.role !== 'superadmin' && parsedVolunteerIds.length) {
      rows = rows.filter(r => parsedVolunteerIds.includes(Number(r.volunteer_id)));
    }
    rows.forEach(r => {
      if ((r.event_id == null || r.event_id === undefined) && r.duty_event_id != null) {
        r.event_id = r.duty_event_id;
      }
    });
    const format12Hour = iso => {
      if (!iso) return '';
      try {
        return new Intl.DateTimeFormat('en-US', {
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: true,
          timeZone: 'UTC'
        }).format(new Date(iso));
      } catch { return iso; }
    };
    const formatCell = value => {
      if (value == null) return '';
      return String(value).replace(/"/g, '""');
    };
    const header = ['Log ID','Volunteer','Duty','Event ID','Event Name','Start Time','End Time','Hours','Duty Date','Approved'];
    const body = rows.map(r => {
      const volunteerLabel = r.volunteer_name
        ? `${r.volunteer_name} (${r.volunteer_email || 'no email'})`
        : (r.volunteer_email || `Volunteer #${r.volunteer_id}`);
      const dutyLabel = r.duty_title ? `${r.duty_title} (#${r.duty_id || 'N/A'})` : (r.duty_id != null ? `Duty #${r.duty_id}` : '');
      const eventLabel = r.event_title || '';
      return [
        formatCell(r.id),
        formatCell(volunteerLabel),
        formatCell(dutyLabel),
        formatCell(r.event_id ?? ''),
        formatCell(eventLabel || ''),
        formatCell(format12Hour(r.start_time)),
        formatCell(format12Hour(r.end_time)),
        formatCell(r.duration_hours != null ? Number(r.duration_hours).toFixed(2) : ''),
        formatCell(r.duty_date || ''),
        formatCell(r.approved ? 'Yes' : 'No')
      ].map(v => `"${v}"`).join(',');
    });
    const csv = [header.map(v => `"${v}"`).join(','), ...body].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="time-tracking.csv"');
    res.send(csv);
  } catch (err) {
    console.error('Error generating time-tracking CSV:', err);
    res.status(500).json({ message: 'Failed to export CSV', error: err?.message || 'Unknown error' });
  }
});

// Calendar-friendly schedule snapshot for a single date
app.get('/calendar/assignments', authRequired, async (req, res) => {
  try {
    await ensureDutyDateColumn();
    const rawDate = String(req.query.date || '').trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(rawDate)) {
      return res.status(400).json({ message: 'A date parameter in YYYY-MM-DD format is required.' });
    }

    const params = [rawDate];
    const where = ['t.duty_date = $1'];
    let idx = 2;
    let scopedGroupId = null;

    if (req.user.role === 'volunteer') {
      where.push(`t.volunteer_id = $${idx++}`);
      params.push(req.user.id);
    } else if (req.user.role === 'admin') {
      const gid = Number(req.user.group_id);
      if (!Number.isFinite(gid)) {
        return res.status(400).json({ message: 'Admins must belong to an organization to view schedules.' });
      }
      where.push(`d.group_id = $${idx++}`);
      params.push(gid);
      scopedGroupId = gid;
    } else if (req.user.role === 'superadmin') {
      const gid = Number(req.query.group_id);
      if (!Number.isFinite(gid)) {
        return res.status(400).json({ message: 'Select an organization to view volunteer schedules.' });
      }
      where.push(`d.group_id = $${idx++}`);
      params.push(gid);
      scopedGroupId = gid;
    } else {
      return res.status(403).json({ message: 'Unsupported role for schedule view.' });
    }

    const sql = `
      SELECT
        t.id AS time_tracking_id,
        t.volunteer_id,
        COALESCE(u.name, p.name, u.email, 'Volunteer #' || u.id::text) AS volunteer_name,
        u.email AS volunteer_email,
        t.start_time,
        t.end_time,
        t.duty_date,
        d.id AS duty_id,
        d.title AS duty_title,
        d.location AS duty_location,
        d.max_volunteers,
        d.group_id,
        e.id AS event_id,
        e.title AS event_title,
        e.color_hex AS event_color_hex,
        e.start_date AS event_start_date,
        e.end_date AS event_end_date,
        e.start_time AS event_start_time,
        e.end_time AS event_end_time,
        e.address AS event_address
      FROM time_tracking t
      JOIN duties d ON d.id = t.duty_id
      LEFT JOIN events e ON e.id = d.event_id
      LEFT JOIN users u ON u.id = t.volunteer_id
      LEFT JOIN user_profile p ON p.user_id = u.id
      WHERE ${where.join(' AND ')}
      ORDER BY
        COALESCE(t.start_time, (t.duty_date::timestamp)),
        e.title NULLS LAST,
        d.title,
        volunteer_name
    `;

    const rows = (await pool.query(sql, params)).rows;
    const events = [];
    const eventMap = new Map();

    rows.forEach(row => {
      const eventKey = row.event_id ? `event-${row.event_id}` : `duty-${row.duty_id}`;
      let eventEntry = eventMap.get(eventKey);
      if (!eventEntry) {
        eventEntry = {
          event_id: row.event_id,
          title: row.event_title || row.duty_title || 'Untitled Event',
          color_hex: row.event_color_hex || null,
          group_id: row.group_id,
          start_date: row.event_start_date,
          end_date: row.event_end_date,
          start_time: row.event_start_time,
          end_time: row.event_end_time,
          address: row.event_address || null,
          duties: [],
        };
        eventMap.set(eventKey, eventEntry);
        events.push(eventEntry);
      }
      let dutyEntry = eventEntry.duties.find(d => d.id === row.duty_id);
      if (!dutyEntry) {
        dutyEntry = {
          id: row.duty_id,
          title: row.duty_title,
          location: row.duty_location || null,
          max_volunteers: row.max_volunteers,
          assignments: [],
        };
        eventEntry.duties.push(dutyEntry);
      }
      dutyEntry.assignments.push({
        time_tracking_id: row.time_tracking_id,
        volunteer_id: row.volunteer_id,
        volunteer_name: row.volunteer_name || row.volunteer_email || (row.volunteer_id ? `Volunteer #${row.volunteer_id}` : 'Volunteer'),
        volunteer_email: row.volunteer_email || null,
        start_time: row.start_time,
        end_time: row.end_time,
        duty_date: row.duty_date,
      });
    });

    if (scopedGroupId == null && rows.length && rows[0].group_id != null) {
      scopedGroupId = rows[0].group_id;
    }

    res.json({
      date: rawDate,
      group_id: scopedGroupId,
      events,
      total_assignments: rows.length,
    });
  } catch (err) {
    res.status(500).json({ message: err?.message || 'Failed to load calendar assignments' });
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
    await ensureDurationHoursColumn();
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
    await ensureDurationHoursColumn();
    await ensureTimeTrackingConstraints();
    await ensureTimeTrackingEventColumn();
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
    const dutyRes = await pool.query('SELECT id, group_id, event_id FROM duties WHERE id=$1', [dutyIdNum]);
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
    const dutyEventId = dutyRes.rows[0].event_id || null;
    const result = await pool.query(
      `INSERT INTO time_tracking (volunteer_id,duty_id,event_id,start_time,end_time,duty_date)
       VALUES ($1,$2,$3,$4::timestamp,$5::timestamp,$6::date) RETURNING id`,
      [volunteerIdNum, dutyIdNum, dutyEventId, start_time, end_time || null, duty_date || null]
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

// Duty restrictions management
app.get('/duties/:id/restrictions', authRequired, async (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).json({ message: 'Admins only' });
  const dutyId = Number(req.params.id);
  if (!Number.isFinite(dutyId)) return res.status(400).json({ message: 'Invalid id' });
  const duty = await pool.query('SELECT id, group_id FROM duties WHERE id=$1', [dutyId]);
  if (duty.rowCount === 0) return res.status(404).json({ message: 'Duty not found' });
  if (req.user.role === 'admin' && duty.rows[0].group_id !== req.user.group_id) {
    return res.status(403).json({ message: 'Admins can only manage duties in their organization.' });
  }
  const rows = await pool.query(
    `SELECT u.id, COALESCE(u.name, p.name) AS name, u.email
     FROM duty_restrictions dr
     JOIN users u ON u.id = dr.volunteer_id
     LEFT JOIN user_profile p ON p.user_id = u.id
     WHERE dr.duty_id=$1
     ORDER BY COALESCE(u.name, p.name, u.email, u.id::text)`,
    [dutyId]
  );
  res.json(rows.rows);
});

app.post('/duties/:id/restrictions', authRequired, async (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).json({ message: 'Admins only' });
  const dutyId = Number(req.params.id);
  if (!Number.isFinite(dutyId)) return res.status(400).json({ message: 'Invalid id' });
  const { volunteer_id } = req.body || {};
  const volunteerIdNum = Number(volunteer_id);
  if (!Number.isFinite(volunteerIdNum)) return res.status(400).json({ message: 'Invalid volunteer_id' });
  const duty = await pool.query('SELECT id, group_id FROM duties WHERE id=$1', [dutyId]);
  if (duty.rowCount === 0) return res.status(404).json({ message: 'Duty not found' });
  if (req.user.role === 'admin' && duty.rows[0].group_id !== req.user.group_id) {
    return res.status(403).json({ message: 'Admins can only manage duties in their organization.' });
  }
  const volunteerRes = await pool.query('SELECT id, role, group_id FROM users WHERE id=$1', [volunteerIdNum]);
  if (volunteerRes.rowCount === 0 || String(volunteerRes.rows[0].role || '').toLowerCase() !== 'volunteer') {
    return res.status(404).json({ message: 'Volunteer not found' });
  }
  if (req.user.role === 'admin' && volunteerRes.rows[0].group_id !== req.user.group_id) {
    return res.status(403).json({ message: 'Admins can only manage volunteers in their organization.' });
  }
  if (req.user.role === 'superadmin') {
    const dutyGroup = duty.rows[0].group_id;
    const volunteerGroup = volunteerRes.rows[0].group_id;
    if (dutyGroup != null && volunteerGroup != null && dutyGroup !== volunteerGroup) {
      return res.status(400).json({ message: 'Volunteer must belong to the same organization as the duty.' });
    }
  }
  await pool.query(
    'INSERT INTO duty_restrictions (duty_id, volunteer_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
    [dutyId, volunteerIdNum]
  );
  res.json({ ok: true });
});

app.delete('/duties/:id/restrictions/:volunteerId', authRequired, async (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).json({ message: 'Admins only' });
  const dutyId = Number(req.params.id);
  const volunteerId = Number(req.params.volunteerId);
  if (!Number.isFinite(dutyId) || !Number.isFinite(volunteerId)) return res.status(400).json({ message: 'Invalid id' });
  const duty = await pool.query('SELECT id, group_id FROM duties WHERE id=$1', [dutyId]);
  if (duty.rowCount === 0) return res.status(404).json({ message: 'Duty not found' });
  if (req.user.role === 'admin' && duty.rows[0].group_id !== req.user.group_id) {
    return res.status(403).json({ message: 'Admins can only manage duties in their organization.' });
  }
  await pool.query('DELETE FROM duty_restrictions WHERE duty_id=$1 AND volunteer_id=$2', [dutyId, volunteerId]);
  res.json({ ok: true });
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
  await ensureTimeTrackingApprovalColumn();
  const rows = await pool.query('SELECT * FROM time_tracking WHERE approved=false');
  res.json(rows.rows);
});

app.post('/approvals/:id/approve', authRequired, adminOnly, async (req, res) => {
  await ensureTimeTrackingApprovalColumn();
  await pool.query('UPDATE time_tracking SET approved=true WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// Alias to match frontend POST /time-tracking/:id/approve
app.post('/time-tracking/:id/approve', authRequired, adminOnly, async (req, res) => {
  await ensureTimeTrackingApprovalColumn();
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

function getBrandingAssetColumn(target) {
  const map = {
    logo: { blob: 'logo_blob', type: 'logo_blob_type', updated: 'logo_blob_updated_at', urlKey: 'logo_url' },
    banner: { blob: 'banner_blob', type: 'banner_blob_type', updated: 'banner_blob_updated_at', urlKey: 'banner_url' },
    hero: { blob: 'hero_blob', type: 'hero_blob_type', updated: 'hero_blob_updated_at', urlKey: 'hero_url' },
    footer: { blob: 'footer_blob', type: 'footer_blob_type', updated: 'footer_blob_updated_at', urlKey: 'footer_url' }
  };
  return map[target] || null;
}

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
