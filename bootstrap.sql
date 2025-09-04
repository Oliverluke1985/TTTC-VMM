-- Ensure functions like crypt()/gen_salt() are present
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- GROUPS (orgs)
CREATE TABLE IF NOT EXISTS groups (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT DEFAULT 'active'
);

-- USERS
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  phone TEXT,
  address TEXT,
  password TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('volunteer','admin','superadmin')),
  group_id INTEGER NULL
);

-- EVENTS
CREATE TABLE IF NOT EXISTS events (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  event_date DATE,
  group_id INTEGER REFERENCES groups(id)
);

-- DUTIES
CREATE TABLE IF NOT EXISTS duties (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT DEFAULT 'open',
  group_id INTEGER REFERENCES groups(id)
);

-- TIME TRACKING
CREATE TABLE IF NOT EXISTS time_tracking (
  id SERIAL PRIMARY KEY,
  volunteer_id INTEGER REFERENCES users(id),
  duty_id INTEGER REFERENCES duties(id),
  event_id INTEGER REFERENCES events(id),
  start_time TIMESTAMP,
  end_time TIMESTAMP,
  duration_hours DOUBLE PRECISION,
  duty_date DATE,
  approved BOOLEAN DEFAULT FALSE
);

-- MILESTONES
CREATE TABLE IF NOT EXISTS milestones (
  id SERIAL PRIMARY KEY,
  volunteer_id INTEGER REFERENCES users(id),
  goal_hours INTEGER NOT NULL,
  achieved BOOLEAN DEFAULT FALSE
);

-- WORK PHOTOS (evidence)
CREATE TABLE IF NOT EXISTS work_photos (
  id SERIAL PRIMARY KEY,
  volunteer_id INTEGER REFERENCES users(id),
  duty_id INTEGER REFERENCES duties(id),
  file_path TEXT NOT NULL,
  caption TEXT,
  approved BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);

-- USER THEME PREFERENCES
CREATE TABLE IF NOT EXISTS user_theme (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  primary_color TEXT,
  text_color TEXT,
  accent1 TEXT,
  accent2 TEXT,
  accent3 TEXT,
  accent4 TEXT,
  accent5 TEXT,
  logo_url TEXT,
  bg_image_url TEXT,
  updated_at TIMESTAMP DEFAULT NOW()
);

-- SUPERADMIN SEEDS (Tickets to the City)
INSERT INTO users (name, email, phone, address, password, role, group_id) VALUES
('Oliver Lukach', 'oliver@ticketstothecity.com',  '555-111-2222', 'Main Office', crypt('password123', gen_salt('bf')), 'superadmin', NULL),
('Trusted Admin', 'trusted@ticketstothecity.com', '555-333-4444', 'Main Office', crypt('password123', gen_salt('bf')), 'superadmin', NULL),
('System Superadmin', 'admin@example.com',        NULL,           NULL,         crypt('password123', gen_salt('bf')), 'superadmin', NULL)
ON CONFLICT (email) DO NOTHING;
