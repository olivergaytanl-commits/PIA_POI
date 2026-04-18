require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Supabase ──────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// ── Helper: verificar JWT ─────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { full_name, email, password } = req.body;
  if (!full_name || !email || !password)
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });

  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('email', email)
    .single();

  if (existing) return res.status(409).json({ error: 'El email ya está registrado' });

  const hashed = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from('users')
    .insert([{ full_name, email, password: hashed }])
    .select('id, full_name, email')
    .single();

  if (error) return res.status(500).json({ error: error.message });

  const token = jwt.sign(
    { id: data.id, email: data.email, full_name: data.full_name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.status(201).json({ user: data, token });
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email y contraseña requeridos' });

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !user) return res.status(401).json({ error: 'Credenciales incorrectas' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Credenciales incorrectas' });

  const token = jwt.sign(
    { id: user.id, email: user.email, full_name: user.full_name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ user: { id: user.id, full_name: user.full_name, email: user.email }, token });
});

// ══════════════════════════════════════════════════════════════════════════════
//  USUARIOS
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/users/search?q=nombre
app.get('/api/users/search', authMiddleware, async (req, res) => {
  const q = req.query.q || '';
  const { data, error } = await supabase
    .from('users')
    .select('id, full_name, email')
    .ilike('full_name', `%${q}%`)
    .neq('id', req.user.id)
    .limit(20);

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════════════════════════════════════════
//  AMIGOS
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/friends
app.get('/api/friends', authMiddleware, async (req, res) => {
  const uid = req.user.id;

  const { data, error } = await supabase
    .from('friends')
    .select('id, user1_id, user2_id')
    .or(`user1_id.eq.${uid},user2_id.eq.${uid}`);

  if (error) return res.status(500).json({ error: error.message });

  const friendIds = data.map(f => f.user1_id === uid ? f.user2_id : f.user1_id);
  if (friendIds.length === 0) return res.json([]);

  const { data: users, error: err2 } = await supabase
    .from('users')
    .select('id, full_name, email')
    .in('id', friendIds);

  if (err2) return res.status(500).json({ error: err2.message });
  res.json(users);
});

// POST /api/friends
app.post('/api/friends', authMiddleware, async (req, res) => {
  const uid = req.user.id;
  const { friend_id } = req.body;
  if (!friend_id) return res.status(400).json({ error: 'friend_id requerido' });

  const { data: existing } = await supabase
    .from('friends')
    .select('id')
    .or(`and(user1_id.eq.${uid},user2_id.eq.${friend_id}),and(user1_id.eq.${friend_id},user2_id.eq.${uid})`)
    .single();

  if (existing) return res.status(409).json({ error: 'Ya son amigos' });

  const { data, error } = await supabase
    .from('friends')
    .insert([{ user1_id: uid, user2_id: friend_id }])
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// ══════════════════════════════════════════════════════════════════════════════
//  MENSAJES
// ══════════════════════════════════════════════════════════════════════════════

function buildChatId(id1, id2) {
  return [id1, id2].sort().join('_');
}

// GET /api/messages/:friendId
app.get('/api/messages/:friendId', authMiddleware, async (req, res) => {
  const chat_id = buildChatId(req.user.id, req.params.friendId);

  const { data, error } = await supabase
    .from('messages')
    .select('*')
    .eq('chat_id', chat_id)
    .order('created_at', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// POST /api/messages
app.post('/api/messages', authMiddleware, async (req, res) => {
  const { to_user_id, message } = req.body;
  if (!to_user_id || !message)
    return res.status(400).json({ error: 'to_user_id y message son requeridos' });

  const chat_id = buildChatId(req.user.id, to_user_id);

  const { data, error } = await supabase
    .from('messages')
    .insert([{ chat_id, username: req.user.full_name, message }])
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// ══════════════════════════════════════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
});