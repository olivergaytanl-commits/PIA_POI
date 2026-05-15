require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

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

// ── Almacenamiento de usuarios conectados para video ─────────────────────────
const connectedUsers = new Map(); // userId -> socketId
const userDetails = new Map(); // socketId -> { userId, userName }

// ══════════════════════════════════════════════════════════════════════════════
//  SOCKET.IO PARA VIDEOLLAMADAS (VERSIÓN CORREGIDA)
// ══════════════════════════════════════════════════════════════════════════════
io.on('connection', (socket) => {
  console.log('🔌 Nuevo cliente conectado:', socket.id);

  // Registrar usuario
  socket.on('register-user', ({ userId, userName }) => {
    connectedUsers.set(userId, socket.id);
    userDetails.set(socket.id, { userId, userName });
    console.log(`👤 Usuario registrado: ${userName} (${userId})`);
    console.log('Usuarios conectados:', Array.from(connectedUsers.keys()));
  });

  // Iniciar videollamada (el que llama)
  socket.on('call-user', ({ to, from, signalData }) => {
    console.log(`📞 ${from} está llamando a ${to}`);
    const targetSocketId = connectedUsers.get(to);
    
    if (targetSocketId) {
      // Enviar la señal al usuario que recibe la llamada
      io.to(targetSocketId).emit('incoming-call', {
        from: { userId: from, userName: userDetails.get(socket.id)?.userName || 'Usuario' },
        signal: signalData
      });
      console.log(`✅ Señal de llamada enviada a ${to}`);
    } else {
      socket.emit('user-offline', { userId: to });
      console.log(`❌ Usuario ${to} no está conectado`);
    }
  });

  // Aceptar llamada (el que responde)
  socket.on('accept-call', ({ to, signal }) => {
    console.log(`✅ ${socket.id} aceptó la llamada de ${to}`);
    const targetSocketId = connectedUsers.get(to);
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('call-accepted', { signal });
      console.log(`📡 Answer enviado a ${to}`);
    }
  });

  // ICE Candidate del que llama
  socket.on('ice-candidate-caller', ({ to, candidate }) => {
    const targetSocketId = connectedUsers.get(to);
    if (targetSocketId) {
      io.to(targetSocketId).emit('ice-candidate-from-caller', { candidate });
      console.log(`🔄 ICE candidate enviado del caller al callee`);
    }
  });

  // ICE Candidate del que recibe
  socket.on('ice-candidate-callee', ({ to, candidate }) => {
    const targetSocketId = connectedUsers.get(to);
    if (targetSocketId) {
      io.to(targetSocketId).emit('ice-candidate-from-callee', { candidate });
      console.log(`🔄 ICE candidate enviado del callee al caller`);
    }
  });

  // Rechazar llamada
  socket.on('reject-call', ({ to }) => {
    const targetSocketId = connectedUsers.get(to);
    if (targetSocketId) {
      io.to(targetSocketId).emit('call-rejected');
      console.log(`❌ Llamada rechazada`);
    }
  });

  // Colgar llamada
  socket.on('hangup', ({ to }) => {
    const targetSocketId = connectedUsers.get(to);
    if (targetSocketId) {
      io.to(targetSocketId).emit('call-ended');
      console.log(`🔴 Llamada finalizada`);
    }
  });

  // Desconexión
  socket.on('disconnect', () => {
    const user = userDetails.get(socket.id);
    if (user) {
      console.log(`👋 Usuario desconectado: ${user.userName}`);
      connectedUsers.delete(user.userId);
      userDetails.delete(socket.id);
    }
  });
});

// Helper para obtener socketId por userId
function getSocketIdByUserId(userId) {
  return connectedUsers.get(userId);
}

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

app.post('/api/register', async (req, res) => {
  const { full_name, email, password, img_profile } = req.body;

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
    .insert([{ full_name, email, password: hashed, img_profile: img_profile || null }])
    .select('id, full_name, email, img_profile')
    .single();

  if (error) return res.status(500).json({ error: error.message });

  const token = jwt.sign(
    { id: data.id, email: data.email, full_name: data.full_name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.status(201).json({ user: data, token });
});

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
  res.json({ user: { id: user.id, full_name: user.full_name, email: user.email, img_profile: user.img_profile }, token });
});

// ══════════════════════════════════════════════════════════════════════════════
//  USUARIOS
// ══════════════════════════════════════════════════════════════════════════════

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
//  PUBLICACIONES
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/publicaciones', authMiddleware, async (req, res) => {
  const { titulo, datos, categoria, media_url } = req.body;

  if (!titulo || !datos || !categoria)
    return res.status(400).json({ error: 'Título, datos y categoría son obligatorios' });

  const { data, error } = await supabase
    .from('publicaciones')
    .insert([{
      user_id:   req.user.id,
      titulo,
      datos,
      categoria,
      media_url: media_url || null
    }])
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

app.get('/api/publicaciones', authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('publicaciones')
    .select('*, users(full_name, img_profile)')
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════════════════════════════════════════
//  TAREAS INDIVIDUALES
// ══════════════════════════════════════════════════════════════════════════════

// OBTENER TAREAS DEL USUARIO
app.get('/api/tareas', authMiddleware, async (req, res) => {

  try {

    // TAREAS DEL USUARIO
    const { data: tareasUsuario, error: err1 } = await supabase
      .from('tareas_usuarios')
      .select('*')
      .eq('usuario_id', req.user.id);

    if (err1) {

      console.log(err1);

      return res.status(500).json({
        error: err1.message
      });

    }

    // IDS DE TAREAS
    const ids = tareasUsuario.map(t => t.tarea_id);

    if (ids.length === 0) {
      return res.json([]);
    }

    // OBTENER INFO DE TAREAS
    const { data: tareas, error: err2 } = await supabase
      .from('tareas')
      .select('*')
      .in('id', ids);

    if (err2) {

      console.log(err2);

      return res.status(500).json({
        error: err2.message
      });

    }

    // COMBINAR
    const resultado = tareasUsuario.map(tu => {

      const tarea = tareas.find(t => t.id === tu.tarea_id);

      return {

        ...tu,
        tareas: tarea

      };

    });

    res.json(resultado);

  }

  catch(err) {

    console.log(err);

    res.status(500).json({
      error: 'Error al obtener tareas'
    });

  }

});

// CREAR TAREA GLOBAL
app.post('/api/tareas', authMiddleware, async (req, res) => {

  const {
    titulo,
    descripcion,
    fecha_limite
  } = req.body;

  // CREAR TAREA
  const { data: tarea, error: err1 } = await supabase
    .from('tareas')
    .insert([{

      titulo,
      descripcion,
      fecha_limite,
      created_by: req.user.id

    }])
    .select()
    .single();

  if (err1){
    console.log('ERR1:', err1);
    return res.status(500).json({
      error: err1.message
    });
}
  // OBTENER TODOS LOS USUARIOS
  const { data: users, error: err2 } = await supabase
    .from('users')
    .select('id');

  if (err2){
    console.log('ERR2:', err2);
    return res.status(500).json({
      error: err2.message
    });
  }
  // CREAR REGISTRO INDIVIDUAL
  const registros = users.map(u => ({

    tarea_id: tarea.id,
    usuario_id: u.id,
    estado: 'no iniciada'

  }));

  const { error: err3 } = await supabase
    .from('tareas_usuarios')
    .insert(registros);

  if (err3){
    console.log('ERR3:', err3);
    return res.status(500).json({
      error: err3.message
    });
}
  res.status(201).json({
    success: true
  });

});

// CAMBIAR ESTADO INDIVIDUAL
app.put('/api/tareas/:id', authMiddleware, async (req, res) => {

  const { estado } = req.body;

  const { error } = await supabase
    .from('tareas_usuarios')
    .update({ estado })
    .eq('id', req.params.id)
    .eq('usuario_id', req.user.id);

  if (error)
    return res.status(500).json({
      error: error.message
    });

  res.json({
    success: true
  });

});

// ══════════════════════════════════════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════════════════════════════════════
server.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
  console.log(`📹 Video calls habilitado con Socket.IO`);
});