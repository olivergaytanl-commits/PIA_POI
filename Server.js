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

    // Marcar como online en la BD
    supabase.from('users')
      .update({ is_online: true })
      .eq('id', userId)
      .then(() => console.log(`🟢 ${userName} marcado online`));
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

      // Marcar como offline con timestamp
      supabase.from('users')
        .update({ is_online: false, last_seen: new Date().toISOString() })
        .eq('id', user.userId)
        .then(() => console.log(`🔴 ${user.userName} marcado offline`));
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

  // Marcar como online al iniciar sesión
  await supabase.from('users')
    .update({ is_online: true })
    .eq('id', user.id);

  res.json({ user: { id: user.id, full_name: user.full_name, email: user.email, img_profile: user.img_profile, banner_url: user.banner_url }, token });
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

// Estado online/offline de un usuario
app.get('/api/users/:id/status', authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('is_online, last_seen')
    .eq('id', req.params.id)
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Logout explícito: marcar offline y guardar last_seen
app.post('/api/logout', authMiddleware, async (req, res) => {
  await supabase.from('users')
    .update({ is_online: false, last_seen: new Date().toISOString() })
    .eq('id', req.user.id);
  res.json({ ok: true });
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
//  CHATS GRUPALES
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/groups', authMiddleware, async (req, res) => {
  const { data: miembros } = await supabase
    .from('grupo_miembros')
    .select('grupo_id')
    .eq('usuario_id', req.user.id);

  const ids = (miembros || []).map(x => x.grupo_id);
  if (!ids.length) return res.json([]);

  const { data, error } = await supabase
    .from('grupos')
    .select('*')
    .in('id', ids)
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/groups', authMiddleware, async (req, res) => {
  const { nombre, miembros } = req.body;

  if (!nombre || !miembros || miembros.length < 2) {
    return res.status(400).json({ error: 'Selecciona mínimo 2 amigos' });
  }

  const { data: grupo, error: groupError } = await supabase
    .from('grupos')
    .insert([{ nombre, creador_id: req.user.id }])
    .select()
    .single();

  if (groupError) {
    return res.status(500).json({ error: groupError.message });
  }

  const ids = [...new Set([req.user.id, ...miembros.map(Number)])];

  const inserts = ids.map(id => ({
    grupo_id: grupo.id,
    usuario_id: id
  }));

  const { error: memError } = await supabase
    .from('grupo_miembros')
    .insert(inserts);

  if (memError) {
    return res.status(500).json({ error: memError.message });
  }

  res.status(201).json(grupo);
});

app.get('/api/groups/:groupId/messages', authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('mensajes_grupo')
    .select('*')
    .eq('grupo_id', req.params.groupId)
    .order('created_at', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/group-messages', authMiddleware, async (req, res) => {
  const { grupo_id, mensaje } = req.body;

  const { data, error } = await supabase
    .from('mensajes_grupo')
    .insert([{
      grupo_id,
      usuario_id: req.user.id,
      username: req.user.full_name,
      mensaje
    }])
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
    .select('*, users(id, full_name, img_profile, banner_url)')
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── Comentarios ──────────────────────────────────────────────────────────────

// GET comentarios de una publicación
app.get('/api/publicaciones/:id/comentarios', authMiddleware, async (req, res) => {
  const pubId = req.params.id;

  // Primero insertamos sin join para verificar que la tabla existe
  const { data, error } = await supabase
    .from('comentarios')
    .select('id, contenido, created_at, user_id')
    .eq('publicacion_id', pubId)
    .order('created_at', { ascending: true });

  if (error) {
    console.error('❌ GET comentarios error:', error);
    return res.status(500).json({ error: error.message, detalle: error });
  }

  // Enriquecer con datos del usuario manualmente
  if (!data.length) return res.json([]);

  const userIds = [...new Set(data.map(c => c.user_id))];
  const { data: usuarios } = await supabase
    .from('users')
    .select('id, full_name, img_profile')
    .in('id', userIds);

  const userMap = {};
  (usuarios || []).forEach(u => { userMap[u.id] = u; });

  const resultado = data.map(c => ({
    ...c,
    users: userMap[c.user_id] || { full_name: 'Usuario', img_profile: null }
  }));

  res.json(resultado);
});

// POST nuevo comentario
app.post('/api/publicaciones/:id/comentarios', authMiddleware, async (req, res) => {
  const pubId = req.params.id;
  const { contenido } = req.body;

  if (!contenido || !contenido.trim())
    return res.status(400).json({ error: 'El comentario no puede estar vacío' });

  // Insertar sin join primero
  const { data: nuevo, error } = await supabase
    .from('comentarios')
    .insert([{
      publicacion_id: parseInt(pubId),
      user_id:        req.user.id,
      contenido:      contenido.trim()
    }])
    .select('id, contenido, created_at, user_id')
    .single();

  if (error) {
    console.error('❌ POST comentario error:', error);
    return res.status(500).json({ error: error.message, detalle: error });
  }

  // Buscar datos del usuario 
  const { data: autor } = await supabase
    .from('users')
    .select('id, full_name, img_profile')
    .eq('id', req.user.id)
    .single();

  res.status(201).json({
    ...nuevo,
    users: autor || { full_name: req.user.full_name, img_profile: null }
  });
});

// Alias /api/amigos -> /api/friends (compatibilidad con el frontend)
app.post('/api/amigos', authMiddleware, async (req, res) => {
  const uid = req.user.id;
  const { friend_id } = req.body;
  if (!friend_id) return res.status(400).json({ error: 'friend_id requerido' });

  const { data: existing } = await supabase
    .from('friends')
    .select('id')
    .or(`and(user1_id.eq.${uid},user2_id.eq.${friend_id}),and(user1_id.eq.${friend_id},user2_id.eq.${uid})`)
    .single();

  if (existing) return res.status(409).json({ error: 'Ya son amigos o solicitud pendiente' });

  const { data, error } = await supabase
    .from('friends')
    .insert([{ user1_id: uid, user2_id: friend_id }])
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// ══════════════════════════════════════════════════════════════════════════════
//  TAREAS INDIVIDUALES
// ══════════════════════════════════════════════════════════════════════════════

// OBTENER TAREAS DEL USUARIO
app.get('/api/tareas', authMiddleware, async (req, res) => {

  const uid = req.user.id;

  try {

    // 1. Tareas donde estoy asignado
    const { data: misAsignaciones, error: e1 } = await supabase
      .from('tareas_usuarios')
      .select('*')
      .eq('usuario_id', uid);
    if (e1) return res.status(500).json({ error: e1.message });

    // 2. Tareas que yo creé (aunque no esté asignado)
    const { data: tareasCreadas, error: e2 } = await supabase
      .from('tareas')
      .select('id')
      .eq('created_by', uid);
    if (e2) return res.status(500).json({ error: e2.message });

    // 3. Unir IDs sin duplicados
    const idsAsignadas = misAsignaciones.map(a => a.tarea_id);
    const idsCreadas   = tareasCreadas.map(t => t.id);
    const todosIds     = [...new Set([...idsAsignadas, ...idsCreadas])];

    if (todosIds.length === 0) return res.json([]);

    // 4. Detalle de cada tarea
    const { data: tareas, error: e3 } = await supabase
      .from('tareas')
      .select('*')
      .in('id', todosIds);
    if (e3) return res.status(500).json({ error: e3.message });

    // 5. Todos los registros de asignación para esas tareas
    const { data: todosAsignados, error: e4 } = await supabase
      .from('tareas_usuarios')
      .select('tarea_id, usuario_id, estado')
      .in('tarea_id', todosIds);
    if (e4) return res.status(500).json({ error: e4.message });

    // 6. Nombres de los usuarios asignados
    const userIds = [...new Set(todosAsignados.map(a => a.usuario_id))];
    let userMap = {};
    if (userIds.length > 0) {
      const { data: usuarios } = await supabase
        .from('users')
        .select('id, full_name')
        .in('id', userIds);
      (usuarios || []).forEach(u => { userMap[u.id] = u.full_name || 'Usuario'; });
    }

    // 7. Construir respuesta
    const resultado = tareas.map(tarea => {
      const miAsignacion     = misAsignaciones.find(a => a.tarea_id === tarea.id);
      const esCreador        = tarea.created_by === uid;

      // Los asignados (no creadores) no ven tareas finalizadas
      if (tarea.estado === 'finalizada' && !esCreador) return null;

      const asignadosDeTarea = todosAsignados
        .filter(a => a.tarea_id === tarea.id)
        .map(a => ({ nombre: userMap[a.usuario_id] || 'Usuario', estado: a.estado }));

      return {
        id:          miAsignacion ? miAsignacion.id : null,
        tarea_id:    tarea.id,
        estado:      miAsignacion ? miAsignacion.estado : null,
        tareaEstado: tarea.estado,   // 'activa' | 'finalizada'
        esCreador,
        tareas:      tarea,
        asignados:   asignadosDeTarea
      };
    }).filter(Boolean);

    res.json(resultado);

  } catch(err) {
    console.log(err);
    res.status(500).json({ error: 'Error al obtener tareas' });
  }

});

// CREAR TAREA GLOBAL
app.post('/api/tareas', authMiddleware, async (req, res) => {

  const {
    titulo,
    descripcion,
    fecha_limite,
    asignados  // array de user IDs; si viene vacío/null => asignar a todos
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

  if (err1) {
    console.log('ERR1:', err1);
    return res.status(500).json({ error: err1.message });
  }

  // DETERMINAR A QUIÉN ASIGNAR
  let targetIds = [];

  if (Array.isArray(asignados) && asignados.length > 0) {
    // Asignar solo a los usuarios seleccionados
    targetIds = asignados;
  } else {
    // Sin selección => asignar a todos
    const { data: users, error: err2 } = await supabase
      .from('users')
      .select('id');

    if (err2) {
      console.log('ERR2:', err2);
      return res.status(500).json({ error: err2.message });
    }
    targetIds = users.map(u => u.id);
  }

  // CREAR REGISTROS INDIVIDUALES
  const registros = targetIds.map(uid => ({
    tarea_id: tarea.id,
    usuario_id: uid,
    estado: 'no iniciada'
  }));

  const { error: err3 } = await supabase
    .from('tareas_usuarios')
    .insert(registros);

  if (err3) {
    console.log('ERR3:', err3);
    return res.status(500).json({ error: err3.message });
  }

  res.status(201).json({ success: true });

});

// FINALIZAR TAREA (solo el creador)
app.put('/api/tareas/:tareaId/finalizar', authMiddleware, async (req, res) => {

  const tareaId = parseInt(req.params.tareaId);
  const uid     = req.user.id;

  // Verificar que el usuario sea el creador
  const { data: tarea, error: e1 } = await supabase
    .from('tareas')
    .select('id, created_by, estado')
    .eq('id', tareaId)
    .single();

  if (e1 || !tarea) return res.status(404).json({ error: 'Tarea no encontrada' });
  if (tarea.created_by !== uid) return res.status(403).json({ error: 'No autorizado' });
  if (tarea.estado === 'finalizada') return res.status(400).json({ error: 'La tarea ya fue finalizada' });

  // Marcar tarea como finalizada
  const { error: e2 } = await supabase
    .from('tareas')
    .update({ estado: 'finalizada' })
    .eq('id', tareaId);
  if (e2) return res.status(500).json({ error: e2.message });

  // Buscar usuarios que completaron la tarea
  const { data: completados, error: e3 } = await supabase
    .from('tareas_usuarios')
    .select('usuario_id')
    .eq('tarea_id', tareaId)
    .eq('estado', 'completada');
  if (e3) return res.status(500).json({ error: e3.message });

  // Dar 10 monedas a cada uno
  if (completados.length > 0) {

    const completedIds = completados.map(c => c.usuario_id);

    const { data: existing } = await supabase
      .from('monedas')
      .select('usuario_id, total')
      .in('usuario_id', completedIds);

    const existingMap = {};
    (existing || []).forEach(e => { existingMap[e.usuario_id] = e.total; });

    const upserts = completedIds.map(id => ({
      usuario_id:  id,
      total:       (existingMap[id] || 0) + 10,
      updated_at:  new Date().toISOString()
    }));

    const { error: e4 } = await supabase
      .from('monedas')
      .upsert(upserts, { onConflict: 'usuario_id' });
    if (e4) return res.status(500).json({ error: e4.message });

  }

  res.json({ success: true, recompensados: completados.length });

});

// OBTENER PERFIL PROPIO
app.get('/api/me', authMiddleware, async (req, res) => {
  const uid = req.user.id;
  const { data: user, error: e1 } = await supabase
    .from('users')
    .select('id, full_name, email, img_profile')
    .eq('id', uid)
    .single();
  if (e1 || !user) return res.status(404).json({ error: 'Usuario no encontrado' });
  const { data: monedas } = await supabase
    .from('monedas')
    .select('total')
    .eq('usuario_id', uid)
    .single();
  res.json({ ...user, monedas: monedas ? monedas.total : 0 });
});

// EDITAR PERFIL PROPIO
app.put('/api/me', authMiddleware, async (req, res) => {
  const uid = req.user.id;
  const { full_name, email, current_password, new_password, img_profile } = req.body;
  if (!current_password)
    return res.status(400).json({ error: 'La contraseña actual es requerida' });
  // Verificar contraseña actual
  const { data: user, error: e1 } = await supabase
    .from('users')
    .select('*')
    .eq('id', uid)
    .single();
  if (e1 || !user) return res.status(404).json({ error: 'Usuario no encontrado' });
  const valid = await bcrypt.compare(current_password, user.password);
  if (!valid) return res.status(401).json({ error: 'La contraseña actual es incorrecta' });
  // Construir objeto de actualización
  const updates = {};
  if (full_name) updates.full_name = full_name;
  if (email)     updates.email     = email;
  if (new_password) updates.password = await bcrypt.hash(new_password, 10);
  if (img_profile !== undefined) updates.img_profile = img_profile;
  const { data: updated, error: e2 } = await supabase
    .from('users')
    .update(updates)
    .eq('id', uid)
    .select('id, full_name, email, img_profile')
    .single();
  if (e2) return res.status(500).json({ error: e2.message });
  // Refrescar token con datos nuevos
  const token = jwt.sign(
    { id: updated.id, email: updated.email, full_name: updated.full_name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ user: updated, token });
});

// LISTAR TODOS LOS USUARIOS (para el selector de asignación)
app.get('/api/users', authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, full_name, email')
    .neq('id', req.user.id)
    .order('full_name');

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
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
//  TIENDA
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/tienda/cosmeticos — catálogo completo (con flag "lo tengo")
app.get('/api/tienda/cosmeticos', authMiddleware, async (req, res) => {
  const uid = req.user.id;

  // Todos los cosméticos activos
  const { data: catalogo, error: e1 } = await supabase
    .from('cosmeticos')
    .select('*')
    .eq('activo', true)
    .order('precio', { ascending: true });

  if (e1) return res.status(500).json({ error: e1.message });

  // Inventario del usuario
  const { data: inv } = await supabase
    .from('inventario_usuario')
    .select('cosmetico_id')
    .eq('usuario_id', uid);

  const tengoIds = new Set((inv || []).map(i => i.cosmetico_id));

  // Banner equipado
  const { data: userData } = await supabase
    .from('users')
    .select('banner_equipado_id, banner_url')
    .eq('id', uid)
    .single();

  const equipadoId = userData?.banner_equipado_id || null;

  const resultado = catalogo.map(c => ({
    ...c,
    tengo:    tengoIds.has(c.id),
    equipado: c.id === equipadoId
  }));

  res.json({ cosmeticos: resultado, banner_url: userData?.banner_url || null });
});

// GET /api/usuarios/monedas — monedas del usuario actual
app.get('/api/usuarios/monedas', authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('monedas')
    .select('total')
    .eq('usuario_id', req.user.id)
    .single();

  if (error) return res.json({ monedas: 0 });
  res.json({ monedas: data?.total || 0 });
});

// POST /api/tienda/comprar — comprar un cosmético
app.post('/api/tienda/comprar', authMiddleware, async (req, res) => {
  const uid          = req.user.id;
  const { cosmetico_id } = req.body;
  if (!cosmetico_id) return res.status(400).json({ error: 'cosmetico_id requerido' });

  // Verificar que el cosmético existe
  const { data: cosm, error: e1 } = await supabase
    .from('cosmeticos')
    .select('id, precio')
    .eq('id', cosmetico_id)
    .eq('activo', true)
    .single();

  if (e1 || !cosm) return res.status(404).json({ error: 'Cosmético no encontrado' });

  // Verificar que no lo tenga ya
  const { data: yaLo } = await supabase
    .from('inventario_usuario')
    .select('id')
    .eq('usuario_id', uid)
    .eq('cosmetico_id', cosmetico_id)
    .single();

  if (yaLo) return res.status(409).json({ error: 'Ya tienes este cosmético' });

  // Verificar monedas
  const { data: monedasRow } = await supabase
    .from('monedas')
    .select('total')
    .eq('usuario_id', uid)
    .single();

  const saldo = monedasRow?.total || 0;
  if (saldo < cosm.precio)
    return res.status(400).json({ error: 'Monedas insuficientes' });

  // Descontar monedas
  const { error: e2 } = await supabase
    .from('monedas')
    .upsert({ usuario_id: uid, total: saldo - cosm.precio, updated_at: new Date().toISOString() },
            { onConflict: 'usuario_id' });

  if (e2) return res.status(500).json({ error: e2.message });

  // Agregar al inventario
  const { error: e3 } = await supabase
    .from('inventario_usuario')
    .insert([{ usuario_id: uid, cosmetico_id }]);

  if (e3) return res.status(500).json({ error: e3.message });

  res.json({ success: true, monedas_restantes: saldo - cosm.precio });
});

// POST /api/tienda/equipar — equipar un banner
app.post('/api/tienda/equipar', authMiddleware, async (req, res) => {
  const uid = req.user.id;
  const { cosmetico_id } = req.body;
  if (!cosmetico_id) return res.status(400).json({ error: 'cosmetico_id requerido' });

  // Verificar que lo tenga en el inventario
  const { data: enInv } = await supabase
    .from('inventario_usuario')
    .select('id')
    .eq('usuario_id', uid)
    .eq('cosmetico_id', cosmetico_id)
    .single();

  if (!enInv) return res.status(403).json({ error: 'No tienes este cosmético en tu inventario' });

  // Obtener la URL del cosmético
  const { data: cosm } = await supabase
    .from('cosmeticos')
    .select('img_url')
    .eq('id', cosmetico_id)
    .single();

  // Actualizar en users
  const { error } = await supabase
    .from('users')
    .update({ banner_equipado_id: cosmetico_id, banner_url: cosm?.img_url || null })
    .eq('id', uid);

  if (error) return res.status(500).json({ error: error.message });

  res.json({ success: true, banner_url: cosm?.img_url || null });
});

// POST /api/tienda/cosmeticos — agregar cosmético al catálogo
app.post('/api/tienda/cosmeticos', authMiddleware, async (req, res) => {
  const { nombre, descripcion, img_url, precio, tipo } = req.body;
  if (!nombre || !img_url) return res.status(400).json({ error: 'nombre e img_url son requeridos' });

  const { data, error } = await supabase
    .from('cosmeticos')
    .insert([{ nombre, descripcion, img_url, precio: precio || 0, tipo: tipo || 'banner' }])
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// ══════════════════════════════════════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════════════════════════════════════
server.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
  console.log(`📹 Video calls habilitado con Socket.IO`);
});