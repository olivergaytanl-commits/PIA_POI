
// ─────────────────────────────────────────────────────────────────────────────
//  CATÁLOGO DE LOGROS  (usado tanto en front como en el panel de Perfil)
// ─────────────────────────────────────────────────────────────────────────────
const CATALOGO_LOGROS = [
  {
    id:          'agente_secreto',
    titulo:      '🕵️ Agente Secreto',
    descripcion: 'Envió su primer mensaje exitoso.',
    monedas:     10,
  },
  {
    id:          'hiperconectado',
    titulo:      '🔗 Hiperconectado',
    descripcion: 'Alcanzó 10 mensajes enviados en la plataforma.',
    monedas:     10,
  },
  {
    id:          'corresponsal_campo',
    titulo:      '📍 Corresponsal de Campo',
    descripcion: 'Compartió su ubicación actual en un chat.',
    monedas:     10,
  },
  {
    id:          'capitan_fundador',
    titulo:      '🚀 Capitán Fundador',
    descripcion: 'Creó un nuevo grupo de chat.',
    monedas:     10,
  },
  {
    id:          'trabajo_en_equipo',
    titulo:      '🤝 Trabajo en Equipo',
    descripcion: 'Completó una tarea asignada.',
    monedas:     10,
  },
  {
    id:          'influencer',
    titulo:      '🌟 Influencer',
    descripcion: 'Realizó al menos 3 publicaciones.',
    monedas:     10,
  },
];

// ─────────────────────────────────────────────────────────────────────────────
//  HELPER: authFetch  (re-usa el que ya existe en cada página; si no, lo define)
// ─────────────────────────────────────────────────────────────────────────────
if (typeof authFetch === 'undefined') {
  window.authFetch = async function(url, opts = {}) {
    const token = localStorage.getItem('token');
    opts.headers = { ...(opts.headers || {}), Authorization: `Bearer ${token}` };
    return fetch(url, opts);
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  NOTIFICACIÓN FLOTANTE  (toast)
// ─────────────────────────────────────────────────────────────────────────────
(function inyectarEstilosLogros() {
  if (document.getElementById('logros-styles')) return;
  const style = document.createElement('style');
  style.id = 'logros-styles';
  style.textContent = `
    /* Toast de logro desbloqueado */
    #logro-toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 9999;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: #fff;
      padding: 16px 22px;
      border-radius: 16px;
      box-shadow: 0 8px 32px rgba(0,0,0,.45);
      display: flex;
      align-items: center;
      gap: 14px;
      min-width: 300px;
      max-width: 380px;
      transform: translateY(120px);
      opacity: 0;
      transition: transform .4s cubic-bezier(.34,1.56,.64,1), opacity .4s ease;
      border: 1px solid rgba(255,215,0,.3);
    }
    #logro-toast.visible {
      transform: translateY(0);
      opacity: 1;
    }
    #logro-toast .logro-icon  { font-size: 2rem; flex-shrink: 0; }
    #logro-toast .logro-info  { display: flex; flex-direction: column; gap: 2px; }
    #logro-toast .logro-label { font-size: .68rem; text-transform: uppercase;
                                letter-spacing: 1px; color: #ffd700; font-weight: 600; }
    #logro-toast .logro-name  { font-size: 1rem; font-weight: 700; }
    #logro-toast .logro-coins { font-size: .8rem; color: #adf; margin-top: 2px; }

    /* Panel de logros en Perfil.html */
    .logros-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 12px;
      margin-top: 12px;
    }
    .logro-card {
      background: #f8f9fa;
      border: 2px solid #dee2e6;
      border-radius: 12px;
      padding: 14px;
      text-align: center;
      transition: .2s;
      position: relative;
    }
    .logro-card.desbloqueado {
      background: linear-gradient(135deg, #fff9e6 0%, #fffde7 100%);
      border-color: #ffd700;
      box-shadow: 0 2px 12px rgba(255,215,0,.25);
    }
    .logro-card.bloqueado { opacity: .45; filter: grayscale(1); }
    .logro-card .lc-emoji  { font-size: 2rem; display: block; margin-bottom: 6px; }
    .logro-card .lc-titulo { font-weight: 700; font-size: .88rem; margin-bottom: 4px; }
    .logro-card .lc-desc   { font-size: .74rem; color: #666; }
    .logro-card .lc-badge  {
      position: absolute; top: 8px; right: 8px;
      background: #ffd700; color: #333; font-size: .65rem;
      font-weight: 700; padding: 2px 6px; border-radius: 99px;
    }
    .logro-card .btn-titulo {
      margin-top: 8px; font-size: .75rem;
      padding: 4px 12px; border-radius: 99px;
      border: 1.5px solid #0d6efd; background: transparent; color: #0d6efd;
      cursor: pointer; transition: .15s;
    }
    .logro-card .btn-titulo:hover { background: #0d6efd; color: #fff; }
    .logro-card .btn-titulo.activo {
      background: #0d6efd; color: #fff; border-color: #0d6efd;
    }

    /* Título mostrado bajo el nombre de usuario en publicaciones */
    .titulo-usuario {
      font-size: .72rem;
      color: #8a7a00;
      background: rgba(255,215,0,.18);
      border: 1px solid rgba(255,215,0,.45);
      border-radius: 99px;
      padding: 1px 9px;
      display: inline-block;
      margin-top: 1px;
    }
  `;
  document.head.appendChild(style);
})();

// ─────────────────────────────────────────────────────────────────────────────
//  MOSTRAR TOAST
// ─────────────────────────────────────────────────────────────────────────────
function mostrarToastLogro(logro) {
  let toast = document.getElementById('logro-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'logro-toast';
    toast.innerHTML = `
      <div class="logro-icon" id="lt-icon"></div>
      <div class="logro-info">
        <span class="logro-label">🏆 ¡Logro desbloqueado!</span>
        <span class="logro-name"  id="lt-name"></span>
        <span class="logro-coins" id="lt-coins"></span>
      </div>`;
    document.body.appendChild(toast);
  }

  const emoji = logro.titulo.split(' ')[0];
  const nombre = logro.titulo.replace(/^\S+\s/, '');

  document.getElementById('lt-icon').textContent  = emoji;
  document.getElementById('lt-name').textContent  = nombre;
  document.getElementById('lt-coins').textContent = `+${logro.monedas} 🪙 monedas`;

  toast.classList.add('visible');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove('visible'), 4500);
}

// ─────────────────────────────────────────────────────────────────────────────
//  DESBLOQUEAR LOGRO  (llama al backend; muestra toast si fue nuevo)
// ─────────────────────────────────────────────────────────────────────────────
async function desbloquearLogro(logroId) {
  try {
    const res  = await authFetch('/api/logros/desbloquear', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ logro_id: logroId }),
    });
    const data = await res.json();

    // El backend devuelve { nuevo: true } solo la primera vez
    if (data.nuevo) {
      const logro = CATALOGO_LOGROS.find(l => l.id === logroId);
      if (logro) mostrarToastLogro(logro);
    }

    return data;
  } catch (err) {
    console.warn('Logros: error al desbloquear', logroId, err);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  HOOKS AUTOMÁTICOS
//  Envuelven las funciones existentes en cada página para detectar los eventos
// ─────────────────────────────────────────────────────────────────────────────

/* ── Chat.html: primer mensaje y geolocalización ── */
if (typeof window !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {

    /* Hook: enviarMensaje */
    const _enviarMensajeOrig = window.enviarMensaje;
    if (typeof _enviarMensajeOrig === 'function') {
      window.enviarMensaje = async function(...args) {
        const input = document.getElementById('msgInput');
        const texto = input ? input.value.trim() : '';

        await _enviarMensajeOrig.apply(this, args);

        // Logro 1 — Agente Secreto (primer mensaje)
        desbloquearLogro('agente_secreto');

        // Logro 2 — Hiperconectado (10 mensajes; el backend lleva la cuenta)
        desbloquearLogro('hiperconectado');

        // Logro 3 — Corresponsal de Campo (mensaje con enlace de Google Maps)
        if (/https?:\/\/(www\.)?google\.com\/maps/i.test(texto)) {
          desbloquearLogro('corresponsal_campo');
        }
      };
    }

    /* Hook: enviarUbicacion (el mensaje ya incluye un link de Maps) */
    const _enviarUbicOrig = window.enviarUbicacion;
    if (typeof _enviarUbicOrig === 'function') {
      window.enviarUbicacion = async function(...args) {
        await _enviarUbicOrig.apply(this, args);
        desbloquearLogro('agente_secreto');
        desbloquearLogro('hiperconectado');
        desbloquearLogro('corresponsal_campo');
      };
    }

    /* ── Chat.html: crear grupo ── */
    const _crearGrupoOrig = window.crearGrupo;
    if (typeof _crearGrupoOrig === 'function') {
      window.crearGrupo = async function(...args) {
        await _crearGrupoOrig.apply(this, args);
        desbloquearLogro('capitan_fundador');
      };
    }
  });
}

/* ── Tarea.html: completar tarea ── */
if (typeof window !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    const _cambiarEstadoOrig = window.cambiarEstado;
    if (typeof _cambiarEstadoOrig === 'function') {
      window.cambiarEstado = async function(id, estado, ...rest) {
        await _cambiarEstadoOrig.apply(this, [id, estado, ...rest]);
        if (estado === 'completada') {
          desbloquearLogro('trabajo_en_equipo');
        }
      };
    }
  });
}

/* ── Publi.html: crear publicación ── */
if (typeof window !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    const _crearPubliOrig = window.crearPublicacion;
    if (typeof _crearPubliOrig === 'function') {
      window.crearPublicacion = async function(...args) {
        await _crearPubliOrig.apply(this, args);
        // Logro 6 — Influencer (≥ 3 publicaciones; el backend verifica el total)
        desbloquearLogro('influencer');
      };
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  PANEL DE LOGROS  (para Perfil.html)
//  Llama a renderPanelLogros('#contenedor') desde Perfil.html
// ─────────────────────────────────────────────────────────────────────────────
async function renderPanelLogros(selectorONodo) {
  const contenedor = typeof selectorONodo === 'string'
    ? document.querySelector(selectorONodo)
    : selectorONodo;
  if (!contenedor) return;

  contenedor.innerHTML = '<p style="color:#aaa;font-size:.85rem;">Cargando logros…</p>';

  let desbloqueados = [];
  let tituloActivo  = null;

  try {
    const [rLogros, rPerfil] = await Promise.all([
      authFetch('/api/logros/mis-logros').then(r => r.json()),
      authFetch('/api/me').then(r => r.json()),
    ]);
    desbloqueados = (rLogros || []).map(l => l.logro_id);
    tituloActivo  = rPerfil.titulo_activo || null;
  } catch (e) {
    contenedor.innerHTML = '<p style="color:red;font-size:.85rem;">Error al cargar logros.</p>';
    return;
  }

  const html = `
    <h3 style="margin-bottom:4px;">🏆 Logros</h3>
    <p style="font-size:.8rem;color:#888;margin-bottom:12px;">
      Desbloquea logros interactuando con la plataforma. Cada uno otorga <strong>10 🪙</strong>.
    </p>
    <div class="logros-grid">
      ${CATALOGO_LOGROS.map(logro => {
        const desbloqueado = desbloqueados.includes(logro.id);
        const esActivo     = tituloActivo === logro.id;
        const emoji        = logro.titulo.split(' ')[0];
        const nombre       = logro.titulo.replace(/^\S+\s/, '');

        return `
          <div class="logro-card ${desbloqueado ? 'desbloqueado' : 'bloqueado'}"
               id="logro-card-${logro.id}">
            ${desbloqueado ? '<span class="lc-badge">+10 🪙</span>' : ''}
            <span class="lc-emoji">${emoji}</span>
            <div class="lc-titulo">${nombre}</div>
            <div class="lc-desc">${logro.descripcion}</div>
            ${desbloqueado ? `
              <button
                class="btn-titulo ${esActivo ? 'activo' : ''}"
                id="btn-titulo-${logro.id}"
                onclick="seleccionarTitulo('${logro.id}')">
                ${esActivo ? '✅ Título activo' : 'Usar como título'}
              </button>` : ''}
          </div>`;
      }).join('')}
    </div>`;

  contenedor.innerHTML = html;
}

// ─────────────────────────────────────────────────────────────────────────────
//  SELECCIONAR TÍTULO ACTIVO
// ─────────────────────────────────────────────────────────────────────────────
async function seleccionarTitulo(logroId) {
  try {
    const res = await authFetch('/api/logros/titulo', {
      method:  'PUT',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ logro_id: logroId }),
    });
    const data = await res.json();
    if (!res.ok) { alert(data.error || 'Error al actualizar título'); return; }

    // Actualizar botones en la UI
    document.querySelectorAll('.btn-titulo').forEach(btn => {
      btn.classList.remove('activo');
      btn.textContent = 'Usar como título';
    });

    // Si el logro ya era el activo, lo deseleccionamos (toggle)
    if (!data.deseleccionado) {
      const btn = document.getElementById(`btn-titulo-${logroId}`);
      if (btn) {
        btn.classList.add('activo');
        btn.textContent = '✅ Título activo';
      }
    }
  } catch (err) {
    console.error('Error al seleccionar título:', err);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  INYECTAR TÍTULO EN PUBLICACIONES  (llama desde Inicio.html)
//  Reemplaza la línea donde se construye el HTML de la tarjeta de publicación:
//
//    <span class="usuario">…</span>
//
//  Por:
//
//    <span class="usuario">…</span>
//    ${buildTituloHtml(p.users?.titulo_activo)}
//
// ─────────────────────────────────────────────────────────────────────────────
function buildTituloHtml(tituloId) {
  if (!tituloId) return '';
  const logro = CATALOGO_LOGROS.find(l => l.id === tituloId);
  if (!logro) return '';
  return `<span class="titulo-usuario">${logro.titulo}</span>`;
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPORTAR helpers globales
// ─────────────────────────────────────────────────────────────────────────────
window.desbloquearLogro  = desbloquearLogro;
window.renderPanelLogros = renderPanelLogros;
window.seleccionarTitulo = seleccionarTitulo;
window.buildTituloHtml   = buildTituloHtml;
window.CATALOGO_LOGROS   = CATALOGO_LOGROS;


// ══════════════════════════════════════════════════════════════════════════════
//  ██████╗  █████╗  ██████╗██╗  ██╗███████╗███╗   ██╗██████╗
//  ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝████╗  ██║██╔══██╗
//  ██████╔╝███████║██║     █████╔╝ █████╗  ██╔██╗ ██║██║  ██║
//  ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██║╚██╗██║██║  ██║
//  ██████╔╝██║  ██║╚██████╗██║  ██╗███████╗██║ ╚████║██████╔╝
//  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═════╝
//
//  SECCIÓN BACKEND — Pega este bloque en Server.js antes de server.listen(...)
//
//  Requiere que la tabla `logros_usuario` y la columna `titulo_activo`
//  ya existan en Supabase (ver SQL al inicio de este archivo).
// ══════════════════════════════════════════════════════════════════════════════

/*

// ── Límite de mensajes para el logro Hiperconectado ─────────────────────────
const MENSAJES_PARA_HIPERCONECTADO = 10;

// Mapa de condiciones de logros que requieren verificación en el backend
const CONDICIONES_LOGROS = {
  hiperconectado:  verificarHiperconectado,
  influencer:      verificarInfluencer,
};

async function verificarHiperconectado(uid) {
  // Cuenta mensajes privados + grupales enviados por el usuario
  const [{ count: c1 }, { count: c2 }] = await Promise.all([
    supabase.from('messages')
            .select('*', { count: 'exact', head: true })
            .eq('username', (await supabase.from('users').select('full_name').eq('id', uid).single()).data?.full_name),
    supabase.from('mensajes_grupo')
            .select('*', { count: 'exact', head: true })
            .eq('usuario_id', uid),
  ]);
  return (c1 || 0) + (c2 || 0) >= MENSAJES_PARA_HIPERCONECTADO;
}

async function verificarInfluencer(uid) {
  const { count } = await supabase.from('publicaciones')
    .select('*', { count: 'exact', head: true })
    .eq('user_id', uid);
  return (count || 0) >= 3;
}

// POST /api/logros/desbloquear ────────────────────────────────────────────────
app.post('/api/logros/desbloquear', authMiddleware, async (req, res) => {
  const uid     = req.user.id;
  const logroId = req.body.logro_id;

  if (!logroId) return res.status(400).json({ error: 'logro_id requerido' });

  // Verificar que el logro_id existe
  const LOGROS_VALIDOS = [
    'agente_secreto','hiperconectado','corresponsal_campo',
    'capitan_fundador','trabajo_en_equipo','influencer'
  ];
  if (!LOGROS_VALIDOS.includes(logroId))
    return res.status(400).json({ error: 'logro_id inválido' });

  // ¿Ya lo tiene?
  const { data: existente } = await supabase
    .from('logros_usuario')
    .select('id')
    .eq('usuario_id', uid)
    .eq('logro_id', logroId)
    .single();

  if (existente) return res.json({ nuevo: false });

  // Logros con condición extra que el backend verifica
  const condicion = CONDICIONES_LOGROS[logroId];
  if (condicion) {
    const cumple = await condicion(uid);
    if (!cumple) return res.json({ nuevo: false, pendiente: true });
  }

  // Insertar logro
  const { error: e1 } = await supabase
    .from('logros_usuario')
    .insert([{ usuario_id: uid, logro_id: logroId }]);

  if (e1) return res.status(500).json({ error: e1.message });

  // Dar 10 monedas
  const { data: monedasRow } = await supabase
    .from('monedas').select('total').eq('usuario_id', uid).single();

  await supabase.from('monedas').upsert(
    { usuario_id: uid, total: (monedasRow?.total || 0) + 10, updated_at: new Date().toISOString() },
    { onConflict: 'usuario_id' }
  );

  return res.json({ nuevo: true });
});

// GET /api/logros/mis-logros ──────────────────────────────────────────────────
app.get('/api/logros/mis-logros', authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('logros_usuario')
    .select('logro_id, obtenido_en')
    .eq('usuario_id', req.user.id)
    .order('obtenido_en', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// PUT /api/logros/titulo ──────────────────────────────────────────────────────
// Activa o desactiva el título del usuario (toggle)
app.put('/api/logros/titulo', authMiddleware, async (req, res) => {
  const uid     = req.user.id;
  const logroId = req.body.logro_id;

  // Verificar que el usuario tiene ese logro
  const { data: logro } = await supabase
    .from('logros_usuario')
    .select('id')
    .eq('usuario_id', uid)
    .eq('logro_id', logroId)
    .single();

  if (!logro) return res.status(403).json({ error: 'No has desbloqueado ese logro' });

  // Leer título actual
  const { data: userData } = await supabase
    .from('users').select('titulo_activo').eq('id', uid).single();

  // Toggle: si ya era el activo, lo quita; si no, lo pone
  const nuevoTitulo = userData?.titulo_activo === logroId ? null : logroId;

  const { error } = await supabase
    .from('users')
    .update({ titulo_activo: nuevoTitulo })
    .eq('id', uid);

  if (error) return res.status(500).json({ error: error.message });

  res.json({ success: true, titulo_activo: nuevoTitulo, deseleccionado: nuevoTitulo === null });
});

// Actualizar /api/publicaciones para incluir titulo_activo en el JOIN
// ► En la ruta GET /api/publicaciones reemplaza:
//     .select('*, users(id, full_name, img_profile, banner_url)')
//   por:
//     .select('*, users(id, full_name, img_profile, banner_url, titulo_activo)')

*/
