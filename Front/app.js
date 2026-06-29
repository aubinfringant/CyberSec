const API = 'http://localhost:8001';

// ─── Onglets ─────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab, .panel').forEach(el => el.classList.remove('active'));
    tab.classList.add('active');
    tab.setAttribute('aria-selected', 'true');
    document.querySelectorAll('.tab').forEach(t => {
      if (t !== tab) t.setAttribute('aria-selected', 'false');
    });
    document.getElementById(tab.dataset.tab).classList.add('active');
  });
});

// ─── Afficher/masquer mot de passe ───────────────────────────────
document.querySelectorAll('.toggle-pass').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = btn.previousElementSibling;
    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';
    btn.setAttribute('aria-label', isHidden ? 'Masquer le mot de passe' : 'Afficher le mot de passe');
  });
});

// ─── Force du mot de passe ───────────────────────────────────────
const fill  = document.getElementById('strength-fill');
const label = document.getElementById('strength-label');

document.getElementById('reg-pass').addEventListener('input', e => {
  const val = e.target.value;
  let score = 0;
  if (/[a-z]/.test(val)) score++;
  if (/[A-Z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;
  if (val.length < 12) score = Math.max(score - 1, 0);

  const levels = [
    { w: '25%',  bg: '#ef4444', text: 'Très faible' },
    { w: '50%',  bg: '#f97316', text: 'Assez faible' },
    { w: '75%',  bg: '#ca8a04', text: 'Faible' },
    { w: '100%', bg: '#16a34a', text: 'Fort' },
  ];
  const lvl = levels[Math.min(score - 1, 3)] ?? levels[0];
  fill.style.width      = val ? lvl.w  : '0';
  fill.style.background = val ? lvl.bg : '';
  label.textContent = val
    ? lvl.text
    : 'Minimum 12 caractères avec une majuscule, une minuscule, un chiffre et un caractère spécial';
});

// ─── Compteur de caractères pour le message de contact ───────────
const msgTextarea  = document.getElementById('c-message');
const charCountEl  = document.getElementById('c-char-count');
if (msgTextarea) {
  msgTextarea.addEventListener('input', () => {
    const len = msgTextarea.value.length;
    charCountEl.textContent = `${len} / 1000 caractères`;
    charCountEl.style.color = len > 950 ? '#f97316' : '';
  });
}

// ─── Appel API générique ─────────────────────────────────────────
async function callAPI(action, data, msgEl, btnEl) {
  btnEl.disabled = true;
  msgEl.className = 'msg';
  msgEl.textContent = 'Chargement…';

  try {
    const res = await fetch(`${API}/auth.php`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, ...data }),
    });
    const json = await res.json();

    if (json.success) {
      msgEl.className = 'msg success';
      msgEl.textContent = typeof json.success === 'string'
        ? json.success
        : `Bienvenue, ${json.username} !`;

      if (action === 'login') {
        document.getElementById('login-form').reset();
        checkAuth();
      }

      if (action === 'register') {
        document.getElementById('register-form').reset();

        fill.style.width = '0';
        label.textContent =
          'Minimum 12 caractères avec une majuscule, une minuscule, un chiffre et un caractère spécial';
      }
    } else {
      msgEl.className = 'msg error';
      msgEl.textContent = json.error ?? 'Erreur inconnue';
    }
  } catch {
    msgEl.className = 'msg error';
    msgEl.textContent = 'Impossible de contacter le serveur.';
  } finally {
    btnEl.disabled = false;
  }
}

// ─── Vérification de l'état de connexion ─────────────────────────
async function checkAuth() {
  try {
    const res  = await fetch(`${API}/auth.php`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'me' })
    });
    const json = await res.json();
    document.getElementById('btn-logout').style.display = json.logged ? 'block' : 'none';
  } catch {
    // Pas de connexion : on ignore silencieusement
  }
}

// ─── Formulaire de contact sécurisé ──────────────────────────────
// Processus :
//   1. Récupération du token CSRF depuis la session serveur (/csrf.php)
//   2. Validation côté client (longueurs, format email)
//   3. Envoi JSON → auth.php (action: 'message')
async function sendContact() {
  const form = document.getElementById("contact-form");
  
  // ── Validation côté client ────────────────────────────────────
  
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }
  
  const msgEl = document.getElementById('contact-msg');
  const btnEl = document.getElementById('btn-contact');

  const name    = document.getElementById('c-name').value.trim();
  const email   = document.getElementById('c-email').value.trim();
  const message = document.getElementById('c-message').value.trim();

  
  // Regex email simple côté client
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    msgEl.className = 'msg error';
    msgEl.textContent = 'Adresse email invalide.';
    return;
  }

  // ── Récupération du token CSRF ────────────────────────────────
  // Le token est lié à la session PHP ; il est régénéré côté serveur
  // après chaque soumission valide pour empêcher la répétition de requêtes.
  let csrfToken = '';

  try {
    const csrfRes  = await fetch(`${API}/csrf.php`, { credentials: 'include' });
    const csrfData = await csrfRes.json();
    csrfToken = csrfData.csrf_token ?? '';
  } catch {
    msgEl.className = 'msg error';
    msgEl.textContent = 'Erreur de sécurité (CSRF). Rechargez la page.';
    return;
  }

  // ── Envoi de la requête ───────────────────────────────────────
  btnEl.disabled    = true;
  msgEl.className   = 'msg';
  msgEl.textContent = 'Envoi en cours…';

  try {
    const res  = await fetch(`${API}/auth.php`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'message',
        name,
        email,
        message,
        csrf_token: csrfToken
      }),
    });
    const json = await res.json();

    if (json.success) {
      msgEl.className   = 'msg success';
      msgEl.textContent = json.success;
      
      document.getElementById('contact-form').reset();
      charCountEl.textContent = '0 / 1000 caractères';
    }
  } catch {
    msgEl.className   = 'msg error';
    msgEl.textContent = 'Impossible de contacter le serveur.';
  } finally {
    btnEl.disabled = false;
  }
}

document.getElementById('contact-form').addEventListener('submit', (e) => {
  e.preventDefault();

  const form = e.target;

  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }

  sendContact();
});

// ─── Connexion ───────────────────────────────────────────────────
document.getElementById('login-form').addEventListener('submit', (e) => {
  e.preventDefault();

  const form = e.target;

  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }

  const username = document.getElementById('login-user').value.trim();
  const password = document.getElementById('login-pass').value;

  callAPI('login',{ username, password },
    document.getElementById('login-msg'),
    document.getElementById('btn-login')
  );
});

// ─── Inscription ─────────────────────────────────────────────────
document.getElementById('register-form').addEventListener('submit', (e) => {
  e.preventDefault();

  const form = e.target;

  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }

  const username = document.getElementById('reg-user').value.trim();
  const password = document.getElementById('reg-pass').value;
  const confirm  = document.getElementById('reg-pass2').value;

  const msg = document.getElementById('reg-msg');

  if (password !== confirm) {
    msg.className = 'msg error';
    msg.textContent = 'Les mots de passe ne correspondent pas.';
    return;
  }

  callAPI('register',{ username, password },
    msg,document.getElementById('btn-register')
  );
});

// ─── Bandeau cookie ───────────────────────────────────────────────
const banner = document.getElementById('cookie-banner');

document.getElementById('cookie-accept').addEventListener('click', () => {
  localStorage.setItem('cookie_choice', 'accepted');
  banner.classList.add('hidden');
  enableAuth();
});

document.getElementById('cookie-refuse').addEventListener('click', () => {
  localStorage.setItem('cookie_choice', 'refused');
  banner.classList.add('hidden');
  disableAuth();
});

function enableAuth() {
  ['btn-login', 'btn-register'].forEach(id => {
    document.getElementById(id).disabled = false;
  });
  ['login-msg', 'reg-msg'].forEach(id => {
    const el = document.getElementById(id);
    if (el.textContent.includes('cookie') || el.textContent.includes('Cookies')) {
      el.textContent = '';
      el.className   = 'msg';
    }
  });
}

function disableAuth() {
  ['btn-login', 'btn-register'].forEach(id => {
    document.getElementById(id).disabled = true;
  });
  const msg = document.getElementById('login-msg');
  msg.className   = 'msg error';
  msg.textContent = 'Cookies refusés. Cliquez sur "Modifier mon choix" pour changer d\'avis.';
}

// Rouvrir le bandeau
document.getElementById('cookie-settings').addEventListener('click', () => {
  banner.classList.remove('hidden');
  banner.style.display = 'flex';
});

// Déconnexion
document.getElementById('btn-logout').addEventListener('click', async () => {
  await fetch(`${API}/auth.php`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'logout' })
  });
  document.getElementById('btn-logout').style.display = 'none';
  document.getElementById('login-msg').textContent    = '';
  document.getElementById('reg-msg').textContent      = '';
  localStorage.removeItem('cookie_choice');
  enableAuth();
});

// ─── Initialisation au chargement ────────────────────────────────
(function init() {
  const choice = localStorage.getItem('cookie_choice');
  if (choice === 'accepted') {
    banner.classList.add('hidden');
    enableAuth();
    checkAuth(); // Vérifie si l'utilisateur est déjà connecté
  } else if (choice === 'refused') {
    banner.classList.add('hidden');
    disableAuth();
  } else {
    // Premier visit : bandeau visible, auth désactivée par défaut
    disableAuth();
  }
})();
