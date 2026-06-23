const API = 'http://localhost:8001';

// ─── Onglets ─────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab, .panel').forEach(el => el.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.tab).classList.add('active');
  });
});

// ─── Afficher/masquer mot de passe ───────────────────────────────
document.querySelectorAll('.toggle-pass').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = btn.previousElementSibling;
    input.type = input.type === 'password' ? 'text' : 'password';
  });
});

// ─── Force du mot de passe ───────────────────────────────────────
const fill  = document.getElementById('strength-fill');
const label = document.getElementById('strength-label');

document.getElementById('reg-pass').addEventListener('input', e => {
  const val = e.target.value;
  let score = 0;
  if (val.length >= 12) score++;
  if (/[A-Z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;

  const levels = [
    { w: '25%', bg: '#ef4444', text: 'Très faible' },
    { w: '50%', bg: '#f97316', text: 'Assez Faible' },
    { w: '75%', bg: 'rgb(197, 181, 34)', text: 'Faible' },
    { w: '100%', bg: '#16a34a', text: 'Fort' },
  ];
  const lvl = levels[Math.min(score - 1, 4)] ?? levels[0];
  fill.style.width = val ? lvl.w : '0';
  fill.style.background = lvl.bg;
  label.textContent = val ? lvl.text : 'Minimum 12 caractères avec une majuscule, une minuscule,un chiffre et un caractère spécial';
});

// ─── Appel API générique ─────────────────────────────────────────
async function callAPI(action, data, msgEl, btnEl) {
  btnEl.disabled = true;
  msgEl.className = 'msg';
  msgEl.textContent = 'Chargement…';

  try {
    const res = await fetch('http://localhost:8001/auth.php', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, ...data }),
    });
    const json = await res.json();

    if (json.success && action === 'login') {
      msgEl.className = 'msg success';
      msgEl.textContent = typeof json.success === 'string'
        ? json.success
        : `Bienvenue, ${json.username} !`;
        checkAuth();
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

async function checkAuth() {
  const res = await fetch('http://localhost:8001/auth.php', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'me' })
  });

  const json = await res.json();

  if (json.logged) {
    document.getElementById('btn-logout').style.display = 'block';
  } else {
    document.getElementById('btn-logout').style.display = 'none';
  }
}

async function sendContact() {
  const csrfRes = await fetch('http://localhost:8001/csrf.php');
  const csrfData = await csrfRes.json();

  const res = await fetch('http://localhost:8001/auth.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      action: 'message',
      name: document.getElementById('c-name').value,
      email: document.getElementById('c-email').value,
      message: document.getElementById('c-message').value,
      csrf_token: csrfData.csrf_token
    })
  });

  const json = await res.json();
  alert(json.success || json.error);
}

// ─── Connexion ───────────────────────────────────────────────────
document.getElementById('btn-login').addEventListener('click', () => {
  const username = document.getElementById('login-user').value.trim();
  const password = document.getElementById('login-pass').value;
  const msg = document.getElementById('login-msg');
  const btn = document.getElementById('btn-login');

  // Validation côté client (jamais suffisante seule !)
  if (!username || !password) {
    msg.className = 'msg error';
    msg.textContent = 'Veuillez remplir tous les champs.';
    return;
  }

  callAPI('login', { username, password }, msg, btn);
});

// ─── Inscription ─────────────────────────────────────────────────
document.getElementById('btn-register').addEventListener('click', () => {
  const username = document.getElementById('reg-user').value.trim();
  const password = document.getElementById('reg-pass').value;
  const confirm  = document.getElementById('reg-pass2').value;
  const msg = document.getElementById('reg-msg');
  const btn = document.getElementById('btn-register');

  if (!username || !password || !confirm) {
    msg.className = 'msg error';
    msg.textContent = 'Veuillez remplir tous les champs.';
    return;
  }
  if (password !== confirm) {
    msg.className = 'msg error';
    msg.textContent = 'Les mots de passe ne correspondent pas.';
    return;
  }
  if (password.length < 12) {
    msg.className = 'msg error';
    msg.textContent = 'Mot de passe trop court (12 min).';
    return;
  }

  callAPI('register', { username, password }, msg, btn);
});
// ── Bandeau cookie ────────────────────────────────────────────────
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
    if (el.textContent.includes('cookie')) {
      el.textContent = '';
      el.className = 'msg';
    }
  });
  document.getElementById('login-msg').className = 'msg error';
  document.getElementById('login-msg').textContent ='';
}

function disableAuth() {
  ['btn-login', 'btn-register'].forEach(id => {
    document.getElementById(id).disabled = true;
  });
  document.getElementById('login-msg').className = 'msg error';
  document.getElementById('login-msg').textContent =
    'Cookies refusés. Cliquez sur "Modifier mon choix" pour changer d\'avis.';
}
disableAuth();

// Au chargement : applique le choix déjà enregistré
if (localStorage.getItem('cookie_choice') === 'refused') {
  disableAuth();
  document.addEventListener('DOMContentLoaded', () => {
  checkAuth();
});
}

// Réouvrir les paramètres cookies
document.getElementById('cookie-settings').addEventListener('click', () => {
  banner.classList.remove('hidden');
  banner.style.display = 'flex';
});

const cookieChoice = localStorage.getItem('cookie_choice');

if (cookieChoice === 'accepted') {
  banner.classList.add('hidden');
  document.getElementById('login-msg').textContent ="";
  enableAuth();
}
else if (cookieChoice === 'refused') {
  banner.classList.add('hidden');
  disableAuth();
}

document.getElementById('btn-logout').addEventListener('click', async () => {
  await fetch('http://localhost:8001/auth.php', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'logout' })
  });

  document.getElementById('btn-logout').style.display = 'none';
  document.getElementById('login-msg').textContent = '';
  document.getElementById('reg-msg').textContent = '';
  localStorage.removeItem('cookie_choice');

  enableAuth();
});