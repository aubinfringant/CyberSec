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
  if (val.length >= 8)  score++;
  if (val.length >= 12) score++;
  if (/[A-Z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;

  const levels = [
    { w: '20%', bg: '#ef4444', text: 'Très faible' },
    { w: '40%', bg: '#f97316', text: 'Faible' },
    { w: '60%', bg: '#eab308', text: 'Moyen' },
    { w: '80%', bg: '#22c55e', text: 'Fort' },
    { w: '100%', bg: '#16a34a', text: 'Très fort' },
  ];
  const lvl = levels[Math.min(score - 1, 4)] ?? levels[0];
  fill.style.width = val ? lvl.w : '0';
  fill.style.background = lvl.bg;
  label.textContent = val ? lvl.text : '—';
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

    if (json.success) {
      msgEl.className = 'msg success';
      msgEl.textContent = typeof json.success === 'string'
        ? json.success
        : `Bienvenue, ${json.username} !`;
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
  if (password.length < 8) {
    msg.className = 'msg error';
    msg.textContent = 'Mot de passe trop court (8 min).';
    return;
  }

  callAPI('register', { username, password }, msg, btn);
});