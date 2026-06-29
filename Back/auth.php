<?php
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);

session_start();

// ─── En-têtes CORS ───────────────────────────────────────────────
// Doit être envoyé AVANT tout autre code, y compris le preflight OPTIONS.
// Avec credentials:include, l'origine doit être exacte (pas de wildcard *).
// Vary: Origin est requis quand l'origine est dynamique pour éviter
// qu'un proxy cache la réponse d'une origine pour une autre.
$allowedOrigins = ['http://localhost:8000', 'http://localhost:8001'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins, true)) {
    header("Access-Control-Allow-Origin: $origin");
    header('Vary: Origin');
}
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Methods: POST, OPTIONS');

// ─── Preflight OPTIONS ────────────────────────────────────────────
// Le navigateur envoie OPTIONS avant chaque POST avec Content-Type: application/json.
// Il faut répondre 200/204 ICI, avant la vérification de méthode ci-dessous,
// sinon le POST déclenche un 405 et le navigateur bloque la requête réelle.
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Max-Age: 86400'); // Cache le preflight 24h
    http_response_code(200);
    exit;
}

// ─── En-têtes de sécurité ─────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['error' => 'Méthode non autorisée']));
}

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

// ─── Rate limiting (5 essais / 1 min par IP) ─────────────────────
function checkRateLimit(PDO $pdo): bool {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $row = $pdo->prepare("SELECT attempts, last_try FROM rate_limit WHERE ip = ?");
    $row->execute([$ip]);
    $data = $row->fetch();

    if ($data) {
        $elapsed = time() - strtotime($data['last_try']);
        if ($elapsed < 60 && $data['attempts'] >= 5) return false;
        if ($elapsed >= 60) {
            $pdo->prepare("UPDATE rate_limit SET attempts=1, last_try=CURRENT_TIMESTAMP WHERE ip=?")
                ->execute([$ip]);
        } else {
            $pdo->prepare("UPDATE rate_limit SET attempts=attempts+1, last_try=CURRENT_TIMESTAMP WHERE ip=?")
                ->execute([$ip]);
        }
    } else {
        $pdo->prepare("INSERT INTO rate_limit (ip) VALUES (?)")->execute([$ip]);
    }
    return true;
}

// ─── Génération JWT ───────────────────────────────────────────────
// Structure : header.payload.signature (HMAC-SHA256)
// Le header identifie l'algo, le payload transporte les claims (sub, usr, iat, exp),
// la signature garantit l'intégrité sans base de données.
function generateToken(int $userId, string $username): string {
    $secret  = getenv('JWT_SECRET') ?: 'CHANGE_ME_32_CHARS_MINIMUM_SECRET';
    $header  = rtrim(strtr(base64_encode(json_encode(['alg'=>'HS256','typ'=>'JWT'])), '+/', '-_'), '=');
    $payload = rtrim(strtr(base64_encode(json_encode([
        'sub' => $userId,
        'usr' => $username,
        'iat' => time(),
        'exp' => time() + 3600
    ])), '+/', '-_'), '=');
    $sig = rtrim(strtr(base64_encode(hash_hmac('sha256', "$header.$payload", $secret, true)), '+/', '-_'), '=');
    return "$header.$payload.$sig";
}

$path = __DIR__ . '/../database/users.db';
$pdo  = new PDO('sqlite:' . $path);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

// ─── INSCRIPTION ──────────────────────────────────────────────────
if ($action === 'register') {
    $username = trim($body['username'] ?? '');
    $password = $body['password'] ?? '';

    if (strlen($username) < 3 || strlen($username) > 30)
        exit(json_encode(['error' => 'Pseudo : 3 à 30 caractères']));
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $username))
        exit(json_encode(['error' => 'Pseudo : lettres, chiffres et _ uniquement']));
    if (strlen($password) < 12)
        exit(json_encode(['error' => 'Mot de passe : 12 caractères minimum']));
    if (!preg_match('/[A-Z]/', $password))
        exit(json_encode(['error' => 'Mot de passe : au moins une majuscule']));
    if (!preg_match('/[a-z]/', $password))
        exit(json_encode(['error' => 'Mot de passe : au moins une minuscule']));
    if (!preg_match('/[0-9]/', $password))
        exit(json_encode(['error' => 'Mot de passe : au moins un chiffre']));
    if (!preg_match('/[^A-Za-z0-9]/', $password))
        exit(json_encode(['error' => 'Mot de passe : au moins un caractère spécial']));

    $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ?');
    $stmt->execute([$username]);
    if ($stmt->fetch()) exit(json_encode(['error' => 'Pseudo déjà pris']));

    $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $pdo->prepare('INSERT INTO users (username, password) VALUES (?, ?)')->execute([$username, $hash]);

    echo json_encode(['success' => 'Compte créé. Vous pouvez vous connecter.']);
}

// ─── CONNEXION ────────────────────────────────────────────────────
elseif ($action === 'login') {
    if (!checkRateLimit($pdo))
        exit(json_encode(['error' => 'Trop de tentatives. Réessayez dans 1 min.']));

    $username = trim($body['username'] ?? '');
    $password = $body['password'] ?? '';

    if (!$username || !$password)
        exit(json_encode(['error' => 'Champs manquants']));

    $stmt = $pdo->prepare('SELECT id, password FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    // Délai constant → protection contre le timing attack
    $dummy = '$2y$12$invalidsaltinvalidsaltinvalids.';
    if (!$user) { password_verify($password, $dummy); }

    if (!$user || !password_verify($password, $user['password'])) {
        http_response_code(401);
        exit(json_encode(['error' => 'Identifiants incorrects']));
    }

    $token = generateToken($user['id'], $username);

    setcookie('auth_token', $token, [
        'expires'  => time() + 3600,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Strict',
        'secure'   => true,
    ]);

    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $pdo->prepare("UPDATE rate_limit SET attempts=1, last_try=CURRENT_TIMESTAMP WHERE ip=?")->execute([$ip]);

    echo json_encode(['success' => true, 'username' => $username]);
}

// ─── DÉCONNEXION ──────────────────────────────────────────────────
elseif ($action === 'logout') {
    setcookie('auth_token', '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'httponly' => true,
        'secure'   => true,
        'samesite' => 'Strict'
    ]);
    session_destroy();
    echo json_encode(['success' => 'Déconnecté']);
}

// ─── ÉTAT DE CONNEXION ────────────────────────────────────────────
elseif ($action === 'me') {
    echo json_encode(['logged' => isset($_COOKIE['auth_token'])]);
}

// ─── FORMULAIRE CONTACT ───────────────────────────────────────────
// Protection CSRF : le token en session est comparé via hash_equals()
// (comparaison en temps constant pour éviter les timing attacks).
// Après validation, le token est régénéré pour invalider tout rejeu.
// Protection XSS : htmlspecialchars() neutralise <, >, ", ', & avant stockage.
// Anti-spam : vérification hCaptcha côté serveur via l'API de validation.
elseif ($action === 'message') {
    $name        = trim($body['name']    ?? '');
    $email       = trim($body['email']   ?? '');
    $message     = trim($body['message'] ?? '');
    $csrfToken   = $body['csrf_token']   ?? '';
    $captchaResp = $body['h-captcha-response'] ?? '';

    // ── 1. Vérification CSRF ──────────────────────────────────────
    if (!$csrfToken || !hash_equals($_SESSION['csrf_token'] ?? '', $csrfToken)) {
        http_response_code(403);
        exit(json_encode(['error' => 'Token CSRF invalide ou expiré.']));
    }
    // Rotation du token après usage → empêche le rejeu
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    // ── 2. Vérification hCaptcha ──────────────────────────────────
    $hcaptchaSecret = getenv('HCAPTCHA_SECRET') ?: 'YOUR_HCAPTCHA_SECRET_KEY';
    if (empty($captchaResp)) {
        exit(json_encode(['error' => 'Captcha manquant. Veuillez cocher la case.']));
    }
    $verify = file_get_contents('https://hcaptcha.com/siteverify', false, stream_context_create([
        'http' => [
            'method'  => 'POST',
            'header'  => 'Content-Type: application/x-www-form-urlencoded',
            'content' => http_build_query(['secret' => $hcaptchaSecret, 'response' => $captchaResp]),
        ]
    ]));
    $captchaData = json_decode($verify, true);
    if (!($captchaData['success'] ?? false)) {
        http_response_code(400);
        exit(json_encode(['error' => 'Captcha invalide. Réessayez.']));
    }

    // ── 3. Validation des champs ──────────────────────────────────
    if (strlen($name) < 2 || strlen($name) > 50)
        exit(json_encode(['error' => 'Nom invalide (2–50 caractères).']));

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254)
        exit(json_encode(['error' => 'Adresse email invalide.']));

    if (strlen($message) < 10 || strlen($message) > 1000)
        exit(json_encode(['error' => 'Message invalide (10–1000 caractères).']));

    // ── 4. Neutralisation XSS avant stockage ─────────────────────
    // htmlspecialchars() convertit <, >, ", ', & en entités HTML.
    // Les données ne peuvent donc pas être interprétées comme du code
    // si elles sont réaffichées dans un contexte HTML.
    $nameSafe    = htmlspecialchars($name,    ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $messageSafe = htmlspecialchars($message, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    // L'email n'est pas affiché en HTML, on le stocke tel quel après validation

    // ── 5. Stockage en base (requête préparée → anti-SQLi) ────────
    $stmt = $pdo->prepare("INSERT INTO contact (name, email, message) VALUES (?, ?, ?)");
    $stmt->execute([$nameSafe, $email, $messageSafe]);

    echo json_encode(['success' => 'Message envoyé avec succès !']);
}

else {
    http_response_code(400);
    echo json_encode(['error' => 'Action inconnue']);
}
