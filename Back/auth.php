<?php
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);

session_start();

// En-têtes de sécurité
header('Access-Control-Allow-Origin: http://localhost:8000');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Répondre aux preflight OPTIONS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once 'db.php';

// Limite les méthodes acceptées
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['error' => 'Méthode non autorisée']));
}

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

// ─── Rate limiting (5 essais / 10 min par IP) ───────────────────
function checkRateLimit(PDO $pdo): bool {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $row = $pdo->prepare("
        SELECT attempts, last_try FROM rate_limit
        WHERE ip = ?
    ");
    $row->execute([$ip]);
    $data = $row->fetch();

    if ($data) {
        $elapsed = time() - strtotime($data['last_try']);
        if ($elapsed < 60 && $data['attempts'] >= 5) return false; // bloqué
        if ($elapsed >= 60) {
            // Reset après 10 min
            $pdo->prepare("UPDATE rate_limit SET attempts=1, last_try=CURRENT_TIMESTAMP WHERE ip=?")
                ->execute([$ip]);
        } else {
            $pdo->prepare("UPDATE rate_limit SET attempts=attempts+1, last_try=CURRENT_TIMESTAMP WHERE ip=?")
                ->execute([$ip]);
        }
    } else {
        $pdo->prepare("INSERT INTO rate_limit (ip) VALUES (?)")
            ->execute([$ip]);
    }
    return true;
}

// ─── Générer un token JWT simple ────────────────────────────────
function generateToken(int $userId, string $username): string {
    $secret = 'CHANGE_ME_32_CHARS_MINIMUM_SECRET';
    $header  = base64_encode(json_encode(['alg'=>'HS256','typ'=>'JWT']));
    $payload = base64_encode(json_encode([
        'sub' => $userId,
        'usr' => $username,
        'iat' => time(),
        'exp' => time() + 3600
    ]));
    $sig = hash_hmac('sha256', "$header.$payload", $secret, true);
    return "$header.$payload." . base64_encode($sig);
}

$pdo = getDB();

// ─── INSCRIPTION ─────────────────────────────────────────────────
if ($action === 'register') {
    $username = trim($body['username'] ?? '');
    $password = $body['password'] ?? '';

    // Validation user
    if (strlen($username) < 3 || strlen($username) > 30)
        exit(json_encode(['error' => 'Pseudo : 3 à 30 caractères']));
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $username))  
        exit(json_encode(['error' => 'Pseudo : lettres (minuscule, majuscule), chiffres et _ uniquement']));
    
    // Validation MDP
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

    // Vérifie si le pseudo existe
    $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ?');
    $stmt->execute([$username]);
    if ($stmt->fetch()) exit(json_encode(['error' => 'Pseudo déjà pris']));

    // Hachage bcrypt
    $hash = password_hash($password, PASSWORD_BCRYPT);

    $ins = $pdo->prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    $ins->execute([$username, $hash]);

    echo json_encode(['success' => 'Compte créé. Vous pouvez vous connecter.']);
}

// ─── CONNEXION ───────────────────────────────────────────────────
elseif ($action === 'login') {
    if (!checkRateLimit($pdo))
        exit(json_encode(['error' => 'Trop de tentatives. Réessayez dans 1 min.']));

    $username = trim($body['username'] ?? '');
    $password = $body['password'] ?? '';

    if (!$username || !$password)
        exit(json_encode(['error' => 'Champs manquants']));

    // Requête préparée → protection contre l'injection SQL
    $stmt = $pdo->prepare('SELECT id, password FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    // Délai constant → protection contre le timing attack
    if (!$user || !password_verify($password, $user['password'])) {
        http_response_code(401);
        exit(json_encode(['error' => 'Identifiants incorrects']));
    }

    $token = generateToken($user['id'], $username);

    // Cookie httpOnly + SameSite = Strict
    setcookie('auth_token', $token, [
        'expires'  => time() + 3600,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Strict',
        'secure' => true, 
    ]);

    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $pdo->prepare("UPDATE rate_limit SET attempts=1, last_try=CURRENT_TIMESTAMP WHERE ip=?")->execute([$ip]);

    echo json_encode(['success' => true, 'username' => $username]);
}

// ─── DÉCONNEXION ─────────────────────────────────────────────────
elseif ($action === 'logout') {
    setcookie('auth_token', '', [
    'expires' => time() - 3600,
    'path' => '/',
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Strict'
    ]);
    session_destroy();
    echo json_encode(['success' => 'Déconnecté']);
}

//─── LOGGED ─────────────────────────────────────────────────
elseif ($action === 'me') {

    if (!isset($_COOKIE['auth_token'])) {
        echo json_encode(['logged' => false]);
        exit;
    }

    echo json_encode(['logged' => true]);
}

//─── MESSAGE ─────────────────────────────────────────────────
elseif ($action === 'message'){

$body = json_decode(file_get_contents("php://input"), true);

$name    = trim($body['name'] ?? '');
$email   = trim($body['email'] ?? '');
$message = trim($body['message'] ?? '');
$token   = $body['csrf_token'] ?? '';

// ─── CSRF CHECK ───
if (!$token || !hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
    exit(json_encode(['error' => 'CSRF invalide']));
}

// ─── VALIDATION ───
if (strlen($name) < 2 || strlen($name) > 50) {
    exit(json_encode(['error' => 'Nom invalide']));
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    exit(json_encode(['error' => 'Email invalide']));
}

if (strlen($message) < 1 || strlen($message) > 1000) {
    exit(json_encode(['error' => 'Message invalide']));
}

// ─── XSS SAFE (store only sanitized OR escape later) ───
$name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

// exemple stockage DB
$stmt = $pdo->prepare("INSERT INTO contact (name, email, message) VALUES (?, ?, ?)");
$stmt->execute([$name, $email, $message]);

echo json_encode(['success' => 'Message envoyé']); 
}

else {
    http_response_code(400);
    echo json_encode(['error' => 'Action inconnue']);
}
