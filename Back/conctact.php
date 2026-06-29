<?php
session_start(); // Démarre ou reprend la session PHP

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Si le champ 'website' est rempli, c'est qu'un robot l'a soumis automatiquement.
$honeypot = $body['website'] ?? '';
if (!empty($honeypot)) {
    // On feint le succès pour que le robot pense avoir réussi, mais on stoppe tout.
    exit(json_encode(['success' => 'Message envoyé'])); 
}

header('Content-Type: application/json');


require_once 'db.php';

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

if (strlen($message) < 10 || strlen($message) > 1000) {
    exit(json_encode(['error' => 'Message invalide']));
}

// ─── XSS SAFE (store only sanitized OR escape later) ───
$name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

// exemple stockage DB
$stmt = $pdo->prepare("INSERT INTO contact (name, email, message) VALUES (?, ?, ?)");
$stmt->execute([$name, $email, $message]);

echo json_encode(['success' => 'Message envoyé']);