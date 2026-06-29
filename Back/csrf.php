<?php
/**
 * csrf.php – Génération et distribution du token CSRF
 *
 * Le token est stocké en session côté serveur et transmis au client
 * pour être renvoyé lors de chaque soumission de formulaire.
 * La vérification se fait via hash_equals() (temps constant → pas de timing attack).
 * La rotation a lieu dans auth.php après chaque validation réussie.
 */
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);

session_start();

header('Access-Control-Allow-Origin: http://localhost:8000');
header('Access-Control-Allow-Credentials: true');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store'); // Ne pas mettre en cache un token de sécurité

// Génère un token si absent (première visite) ou si la session est nouvelle
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // 256 bits d'entropie
}

echo json_encode(['csrf_token' => $_SESSION['csrf_token']]);
