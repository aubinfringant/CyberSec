<?php
$user = $_POST['username']; //On récupére n'importe quoi
$password = $_POST['password']; //Pareil et en clair
$sql = "SELECT * FROM users WHERE login = '".$user."' AND mp = '".$password."'"; //Injection SQL car on recupére les entrées sans vérification
$result = mysqli_query($conn, $sql); // on envoie le tout directement a la base de donné sans protection

// parser les variables
$username = trim($_POST['username']);

if (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
    exit('Nom invalide'); 
}

$password = $_POST['password'];

if (strlen($password) < 12) {
    exit('Mot de passe trop court');
}

// requête préparée

$stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?');
$stmt->execute([$username]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

// sécuriser l'envoi et vérifier le mdp
if (!$user || !password_verify($password, $user['password'])) {
    exit('Identifiants incorrects');
}

// log secure si connexion
echo 'Bienvenue ' . htmlspecialchars($user['username']);