<?php
function getDB(): PDO {
    $path = __DIR__ . '/../database/users.db';
    $dir  = dirname($path);
    if (!is_dir($dir)) mkdir($dir, 0750, true);

    $pdo = new PDO('sqlite:' . $path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA foreign_keys=ON');

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL UNIQUE,
            password   TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS rate_limit (
            ip         TEXT NOT NULL,
            attempts   INTEGER DEFAULT 1,
            last_try   DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ");
    return $pdo;
}