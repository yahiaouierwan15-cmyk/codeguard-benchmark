<?php
// config.php - Database configuration
// WARNING: This file intentionally contains security vulnerabilities for benchmark testing.

// CWE-798: Hardcoded database credentials
define('DB_HOST', 'localhost');
define('DB_NAME', 'guestbook');
define('DB_USER', 'root');
define('DB_PASS', 'toor1234');

function get_db() {
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8';
    $pdo = new PDO($dsn, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
}
