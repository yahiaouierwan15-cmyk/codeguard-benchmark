<?php
// submit.php - Process guestbook submission
// WARNING: This file intentionally contains security vulnerabilities for benchmark testing.

require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    ?>
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"><title>Sign Guestbook</title></head>
    <body>
        <h1>Sign the Guestbook</h1>
        <form method="POST" action="submit.php">
            <label>Name: <input type="text" name="name" required></label><br><br>
            <label>Message:<br>
                <textarea name="message" rows="5" cols="40" required></textarea>
            </label><br><br>
            <button type="submit">Submit</button>
        </form>
        <p><a href="index.php">Back to guestbook</a></p>
    </body>
    </html>
    <?php
    exit;
}

$name = $_POST['name'];
$message = $_POST['message'];

// CWE-89: SQL Injection — user inputs concatenated directly into SQL query
$db = get_db();
$query = "INSERT INTO entries (name, message) VALUES ('" . $name . "', '" . $message . "')";
$db->exec($query);

header('Location: index.php');
exit;
