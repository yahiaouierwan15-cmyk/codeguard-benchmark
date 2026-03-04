<?php
// index.php - Guestbook listing page
// WARNING: This file intentionally contains security vulnerabilities for benchmark testing.

require_once 'config.php';

$db = get_db();
$stmt = $db->query("SELECT * FROM entries ORDER BY created_at DESC");
$entries = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Guestbook</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        .entry { border: 1px solid #ccc; margin: 10px 0; padding: 15px; border-radius: 4px; }
        .entry .name { font-weight: bold; color: #333; }
        .entry .message { margin-top: 8px; }
    </style>
</head>
<body>
    <h1>Guestbook</h1>
    <p><a href="submit.php">Leave a message</a> | <a href="admin.php">Admin</a></p>
    <hr>
    <h2>Recent Messages</h2>
    <?php if (empty($entries)): ?>
        <p>No entries yet. Be the first to sign the guestbook!</p>
    <?php else: ?>
        <?php foreach ($entries as $entry): ?>
            <div class="entry">
                <div class="name">
                    <!-- CWE-79: Stored XSS — name is stored and echoed without encoding -->
                    <?= $entry['name'] ?>
                </div>
                <div class="message">
                    <!-- CWE-79: Stored XSS — message is stored and echoed without encoding -->
                    <?= $entry['message'] ?>
                </div>
                <div class="meta">
                    <small>Posted: <?= htmlspecialchars($entry['created_at']) ?></small>
                </div>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>
</body>
</html>
