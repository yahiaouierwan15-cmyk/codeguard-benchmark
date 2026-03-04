<?php
// admin.php - Admin panel for guestbook management
// WARNING: This file intentionally contains security vulnerabilities for benchmark testing.

require_once 'config.php';

$action = $_GET['action'] ?? 'list';

if ($action === 'list') {
    $db = get_db();
    $stmt = $db->query("SELECT * FROM entries ORDER BY created_at DESC");
    $entries = $stmt->fetchAll(PDO::FETCH_ASSOC);
    ?>
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"><title>Admin Panel</title></head>
    <body>
        <h1>Admin Panel</h1>
        <h2>Manage Entries</h2>
        <table border="1" cellpadding="5">
            <tr><th>ID</th><th>Name</th><th>Message</th><th>Actions</th></tr>
            <?php foreach ($entries as $e): ?>
            <tr>
                <td><?= $e['id'] ?></td>
                <td><?= htmlspecialchars($e['name']) ?></td>
                <td><?= htmlspecialchars($e['message']) ?></td>
                <td>
                    <a href="admin.php?action=delete&id=<?= $e['id'] ?>">Delete</a> |
                    <a href="admin.php?action=view-log&file=<?= $e['id'] ?>.log">View Log</a>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
        <hr>
        <h2>Export Entries</h2>
        <form method="GET" action="admin.php">
            <input type="hidden" name="action" value="export">
            Format: <input type="text" name="format" value="csv">
            <button type="submit">Export</button>
        </form>
    </body>
    </html>
    <?php
} elseif ($action === 'delete') {
    $id = $_GET['id'] ?? '';
    $db = get_db();
    $db->exec("DELETE FROM entries WHERE id = " . $id);
    header('Location: admin.php');
    exit;
} elseif ($action === 'view-log') {
    $file = $_GET['file'] ?? '';
    // CWE-22: Path Traversal — user-supplied filename used directly in file_get_contents
    $log_dir = '/var/log/guestbook/';
    $content = file_get_contents($log_dir . $file);
    echo '<pre>' . htmlspecialchars($content) . '</pre>';
} elseif ($action === 'export') {
    $format = $_GET['format'] ?? 'csv';
    // CWE-78: Command Injection — format parameter passed unsanitized to shell command
    $output = shell_exec('php export.php --format=' . $format);
    header('Content-Type: text/plain');
    echo $output;
}
