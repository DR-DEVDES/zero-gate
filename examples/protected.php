<?php
declare(strict_types=1);

// Keep this include before any HTML, whitespace, or output.
require_once dirname(__DIR__) . '/zero-gate.php';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Protected page</title>
</head>
<body>
    <h1>Welcome — you are authenticated.</h1>
    <p>This page is protected by ZERO GATE.</p>
    <p><a href="?logout=1">Log out</a></p>
</body>
</html>
