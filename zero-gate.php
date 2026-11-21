<?php
declare(strict_types=1);

/**
 * ZERO GATE — modern PHP page protection
 * Requires PHP 8.1+
 *
 * Usage:
 * 1. Configure the settings below.
 * 2. Include this file at the VERY TOP of every protected PHP page:
 *      require_once __DIR__ . '/zero-gate.php';
 * 3. Logout link:
 *      <a href="?logout=1">Logout</a>
 *
 * Generate a password hash:
 *		echo password_hash('meinpasswort', PASSWORD_DEFAULT);
 */

############################################################
# CONFIGURATION
############################################################

const USE_USERNAME = false;       // true = username + password
const SESSION_TIMEOUT = 20;       // minutes; 0 = no inactivity timeout
const LOGIN_TITLE = 'PRIVATE ACCESS';
const BRAND_NAME = 'ZERO GATE';
const LOGOUT_URL = './';

// Store password_hash() values here, NEVER plain-text passwords.
// Password-only mode:
$ACCESS_USERS = [
    // Add your own password hash here. Never commit real credentials.
    // 'admin' => 'PASTE_PASSWORD_HASH_HERE',
];

// Username mode example:
// const USE_USERNAME = true;
// $ACCESS_USERS = [
//     'admin' => '$2y$10$REPLACE_WITH_ADMIN_PASSWORD_HASH',
//     'editor' => '$2y$10$REPLACE_WITH_EDITOR_PASSWORD_HASH',
// ];

############################################################
# SESSION / SECURITY BOOTSTRAP
############################################################

if (headers_sent()) {
    http_response_code(500);
    exit('ZERO GATE must be included before any output.');
}

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

session_name('ZERO_GATE_SESSION');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: DENY');

function zg_redirect(string $url): never
{
    header('Location: ' . $url, true, 303);
    exit;
}

function zg_csrf_token(): string
{
    if (empty($_SESSION['zg_csrf'])) {
        $_SESSION['zg_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['zg_csrf'];
}

function zg_valid_csrf(): bool
{
    return isset($_POST['csrf_token'], $_SESSION['zg_csrf'])
        && is_string($_POST['csrf_token'])
        && hash_equals($_SESSION['zg_csrf'], $_POST['csrf_token']);
}

function zg_is_authenticated(): bool
{
    return !empty($_SESSION['zg_authenticated'])
        && $_SESSION['zg_authenticated'] === true;
}

function zg_logout(): never
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'] ?: '/',
            'domain' => $params['domain'] ?? '',
            'secure' => (bool)($params['secure'] ?? false),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    session_destroy();
    zg_redirect(LOGOUT_URL);
}

############################################################
# LOGOUT
############################################################

if (isset($_GET['logout'])) {
    zg_logout();
}

############################################################
# SESSION TIMEOUT
############################################################

if (zg_is_authenticated()) {
    $lastActivity = (int)($_SESSION['zg_last_activity'] ?? time());

    if (SESSION_TIMEOUT > 0 && (time() - $lastActivity) > SESSION_TIMEOUT * 60) {
        $_SESSION = [];
        session_regenerate_id(true);
    } else {
        $_SESSION['zg_last_activity'] = time();
    }
}

############################################################
# LOGIN HANDLER
############################################################

$error = '';
$attempts = (int)($_SESSION['zg_attempts'] ?? 0);
$lockedUntil = (int)($_SESSION['zg_locked_until'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !zg_is_authenticated()) {
    if (!zg_valid_csrf()) {
        $error = 'Your session expired. Please try again.';
    } elseif ($lockedUntil > time()) {
        $remaining = $lockedUntil - time();
        $error = 'Too many attempts. Try again in ' . $remaining . ' seconds.';
    } else {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');

        $valid = false;

        if (USE_USERNAME) {
            if (isset($ACCESS_USERS[$username]) && is_string($ACCESS_USERS[$username])) {
                $valid = password_verify($password, $ACCESS_USERS[$username]);
            }
        } else {
            foreach ($ACCESS_USERS as $hash) {
                if (is_string($hash) && password_verify($password, $hash)) {
                    $valid = true;
                    break;
                }
            }
        }

        if ($valid) {
            session_regenerate_id(true);
            $_SESSION['zg_authenticated'] = true;
            $_SESSION['zg_last_activity'] = time();
            $_SESSION['zg_attempts'] = 0;
            $_SESSION['zg_locked_until'] = 0;
            unset($_SESSION['zg_csrf']);
            zg_redirect($_SERVER['REQUEST_URI'] ?? './');
        }

        $attempts++;
        $_SESSION['zg_attempts'] = $attempts;

        // Simple session-level throttling. For public-facing systems,
        // add server-side/IP-based throttling at the web server or database layer.
        if ($attempts >= 5) {
            $_SESSION['zg_locked_until'] = time() + 60;
            $_SESSION['zg_attempts'] = 0;
            $error = 'Access temporarily locked. Try again in 60 seconds.';
        } else {
            $error = 'Access denied. Check your credentials.';
        }
    }
}

############################################################
# AUTHORIZATION GATE
############################################################

if (!zg_is_authenticated()) {
    http_response_code(401);
    $csrf = htmlspecialchars(zg_csrf_token(), ENT_QUOTES, 'UTF-8');
    $safeTitle = htmlspecialchars(LOGIN_TITLE, ENT_QUOTES, 'UTF-8');
    $safeBrand = htmlspecialchars(BRAND_NAME, ENT_QUOTES, 'UTF-8');
    $safeError = htmlspecialchars($error, ENT_QUOTES, 'UTF-8');
    ?>
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="robots" content="noindex, nofollow">
        <meta name="theme-color" content="#08090b">
        <title><?= $safeTitle ?> — <?= $safeBrand ?></title>
        <style>
            :root {
                color-scheme: dark;
                --bg: #08090b;
                --panel: rgba(17, 19, 23, .88);
                --line: rgba(255,255,255,.13);
                --text: #f1f1ed;
                --muted: #858991;
                --red: #ff453a;
                --mono: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
                --sans: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }
            * { box-sizing: border-box; }
            html, body { min-height: 100%; }
            body {
                margin: 0; min-height: 100vh; overflow: hidden;
                display: grid; place-items: center; padding: 24px;
                background:
                    radial-gradient(ellipse at 50% 45%, rgba(255,255,255,.075), transparent 36%),
                    linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px),
                    var(--bg);
                background-size: auto, 64px 64px, 64px 64px, auto;
                color: var(--text); font-family: var(--sans);
            }
            body::before {
                content: ""; position: fixed; inset: 0; pointer-events: none;
                opacity: .13; background: repeating-linear-gradient(0deg, transparent 0 3px, rgba(255,255,255,.05) 4px);
            }
            .shell { width: min(100%, 460px); position: relative; }
            .meta {
                display: flex; justify-content: space-between; gap: 16px;
                margin: 0 0 15px; color: var(--muted);
                font: 10px var(--mono); letter-spacing: .16em; text-transform: uppercase;
            }
            .status { color: var(--red); }
            .panel {
                position: relative; padding: clamp(26px, 6vw, 42px);
                background: var(--panel); border: 1px solid var(--line);
                box-shadow: 0 30px 100px rgba(0,0,0,.55);
                backdrop-filter: blur(18px);
            }
            .mark {
                width: 10px; height: 10px; display: block; margin-bottom: 35px;
                background: var(--red); box-shadow: 0 0 22px rgba(255,69,58,.55);
            }
            .kicker { color: var(--muted); font: 10px var(--mono); letter-spacing: .22em; }
            h1 {
                margin: 12px 0 10px; font-size: clamp(36px, 9vw, 58px);
                line-height: .92; letter-spacing: -.075em; font-weight: 650;
            }
            .description { margin: 0 0 34px; color: var(--muted); font-size: 13px; line-height: 1.6; }
            label {
                display: block; margin: 18px 0 8px; color: #a9adb4;
                font: 10px var(--mono); letter-spacing: .15em; text-transform: uppercase;
            }
            input {
                width: 100%; height: 52px; padding: 0 15px;
                border: 1px solid var(--line); border-radius: 0;
                outline: none; background: rgba(0,0,0,.35); color: var(--text);
                font: 14px var(--mono); transition: border-color .2s, background .2s;
            }
            input:focus { border-color: rgba(255,255,255,.65); background: rgba(255,255,255,.045); }
            input::placeholder { color: #555a62; }
            .submit {
                width: 100%; height: 54px; margin-top: 24px;
                border: 1px solid var(--text); background: var(--text); color: #090a0c;
                font: 11px var(--mono); letter-spacing: .18em; text-transform: uppercase;
                transition: background .2s, color .2s, border-color .2s;
                cursor: pointer;
            }
            .submit:hover { background: var(--red); border-color: var(--red); color: white; }
            .error {
                margin: 0 0 20px; padding: 12px 14px;
                border-left: 2px solid var(--red); background: rgba(255,69,58,.09);
                color: #ffaaa5; font: 11px var(--mono); line-height: 1.5;
            }
            .foot {
                display: flex; justify-content: space-between; gap: 15px;
                margin-top: 15px; color: #62666e;
                font: 9px var(--mono); letter-spacing: .12em; text-transform: uppercase;
            }
            @media (max-width: 480px) {
                body { padding: 18px; }
                .panel { padding: 27px 22px; }
                .foot { flex-direction: column; }
            }
            @media (prefers-reduced-motion: no-preference) {
                .panel { animation: appear .8s cubic-bezier(.2,.8,.2,1) both; }
                @keyframes appear { from { opacity: 0; transform: translateY(18px); } to { opacity: 1; transform: translateY(0); } }
            }
        </style>
    </head>
    <body>
        <main class="shell">
            <div class="meta"><span><?= $safeBrand ?> / ACCESS NODE</span><span class="status">● RESTRICTED</span></div>
            <section class="panel">
                <i class="mark"></i>
                <div class="kicker">IDENTITY VERIFICATION / 01</div>
                <h1><?= $safeTitle ?></h1>
                <p class="description">This environment is protected. Authenticate to continue.</p>

                <?php if ($safeError !== ''): ?>
                    <div class="error" role="alert"><?= $safeError ?></div>
                <?php endif; ?>

                <form method="post" action="" autocomplete="on">
                    <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                    <?php if (USE_USERNAME): ?>
                        <label for="username">Username</label>
                        <input id="username" name="username" type="text" placeholder="Enter username" autocomplete="username" required autofocus>
                    <?php endif; ?>

                    <label for="password">Access key</label>
                    <input id="password" name="password" type="password" placeholder="Enter access key" autocomplete="current-password" required <?= USE_USERNAME ? '' : 'autofocus' ?>>

                    <button class="submit" type="submit">Authenticate <span aria-hidden="true">↗</span></button>
                </form>
            </section>
            <div class="foot"><span>SECURE SESSION / <?= date('Y') ?></span><span>UNAUTHORIZED ACCESS PROHIBITED</span></div>
        </main>
    </body>
    </html>
    <?php
    exit;
}

// Authenticated: execution continues into the protected page.
