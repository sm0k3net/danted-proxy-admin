<?php

function html(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function post(string $name): string
{
    return is_string($_POST[$name] ?? null) ? $_POST[$name] : '';
}

function redirectHome(): never
{
    header('Location: ' . ($_SERVER['SCRIPT_NAME'] ?? '/index.php'), true, 303);
    exit;
}

function manageAccounts(array $request): array
{
    $payload = json_encode($request, JSON_THROW_ON_ERROR);
    if (strlen($payload) > 4096) {
        throw new RuntimeException('The account request is too large.');
    }
    if (!function_exists('proc_open')) {
        throw new RuntimeException('Enable proc_open in the PHP-FPM pool.');
    }
    $process = @proc_open(
        ['/usr/bin/sudo', '-n', '/usr/local/sbin/dante-proxy-admin'],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'a']],
        $pipes
    );
    if (!is_resource($process)) {
        throw new RuntimeException('The proxy account helper is unavailable. Check its installation and sudo permissions.');
    }
    $written = @fwrite($pipes[0], $payload);
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $exit = proc_close($process);
    if ($written !== strlen($payload) || $exit !== 0 || !is_string($output)) {
        throw new RuntimeException('The proxy account helper is unavailable. Check its installation and sudo permissions.');
    }
    $response = json_decode($output, true);
    if (!is_bool($response['ok'] ?? null)) {
        throw new RuntimeException('The proxy account helper returned an invalid response.');
    }
    if (!$response['ok']) {
        throw new RuntimeException($response['error'] ?? 'The proxy account operation failed.');
    }
    return $response;
}

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
$admin = getenv('DANTE_ADMIN_USERNAME');
$hash = getenv('DANTE_ADMIN_PASSWORD_HASH');
if (!$admin || !$hash || password_get_info($hash)['algo'] === null) {
    http_response_code(503);
    error_log('Dante Proxy Admin: configure DANTE_ADMIN_USERNAME and DANTE_ADMIN_PASSWORD_HASH.');
    exit('The admin panel has not been configured.');
}

session_name('DanteProxyAdmin');
if (!@session_start([
    'use_strict_mode' => true,
    'use_only_cookies' => true,
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
])) {
    http_response_code(503);
    error_log('Dante Proxy Admin: could not start the PHP session. Check session.save_path.');
    exit('The admin panel is temporarily unavailable.');
}
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));
$credential = hash('sha256', $admin . "\0" . $hash);
$signedIn = hash_equals($credential, $_SESSION['credential'] ?? '');
$message = '';
$messageType = 'error';
$action = post('action');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], post('csrf'))) {
        http_response_code(403);
        exit('Session expired. Reload the page and try again.');
    }
    if ($action === 'login' && !$signedIn) {
        $validPassword = password_verify(post('password'), $hash);
        if ($validPassword && hash_equals($admin, post('username'))) {
            if (!session_regenerate_id(true)) {
                http_response_code(503);
                exit('The admin panel could not renew the session.');
            }
            $_SESSION = ['csrf' => bin2hex(random_bytes(32)), 'credential' => $credential];
            redirectHome();
        }
        $message = 'Invalid username or password.';
    } elseif ($action === 'logout' && $signedIn) {
        $_SESSION = [];
        session_destroy();
        redirectHome();
    } elseif ($signedIn) {
        $actions = [
            'create' => 'Account created.',
            'lock' => 'Account locked.',
            'unlock' => 'Account unlocked.',
            'delete' => 'Account deleted.',
        ];
        if (!isset($actions[$action])) {
            http_response_code(400);
            exit('Unknown account action.');
        }
        $request = ['action' => $action, 'username' => trim(post('username'))];
        if ($action === 'create') {
            $request['password'] = post('password');
        }
        try {
            manageAccounts($request);
            $_SESSION['flash'] = ['success', $actions[$action]];
        } catch (RuntimeException | JsonException $error) {
            $_SESSION['flash'] = ['error', $error->getMessage()];
        }
        redirectHome();
    }
}

if (isset($_SESSION['flash'])) {
    [$messageType, $message] = $_SESSION['flash'];
    unset($_SESSION['flash']);
}
$csrf = $_SESSION['csrf'];
session_write_close();
$accounts = [];
$canManage = $signedIn;
if ($signedIn) {
    try {
        $accounts = manageAccounts(['action' => 'list'])['accounts'];
    } catch (RuntimeException $error) {
        $canManage = false;
        $message = trim($message . ' ' . $error->getMessage());
        $messageType = 'error';
    }
}
$statusLabels = ['active' => 'Active', 'locked' => 'Locked', 'no-password' => 'No password', 'unknown' => 'Unknown'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dante Proxy Admin</title>
    <link rel="stylesheet" href="style.css">
    <script src="panel.js" defer></script>
</head>
<body>
<main class="<?= $signedIn ? 'workspace' : 'login' ?>">
    <header>
        <h1>Dante Proxy Admin</h1>
        <?php if ($signedIn): ?>
            <form method="post">
                <input type="hidden" name="csrf" value="<?= html($csrf) ?>">
                <button name="action" value="logout" class="secondary">Log out</button>
            </form>
        <?php endif; ?>
    </header>
    <?php if ($message !== ''): ?>
        <p role="status" class="notice <?= html($messageType) ?>"><?= html($message) ?></p>
    <?php endif; ?>
    <?php if (!$signedIn): ?>
        <section>
            <h2>Sign in</h2>
            <form method="post" class="fields">
                <input type="hidden" name="csrf" value="<?= html($csrf) ?>">
                <label>Username<input name="username" autocomplete="username" required></label>
                <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
                <button name="action" value="login">Sign in</button>
            </form>
        </section>
    <?php elseif ($canManage): ?>
        <section>
            <h2>Add a proxy account</h2>
            <form method="post" class="create">
                <input type="hidden" name="csrf" value="<?= html($csrf) ?>">
                <label>Username<input name="username" placeholder="proxyteam" pattern="proxy[A-Za-z0-9_]{1,27}" maxlength="32" required></label>
                <label>Password<input name="password" type="password" autocomplete="new-password" minlength="12" required></label>
                <button name="action" value="create">Add account</button>
            </form>
            <p class="hint">Use the <code>proxy</code> prefix and a password of 12–72 bytes.</p>
        </section>
        <section>
            <h2>Managed accounts</h2>
            <?php if (!$accounts): ?>
                <p>No proxy accounts have been added.</p>
            <?php else: ?>
                <div class="table-container">
                    <table>
                        <thead><tr><th scope="col">Username</th><th scope="col">UID</th><th scope="col">Password status</th><th scope="col">Actions</th></tr></thead>
                        <tbody>
                        <?php foreach ($accounts as $account): ?>
                            <tr>
                                <th scope="row"><?= html($account['username']) ?></th>
                                <td><?= (int) $account['uid'] ?></td>
                                <td><span class="status <?= html($account['status']) ?>"><?= $statusLabels[$account['status']] ?></span></td>
                                <td>
                                    <form method="post" class="actions">
                                        <input type="hidden" name="csrf" value="<?= html($csrf) ?>">
                                        <input type="hidden" name="username" value="<?= html($account['username']) ?>">
                                        <?php if ($account['status'] === 'active'): ?>
                                            <button class="secondary" name="action" value="lock">Lock</button>
                                        <?php elseif ($account['status'] === 'locked'): ?>
                                            <button class="secondary" name="action" value="unlock">Unlock</button>
                                        <?php endif; ?>
                                        <button class="danger" name="action" value="delete">Delete</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </section>
    <?php endif; ?>
</main>
</body>
</html>
