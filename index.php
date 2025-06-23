<?php
session_start();

// Configuration
$config = [
    'auth_method' => 'system', // 'system' for system users, 'file' for custom file
    'users_file' => '/etc/sockd.users',  // Only used if auth_method is 'file'
    'dante_config' => '/etc/danted.conf', // Adjust path as needed
    'reload_cmd' => 'sudo systemctl reload danted', // Command to reload Dante
    'admin_username' => 'demo',  // Change this
    'admin_password' => 'demo' // Change this to a strong password
];

// Check authentication
function isAuthenticated() {
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
}

// Handle login
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $username = $_POST['login_username'] ?? '';
    $password = $_POST['login_password'] ?? '';
    
    if ($username === $config['admin_username'] && $password === $config['admin_password']) {
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $username;
        $message = 'Login successful!';
        $messageType = 'success';
    } else {
        $message = 'Invalid username or password!';
        $messageType = 'danger';
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// If not authenticated, show login form
if (!isAuthenticated()) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dante Proxy Admin Login</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .login-card {
                max-width: 400px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                border: none;
                border-radius: 15px;
            }
            .login-header {
                background: rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                border-radius: 15px 15px 0 0;
                color: white;
                text-align: center;
                padding: 2rem;
            }
            .login-body {
                padding: 2rem;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card login-card">
                        <div class="login-header">
                            <i class="bi bi-shield-lock display-4 mb-3"></i>
                            <h3>Dante Proxy Admin</h3>
                            <p class="mb-0">Please login to continue</p>
                        </div>
                        <div class="login-body">
                            <?php if (!empty($message)): ?>
                            <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                                <?php echo htmlspecialchars($message); ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                            <?php endif; ?>
                            
                            <form method="POST">
                                <div class="mb-3">
                                    <label for="login_username" class="form-label">
                                        <i class="bi bi-person"></i> Username
                                    </label>
                                    <input type="text" class="form-control" id="login_username" name="login_username" required>
                                </div>
                                <div class="mb-4">
                                    <label for="login_password" class="form-label">
                                        <i class="bi bi-lock"></i> Password
                                    </label>
                                    <input type="password" class="form-control" id="login_password" name="login_password" required>
                                </div>
                                <button type="submit" name="login" class="btn btn-primary w-100">
                                    <i class="bi bi-box-arrow-in-right"></i> Login
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
    exit;
}

// Initialize users array
$users = [];
$message = '';
$messageType = '';

// Load system users (proxy users)
function loadUsers() {
    $users = [];
    // Get all users from /etc/passwd
    $passwd_content = file_get_contents('/etc/passwd');
    $lines = explode("\n", $passwd_content);
    
    foreach ($lines as $line) {
        if (empty($line)) continue;
        $parts = explode(':', $line);
        if (count($parts) >= 7) {
            $username = $parts[0];
            $shell = $parts[6];
            
            // Only include users with prefix 'proxy'
            if (strpos($username, 'proxy') === 0) {
                $users[] = [
                    'username' => $username,
                    'uid' => $parts[2],
                    'shell' => $shell,
                    'active' => $shell !== '/bin/false' ? false : true,
                    'is_system' => true
                ];
            }
        }
    }
    return $users;
}

// Create system user
function createSystemUser($username, $password) {
    // Create user exactly like test123 (system user with -r flag)
    $cmd = "sudo /usr/sbin/useradd -r -s /bin/false " . escapeshellarg($username) . " 2>&1";
    exec($cmd, $output, $return_var);
    
    if ($return_var === 0) {
        // Use passwd command directly (more reliable for system users)
        $descriptorspec = array(
            0 => array("pipe", "r"),  // stdin
            1 => array("pipe", "w"),  // stdout
            2 => array("pipe", "w")   // stderr
        );
        
        $process = proc_open("sudo /usr/bin/passwd " . escapeshellarg($username), $descriptorspec, $pipes);
        
        if (is_resource($process)) {
            // Write password twice (as passwd command expects)
            fwrite($pipes[0], $password . "\n");
            fwrite($pipes[0], $password . "\n");
            fclose($pipes[0]);
            
            // Get output
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            
            $return_var = proc_close($process);
            
            // Verify password was set
            if ($return_var === 0) {
                $cmd = "sudo /usr/bin/passwd -S " . escapeshellarg($username) . " 2>&1";
                exec($cmd, $status_output, $status_return);
                
                if ($status_return === 0 && !empty($status_output[0])) {
                    return strpos($status_output[0], ' P ') !== false;
                }
            }
        }
    }
    return false;
}

// Delete system user
function deleteSystemUser($username) {
    // Only delete users that start with 'proxy' for safety
    if (strpos($username, 'proxy') !== 0) {
        return false;
    }
    
    $cmd = "sudo /usr/sbin/userdel " . escapeshellarg($username) . " 2>&1";
    exec($cmd, $output, $return_var);
    return $return_var === 0;
}

// Lock/unlock user account
function toggleUserAccount($username, $lock = true) {
    // Only modify users that start with 'proxy' for safety
    if (strpos($username, 'proxy') !== 0) {
        return false;
    }
    
    if ($lock) {
        $cmd = "sudo /usr/sbin/usermod -L " . escapeshellarg($username) . " 2>&1";
    } else {
        $cmd = "sudo /usr/sbin/usermod -U " . escapeshellarg($username) . " 2>&1";
    }
    exec($cmd, $output, $return_var);
    return $return_var === 0;
}

// Check if user is locked
function isUserLocked($username) {
    // Only check users that start with 'proxy' for safety
    if (strpos($username, 'proxy') !== 0) {
        return false;
    }
    
    $cmd = "sudo /usr/bin/passwd -S " . escapeshellarg($username) . " 2>/dev/null";
    exec($cmd, $output, $return_var);
    if ($return_var === 0 && !empty($output[0])) {
        return strpos($output[0], ' L ') !== false;
    }
    return false;
}

// Reload Dante service
function reloadDante($cmd) {
    exec($cmd . ' 2>&1', $output, $return_var);
    return $return_var === 0;
}

// Handle form submissions
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'add_user':
                $username = trim($_POST['username']);
                $password = trim($_POST['password']);
                
                if (!empty($username) && !empty($password)) {
                    // Validate username (alphanumeric + underscore, must start with 'proxy')
                    if (!preg_match('/^proxy[a-zA-Z0-9_]+$/', $username)) {
                        $message = "Username must start with 'proxy' and contain only letters, numbers, and underscores!";
                        $messageType = 'danger';
                    } else {
                        // Check if user already exists
                        $existing_users = loadUsers();
                        $exists = false;
                        foreach ($existing_users as $user) {
                            if ($user['username'] === $username) {
                                $exists = true;
                                break;
                            }
                        }
                        
                        if (!$exists) {
                            if (createSystemUser($username, $password)) {
                                reloadDante($config['reload_cmd']);
                                $message = "User '$username' created successfully!";
                                $messageType = 'success';
                            } else {
                                $message = "Error creating system user '$username'! Check server logs for details.";
                                $messageType = 'danger';
                            }
                        } else {
                            $message = "User '$username' already exists!";
                            $messageType = 'warning';
                        }
                    }
                } else {
                    $message = "Username and password are required!";
                    $messageType = 'danger';
                }
                break;
                
            case 'toggle_user':
                $username = $_POST['username'];
                $users = loadUsers();
                $user_found = false;
                
                foreach ($users as $user) {
                    if ($user['username'] === $username) {
                        $user_found = true;
                        $is_locked = isUserLocked($username);
                        
                        if (toggleUserAccount($username, !$is_locked)) {
                            reloadDante($config['reload_cmd']);
                            $status = $is_locked ? 'activated' : 'deactivated';
                            $message = "User '$username' $status successfully!";
                            $messageType = 'success';
                        } else {
                            $message = "Error updating user '$username' status!";
                            $messageType = 'danger';
                        }
                        break;
                    }
                }
                
                if (!$user_found) {
                    $message = "User '$username' not found!";
                    $messageType = 'danger';
                }
                break;
                
            case 'delete_user':
                $username = $_POST['username'];
                
                if (deleteSystemUser($username)) {
                    reloadDante($config['reload_cmd']);
                    $message = "User '$username' deleted successfully!";
                    $messageType = 'success';
                } else {
                    $message = "Error deleting user '$username'!";
                    $messageType = 'danger';
                }
                break;
        }
    }
}

// Load current users
$users = loadUsers();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dante Proxy User Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        .status-badge {
            font-size: 0.8em;
        }
        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-group-sm .btn {
            padding: 0.25rem 0.5rem;
            font-size: 0.875rem;
        }
    </style>
</head>
<body class="bg-light">
    <div class="container mt-4">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <!-- Header -->
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h3 class="mb-0"><i class="bi bi-shield-lock"></i> Dante Proxy User Management</h3>
                        <div>
                            <span class="text-light me-3">
                                <i class="bi bi-person-circle"></i> Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>
                            </span>
                            <a href="?logout=1" class="btn btn-outline-light btn-sm">
                                <i class="bi bi-box-arrow-right"></i> Logout
                            </a>
                        </div>
                    </div>
                </div>

                <!-- Messages -->
                <?php if (!empty($message)): ?>
                <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                    <?php echo htmlspecialchars($message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
                <?php endif; ?>

                <!-- Add User Form -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="bi bi-person-plus"></i> Add New User</h5>
                    </div>
                    <div class="card-body">
                        <form method="POST" class="row g-3">
                            <input type="hidden" name="action" value="add_user">
                            <div class="col-md-4">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username" name="username" 
                                       placeholder="proxyuser1" required pattern="proxy[a-zA-Z0-9_]+" 
                                       title="Username must start with 'proxy' followed by letters, numbers, and underscore">
                                <small class="text-muted">Must start with 'proxy' (e.g., proxyuser1)</small>
                            </div>
                            <div class="col-md-4">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <div class="col-md-4 d-flex align-items-end">
                                <button type="submit" class="btn btn-primary">
                                    <i class="bi bi-plus-circle"></i> Add User
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Users List -->
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0"><i class="bi bi-people"></i> Current Users</h5>
                        <span class="badge bg-light text-dark"><?php echo count($users); ?> users</span>
                    </div>
                    <div class="card-body p-0">
                        <?php if (empty($users)): ?>
                        <div class="text-center py-5">
                            <i class="bi bi-inbox display-1 text-muted"></i>
                            <p class="text-muted mt-3">No proxy users found. Add your first user above.</p>
                        </div>
                        <?php else: ?>
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th><i class="bi bi-person"></i> Username</th>
                                        <th><i class="bi bi-shield"></i> Status</th>
                                        <th><i class="bi bi-terminal"></i> Shell Info</th>
                                        <th width="200"><i class="bi bi-gear"></i> Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($users as $user): ?>
                                    <tr class="<?php echo (isUserLocked($user['username'])) ? 'table-secondary' : ''; ?>">
                                        <td>
                                            <strong><?php echo htmlspecialchars($user['username']); ?></strong>
                                            <br><small class="text-muted">UID: <?php echo $user['uid']; ?></small>
                                        </td>
                                        <td>
                                            <?php if (!isUserLocked($user['username'])): ?>
                                                <span class="badge bg-success status-badge">
                                                    <i class="bi bi-check-circle"></i> Active
                                                </span>
                                            <?php else: ?>
                                                <span class="badge bg-secondary status-badge">
                                                    <i class="bi bi-lock"></i> Locked
                                                </span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <small class="text-muted">
                                                Shell: <?php echo htmlspecialchars($user['shell']); ?>
                                            </small>
                                        </td>
                                        <td>
                                            <div class="btn-group btn-group-sm" role="group">
                                                <!-- Toggle Status -->
                                                <form method="POST" class="d-inline">
                                                    <input type="hidden" name="action" value="toggle_user">
                                                    <input type="hidden" name="username" value="<?php echo htmlspecialchars($user['username']); ?>">
                                                    <button type="submit" class="btn <?php echo isUserLocked($user['username']) ? 'btn-success' : 'btn-warning'; ?>" 
                                                            title="<?php echo isUserLocked($user['username']) ? 'Unlock' : 'Lock'; ?>">
                                                        <i class="bi <?php echo isUserLocked($user['username']) ? 'bi-unlock' : 'bi-lock'; ?>"></i>
                                                    </button>
                                                </form>
                                                
                                                <!-- Delete User -->
                                                <form method="POST" class="d-inline" onsubmit="return confirm('Are you sure you want to delete user <?php echo htmlspecialchars($user['username']); ?>?')">
                                                    <input type="hidden" name="action" value="delete_user">
                                                    <input type="hidden" name="username" value="<?php echo htmlspecialchars($user['username']); ?>">
                                                    <button type="submit" class="btn btn-danger" title="Delete">
                                                        <i class="bi bi-trash"></i>
                                                    </button>
                                                </form>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Configuration Info -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="bi bi-info-circle"></i> Configuration</h6>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <small class="text-muted">
                                    <strong>Authentication:</strong> System Users
                                </small>
                            </div>
                            <div class="col-md-6">
                                <small class="text-muted">
                                    <strong>Config File:</strong> <?php echo htmlspecialchars($config['dante_config']); ?>
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-hide alerts after 5 seconds
        setTimeout(function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(function(alert) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            });
        }, 5000);
    </script>
</body>
</html>
