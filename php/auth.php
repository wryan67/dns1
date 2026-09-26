<?php
/******************************************************************************
 * dns1 - authentication pages
 *
 * Included by index.php. Handles signup, email verification, password reset,
 * login, profile and password change. Approval works the same way as lifevue:
 * an email listed in "preapproved" is auto-approved at signup and inherits the
 * level recorded there; anyone else is created unapproved and must be approved
 * before they can log in.
 ******************************************************************************/

function authPageStyles() {
    return '
        body { font-family: "Source Sans Pro", Arial, sans-serif; margin: 0; min-height: 100vh;
               display: flex; justify-content: center; align-items: center;
               background: #1f1815 url("assets/css/images/bg.jpg") center center / cover fixed no-repeat; }
        body:before { content: ""; position: fixed; inset: 0; background: rgba(31,24,21,0.65); z-index: 0; }
        .login-box { position: relative; z-index: 1; background: rgba(255,255,255,0.97); padding: 28px;
                     border-radius: 6px; box-shadow: 0 8px 30px rgba(0,0,0,0.45); width: 350px; }
        .login-box h2 { margin-top: 0; color: #35312f; font-weight: 900; letter-spacing: 0.05em;
                        text-transform: uppercase; font-size: 1.35em; }
        .brand { position: relative; z-index: 1; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; color: #444; }
        .form-group input { width: 100%; padding: 9px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .form-group input[readonly] { background: #f5f5f5; color: #666; }
        .btn-group { display: flex; gap: 10px; }
        .btn { flex: 1; padding: 10px; background-color: #337ab7; color: #fff; border: none; border-radius: 4px;
               font-weight: bold; cursor: pointer; text-align: center; text-decoration: none; }
        .btn:hover { background-color: #286090; }
        .btn-cancel { background-color: #6c757d; }
        .btn-cancel:hover { background-color: #545b62; }
        .error { color: #c0392b; margin-bottom: 15px; font-size: 0.9em; }
        .success { color: #1e8449; margin-bottom: 15px; font-size: 0.9em; }
        .pw-rules { font-size: 0.8em; color: #666; margin-top: 4px; }
        a { color: #337ab7; }
    ';
}

function authPageHead($title) {
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
       . '<meta name="viewport" content="width=device-width, initial-scale=1">'
       . '<title>' . htmlspecialchars($title) . ' - DNS1</title>'
       . '<link rel="stylesheet" href="assets/vendor/css/source-sans-pro.css">'
       . '<style>' . authPageStyles() . '</style></head><body>';
}

/* ---- Logout ---- */
if (isset($_POST['action']) && $_POST['action'] === 'logout') {
    if (hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {
        $_SESSION = [];
        session_destroy();
    }
    header('Location: index.php');
    exit;
}

/* ---- Sign Up ---- */
if (isset($_GET['action']) && $_GET['action'] === 'signup') {
    $error = ''; $success = ''; $formEmail = ''; $formName = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {
            $error = 'Invalid request.';
        } else {
            $formEmail = trim($_POST['email'] ?? '');
            $formName  = trim($_POST['name'] ?? '');
            $pw1 = $_POST['password'] ?? '';
            $pw2 = $_POST['password2'] ?? '';

            if (!filter_var($formEmail, FILTER_VALIDATE_EMAIL)) {
                $error = 'Please enter a valid email.';
            } elseif (strlen($pw1) < 10) {
                $error = 'Password must be at least 10 characters.';
            } elseif (!preg_match('/[A-Z]/', $pw1)) {
                $error = 'Password must contain at least one uppercase letter.';
            } elseif (!preg_match('/[a-z]/', $pw1)) {
                $error = 'Password must contain at least one lowercase letter.';
            } elseif (!preg_match('/[^A-Za-z0-9]/', $pw1)) {
                $error = 'Password must contain at least one special character.';
            } elseif ($pw1 !== $pw2) {
                $error = 'Passwords do not match.';
            } else {
                $db = getDb();
                $exists = $db->prepare('SELECT 1 FROM users WHERE email = ?');
                $exists->execute([$formEmail]);
                if ($exists->fetch()) {
                    $error = 'An account with that email already exists.';
                } else {
                    $preStmt = $db->prepare('SELECT level FROM preapproved WHERE email = ? COLLATE NOCASE');
                    $preStmt->execute([$formEmail]);
                    $preRow = $preStmt->fetch(PDO::FETCH_ASSOC);
                    $level = $preRow ? $preRow['level'] : 'user';
                    $autoApprove = (bool)$preRow;

                    $hash = password_hash($pw1, PASSWORD_BCRYPT);
                    $db->prepare('INSERT INTO users (email, passwd256, level, name, approved, verified) VALUES (?, ?, ?, ?, ?, 0)')
                       ->execute([$formEmail, $hash, $level, $formName, $autoApprove ? 1 : 0]);

                    $guid = bin2hex(random_bytes(16));
                    $db->prepare('INSERT INTO failed_logins (ip, counter, epoch, email) VALUES (?, 0, ?, ?) ON CONFLICT(ip) DO UPDATE SET counter=0, epoch=?, email=?')
                       ->execute([$guid, time(), $formEmail, time(), $formEmail]);
                    $domain = getVanityDomain();
                    $verifyUrl = "https://{$domain}/dns1/index.php?action=verify&guid={$guid}";
                    $body = "<h2>Verify Your Email</h2><p>Hi " . htmlspecialchars($formName) . ",</p>"
                          . "<p>Click below to verify your DNS1 account:</p>"
                          . "<p><a href=\"{$verifyUrl}\">{$verifyUrl}</a></p>";
                    sendEmail($formEmail, 'Verify - DNS1', $body);
                    $success = $autoApprove
                        ? 'Account created! Check your email to verify.'
                        : 'Account created! Check your email to verify. An administrator must also approve your account before you can sign in.';
                }
            }
        }
    }
    authPageHead('Sign Up');
    ?>
    <div class="login-box"><h2>Sign Up</h2>
    <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <?php if ($success): ?><div class="success"><?= htmlspecialchars($success) ?></div>
        <a href="index.php?action=login" class="btn" style="display:inline-block;">Go to Login</a>
    <?php else: ?>
    <form method="POST" action="index.php?action=signup">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
        <div class="form-group"><label>Name</label><input type="text" name="name" value="<?= htmlspecialchars($formName) ?>" required></div>
        <div class="form-group"><label>Email</label><input type="email" name="email" value="<?= htmlspecialchars($formEmail) ?>" required></div>
        <div class="form-group"><label>Password</label><input type="password" name="password" required><div class="pw-rules">Min 10 chars, 1 uppercase, 1 lowercase, 1 special</div></div>
        <div class="form-group"><label>Confirm Password</label><input type="password" name="password2" required></div>
        <div class="btn-group"><button type="submit" class="btn">Sign Up</button><a href="index.php?action=login" class="btn btn-cancel">Cancel</a></div>
    </form>
    <div style="margin-top:15px;font-size:0.9em;"><a href="index.php?action=login">Already have an account? Log in</a></div>
    <?php endif; ?>
    </div></body></html>
    <?php exit;
}

/* ---- Verify Email ---- */
if (isset($_GET['action']) && $_GET['action'] === 'verify') {
    $guid = $_GET['guid'] ?? '';
    $db = getDb();
    $cutoff = time() - 86400;
    $db->prepare('DELETE FROM failed_logins WHERE counter = 0 AND epoch <= ?')->execute([$cutoff]);
    $stmt = $db->prepare('SELECT email FROM failed_logins WHERE ip = ? AND counter = 0');
    $stmt->execute([$guid]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        $db->prepare('UPDATE users SET verified = 1 WHERE email = ?')->execute([$row['email']]);
        $db->prepare('DELETE FROM failed_logins WHERE ip = ?')->execute([$guid]);
        $msg = 'Email verified! You can now log in.';
    } else {
        $msg = 'Invalid or expired verification link.';
    }
    authPageHead('Verify');
    ?>
    <div class="login-box"><h2>Email Verification</h2><p><?= htmlspecialchars($msg) ?></p>
    <a href="index.php?action=login" class="btn" style="display:inline-block;width:auto;padding:10px 30px;">Go to Login</a>
    </div></body></html>
    <?php exit;
}

/* ---- Resend Verification ---- */
if (isset($_GET['action']) && $_GET['action'] === 'resend') {
    $msg = ''; $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {
            $error = 'Invalid request.';
        } else {
            $email = trim($_POST['email'] ?? '');
            $db = getDb();
            $stmt = $db->prepare('SELECT name, verified FROM users WHERE email = ?');
            $stmt->execute([$email]);
            $u = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($u && !$u['verified']) {
                $guid = bin2hex(random_bytes(16));
                $db->prepare('INSERT INTO failed_logins (ip, counter, epoch, email) VALUES (?, 0, ?, ?) ON CONFLICT(ip) DO UPDATE SET counter=0, epoch=?, email=?')
                   ->execute([$guid, time(), $email, time(), $email]);
                $domain = getVanityDomain();
                $verifyUrl = "https://{$domain}/dns1/index.php?action=verify&guid={$guid}";
                sendEmail($email, 'Verify - DNS1',
                    "<h2>Verify Your Email</h2><p><a href=\"{$verifyUrl}\">{$verifyUrl}</a></p>");
            }
            /* Same reply either way, so this cannot be used to discover which
             * addresses have accounts. */
            $msg = 'If that address needs verification, a new email is on its way.';
        }
    }
    authPageHead('Resend Verification');
    ?>
    <div class="login-box"><h2>Resend Verification</h2>
    <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <?php if ($msg): ?><div class="success"><?= htmlspecialchars($msg) ?></div><?php endif; ?>
    <form method="POST" action="index.php?action=resend">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
        <div class="form-group"><label>Email</label><input type="email" name="email" value="<?= htmlspecialchars($_GET['email'] ?? '') ?>" required></div>
        <div class="btn-group"><button type="submit" class="btn">Send</button><a href="index.php?action=login" class="btn btn-cancel">Back</a></div>
    </form>
    </div></body></html>
    <?php exit;
}

/* ---- Forgot Password ---- */
if (isset($_GET['action']) && $_GET['action'] === 'forgot') {
    $msg = ''; $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {
            $error = 'Invalid request.';
        } else {
            $email = trim($_POST['email'] ?? '');
            $db = getDb();
            $stmt = $db->prepare('SELECT email FROM users WHERE email = ?');
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                $guid = bin2hex(random_bytes(16));
                $db->prepare('INSERT INTO failed_logins (ip, counter, epoch, email) VALUES (?, 0, ?, ?) ON CONFLICT(ip) DO UPDATE SET counter=0, epoch=?, email=?')
                   ->execute([$guid, time(), $email, time(), $email]);
                $domain = getVanityDomain();
                $resetUrl = "https://{$domain}/dns1/index.php?action=reset&guid={$guid}";
                sendEmail($email, 'Password Reset - DNS1',
                    "<h2>Password Reset</h2><p>Click below to choose a new password:</p><p><a href=\"{$resetUrl}\">{$resetUrl}</a></p>");
            }
            $msg = 'If that account exists, a reset link is on its way.';
        }
    }
    authPageHead('Forgot Password');
    ?>
    <div class="login-box"><h2>Forgot Password</h2>
    <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <?php if ($msg): ?><div class="success"><?= htmlspecialchars($msg) ?></div><?php endif; ?>
    <form method="POST" action="index.php?action=forgot">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
        <div class="form-group"><label>Email</label><input type="email" name="email" required></div>
        <div class="btn-group"><button type="submit" class="btn">Send Reset Link</button><a href="index.php?action=login" class="btn btn-cancel">Back</a></div>
    </form>
    </div></body></html>
    <?php exit;
}

/* ---- Reset Password ---- */
if (isset($_GET['action']) && $_GET['action'] === 'reset') {
    $guid = $_GET['guid'] ?? ($_POST['guid'] ?? '');
    $error = '';
    $db = getDb();
    $cutoff = time() - 86400;
    $db->prepare('DELETE FROM failed_logins WHERE counter = 0 AND epoch <= ?')->execute([$cutoff]);
    $stmt = $db->prepare('SELECT email FROM failed_logins WHERE ip = ? AND counter = 0');
    $stmt->execute([$guid]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        authPageHead('Reset Password');
        echo '<div class="login-box"><h2>Reset Password</h2><div class="error">Invalid or expired reset link.</div>'
           . '<a href="index.php?action=forgot" class="btn" style="display:inline-block;">Request a new link</a></div></body></html>';
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {
            $error = 'Invalid request.';
        } else {
            $pw1 = $_POST['password'] ?? '';
            $pw2 = $_POST['password2'] ?? '';
            if (strlen($pw1) < 10)                      $error = 'Password must be at least 10 characters.';
            elseif (!preg_match('/[A-Z]/', $pw1))       $error = 'Password must contain at least one uppercase letter.';
            elseif (!preg_match('/[a-z]/', $pw1))       $error = 'Password must contain at least one lowercase letter.';
            elseif (!preg_match('/[^A-Za-z0-9]/', $pw1)) $error = 'Password must contain at least one special character.';
            elseif ($pw1 !== $pw2)                      $error = 'Passwords do not match.';
            else {
                $db->prepare('UPDATE users SET passwd256 = ?, verified = 1 WHERE email = ?')
                   ->execute([password_hash($pw1, PASSWORD_BCRYPT), $row['email']]);
                $db->prepare('DELETE FROM failed_logins WHERE ip = ?')->execute([$guid]);
                header('Location: index.php?action=login&msg=password_reset');
                exit;
            }
        }
    }
    authPageHead('Reset Password');
    ?>
    <div class="login-box"><h2>Reset Password</h2>
    <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <form method="POST" action="index.php?action=reset">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
        <input type="hidden" name="guid" value="<?= htmlspecialchars($guid) ?>">
        <div class="form-group"><label>New Password</label><input type="password" name="password" required><div class="pw-rules">Min 10 chars, 1 uppercase, 1 lowercase, 1 special</div></div>
        <div class="form-group"><label>Confirm Password</label><input type="password" name="password2" required></div>
        <div class="btn-group"><button type="submit" class="btn">Set Password</button><a href="index.php?action=login" class="btn btn-cancel">Cancel</a></div>
    </form>
    </div></body></html>
    <?php exit;
}

/* ---- Login ---- */
if (isset($_GET['action']) && $_GET['action'] === 'login') {
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {
            $error = 'Invalid request.';
        } else {
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $db = getDb();
            $cutoff = time() - 3600;
            $db->prepare('DELETE FROM failed_logins WHERE counter > 0 AND epoch <= ?')->execute([$cutoff]);
            $stmt = $db->prepare('SELECT counter FROM failed_logins WHERE ip = ? AND counter > 0');
            $stmt->execute([$ip]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $counter = $row ? (int)$row['counter'] : 0;

            if ($counter >= 3) {
                $error = 'Too many failed attempts. Try again later.';
            } else {
                $username = trim($_POST['username'] ?? '');
                $password = $_POST['password'] ?? '';
                $authStmt = $db->prepare('SELECT level, passwd256, approved, verified FROM users WHERE email = ?');
                $authStmt->execute([$username]);
                $authRow = $authStmt->fetch(PDO::FETCH_ASSOC);
                $authenticated = false;
                if ($authRow) {
                    $stored = $authRow['passwd256'];
                    if (str_starts_with($stored, '$2y$') || str_starts_with($stored, '$2b$')) {
                        $authenticated = password_verify($password, $stored);
                    } else {
                        $authenticated = hash_equals($stored, hash('sha256', $password));
                        if ($authenticated) {
                            $db->prepare('UPDATE users SET passwd256 = ? WHERE email = ?')
                               ->execute([password_hash($password, PASSWORD_BCRYPT), $username]);
                        }
                    }
                }
                if ($authenticated) {
                    if (!$authRow['verified']) {
                        $error = 'Email not verified. Check your inbox, or <a href="index.php?action=resend&email='
                               . urlencode($username) . '">resend the verification email</a>.';
                    } elseif (!$authRow['approved']) {
                        $error = 'Account not yet approved.';
                    } else {
                        $db->prepare('DELETE FROM failed_logins WHERE ip = ? AND counter > 0')->execute([$ip]);
                        session_regenerate_id(true);
                        $_SESSION['logged_in'] = true;
                        $_SESSION['username']  = $username;
                        $_SESSION['level']     = $authRow['level'] ?? 'user';
                        header('Location: index.php?page=whitelist');
                        exit;
                    }
                } else {
                    $db->prepare('INSERT INTO failed_logins (ip, counter, epoch) VALUES (?, 1, ?) ON CONFLICT(ip) DO UPDATE SET counter = counter + 1, epoch = ?')
                       ->execute([$ip, time(), time()]);
                    $error = 'Invalid email or password.';
                }
            }
        }
    }
    authPageHead('Login');
    ?>
    <div class="login-box"><h2>DNS1 Login</h2>
    <?php if (($_GET['msg'] ?? '') === 'password_reset'): ?><div class="success">Password reset. Please log in.</div><?php endif; ?>
    <?php if ($error): ?><div class="error"><?= $error /* may contain a resend link */ ?></div><?php endif; ?>
    <form method="POST" action="index.php?action=login">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
        <div class="form-group"><label>Email</label><input type="email" name="username" required autofocus></div>
        <div class="form-group"><label>Password</label><input type="password" name="password" required></div>
        <div class="btn-group"><button type="submit" class="btn">Login</button><a href="index.php" class="btn btn-cancel">Cancel</a></div>
    </form>
    <div style="display:flex;justify-content:space-between;margin-top:15px;font-size:0.9em;">
        <a href="index.php?action=signup">Sign Up</a>
        <a href="index.php?action=forgot">Forgot Password</a>
    </div>
    <div style="text-align:center;margin-top:10px;font-size:0.85em;">
        <a href="index.php?action=resend">Resend verification email</a>
    </div>
    </div></body></html>
    <?php exit;
}

/* ---- Profile ---- */
if (isset($_GET['action']) && $_GET['action'] === 'profile') {
    requireLogin();
    $db = getDb();
    $stmt = $db->prepare('SELECT email, name, level, approved, verified FROM users WHERE email = ?');
    $stmt->execute([$_SESSION['username']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    $success = ''; $error = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {
            $error = 'Invalid request.';
        } else {
            $newName = trim($_POST['name'] ?? '');
            $db->prepare('UPDATE users SET name = ? WHERE email = ?')->execute([$newName, $_SESSION['username']]);
            $user['name'] = $newName;
            $success = 'Profile saved.';
        }
    }
    if (($_GET['msg'] ?? '') === 'password_changed') $success = 'Password changed successfully.';

    authPageHead('Profile');
    ?>
    <div class="login-box"><h2>Profile</h2>
    <?php if ($success): ?><div class="success"><?= htmlspecialchars($success) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <form method="POST" action="index.php?action=profile">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
        <div class="form-group"><label>Email</label><input type="email" value="<?= htmlspecialchars($user['email']) ?>" readonly></div>
        <div class="form-group"><label>Name</label><input type="text" name="name" value="<?= htmlspecialchars($user['name'] ?? '') ?>"></div>
        <div class="form-group"><label>Access Level</label><input type="text" value="<?= htmlspecialchars($user['level'] ?? 'user') ?>" readonly></div>
        <div class="btn-group"><button type="submit" class="btn">Save</button><a href="index.php?page=whitelist" class="btn btn-cancel">Back</a></div>
    </form>
    <div style="margin-top:15px;font-size:0.9em;"><a href="index.php?action=changepw">Change Password</a></div>
    </div></body></html>
    <?php exit;
}

/* ---- Change Password ---- */
if (isset($_GET['action']) && $_GET['action'] === 'changepw') {
    requireLogin();
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {
            $error = 'Invalid request.';
        } else {
            $cur = $_POST['current'] ?? '';
            $pw1 = $_POST['password'] ?? '';
            $pw2 = $_POST['password2'] ?? '';
            $db = getDb();
            $stmt = $db->prepare('SELECT passwd256 FROM users WHERE email = ?');
            $stmt->execute([$_SESSION['username']]);
            $u = $stmt->fetch(PDO::FETCH_ASSOC);
            $ok = $u && (str_starts_with($u['passwd256'], '$2y$') || str_starts_with($u['passwd256'], '$2b$'))
                ? password_verify($cur, $u['passwd256'])
                : ($u && hash_equals($u['passwd256'], hash('sha256', $cur)));

            if (!$ok)                                    $error = 'Current password is incorrect.';
            elseif (strlen($pw1) < 10)                   $error = 'Password must be at least 10 characters.';
            elseif (!preg_match('/[A-Z]/', $pw1))        $error = 'Password must contain at least one uppercase letter.';
            elseif (!preg_match('/[a-z]/', $pw1))        $error = 'Password must contain at least one lowercase letter.';
            elseif (!preg_match('/[^A-Za-z0-9]/', $pw1)) $error = 'Password must contain at least one special character.';
            elseif ($pw1 !== $pw2)                       $error = 'Passwords do not match.';
            else {
                $db->prepare('UPDATE users SET passwd256 = ? WHERE email = ?')
                   ->execute([password_hash($pw1, PASSWORD_BCRYPT), $_SESSION['username']]);
                header('Location: index.php?action=profile&msg=password_changed');
                exit;
            }
        }
    }
    authPageHead('Change Password');
    ?>
    <div class="login-box"><h2>Change Password</h2>
    <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <form method="POST" action="index.php?action=changepw">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
        <div class="form-group"><label>Current Password</label><input type="password" name="current" required></div>
        <div class="form-group"><label>New Password</label><input type="password" name="password" required><div class="pw-rules">Min 10 chars, 1 uppercase, 1 lowercase, 1 special</div></div>
        <div class="form-group"><label>Confirm New Password</label><input type="password" name="password2" required></div>
        <div class="btn-group"><button type="submit" class="btn">Change</button><a href="index.php?action=profile" class="btn btn-cancel">Cancel</a></div>
    </form>
    </div></body></html>
    <?php exit;
}
