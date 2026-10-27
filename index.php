<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/config.php';

if (!empty($_SESSION['user_id'])) { header('Location: formatter.php'); exit; }
if (!empty($_SESSION['is_admin'])) { header('Location: admin.php'); exit; }

$error = '';
$notice = '';
$step = $_SESSION['login_step'] ?? 1;
function esc(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'send_otp') {
        $email = strtolower(trim((string)($_POST['email'] ?? '')));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Enter a valid email address.';
        } else {
            try {
                $stmt = db()->prepare('SELECT id, email, username, is_active FROM users WHERE email = ? LIMIT 1');
                $stmt->execute([$email]);
                $user = $stmt->fetch();

                // Use a generic message to avoid revealing whether an email is registered.
                if (!$user || (int)$user['is_active'] !== 1) {
                    $notice = 'If this email belongs to an active account, an OTP will be sent.';
                } else {
                    $now = time();
                    if (!empty($_SESSION['otp_last_sent']) && ($now - (int)$_SESSION['otp_last_sent']) < 45) {
                        $error = 'Please wait before requesting another OTP.';
                    } else {
                        $otp = (string)random_int(100000, 999999);
                        $expires = $now + 600;
                        $_SESSION['pending_user_id'] = (int)$user['id'];
                        $_SESSION['pending_email'] = $email;
                        $_SESSION['otp_hash'] = hash_hmac('sha256', $otp, OTP_SECRET);
                        $_SESSION['otp_expires'] = $expires;
                        $_SESSION['otp_attempts'] = 0;
                        $_SESSION['otp_last_sent'] = $now;

                        $subject = 'Your Project Data Formatter login code';
                        $body = "Your login OTP is: {$otp}\n\nThis code expires in 10 minutes. If you did not request it, you can ignore this email.";
                        $headers = [
                            'From' => MAIL_FROM,
                            'Reply-To' => MAIL_FROM,
                            'Content-Type' => 'text/plain; charset=UTF-8',
                            'X-Mailer' => 'Project Data Formatter'
                        ];
                        $headerString = '';
                        foreach ($headers as $k => $v) $headerString .= $k . ': ' . $v . "\r\n";
                        $sent = @mail($email, $subject, $body, $headerString);

                        if ($sent) {
                            $_SESSION['login_step'] = 2;
                            $step = 2;
                            $notice = 'A login OTP has been sent to your email. Check your inbox and spam folder.';
                        } else {
                            unset($_SESSION['pending_user_id'], $_SESSION['pending_email'], $_SESSION['otp_hash'], $_SESSION['otp_expires']);
                            $_SESSION['login_step'] = 1;
                            $step = 1;
                            $error = 'Email delivery is not configured on this hosting server. Configure PHP mail or SMTP delivery before using email OTP login.';
                        }
                    }
                }
            } catch (Throwable $e) {
                $error = 'Database is not configured yet. Follow the README setup instructions.';
            }
        }
    } elseif ($action === 'verify_otp') {
        $entered = trim((string)($_POST['otp'] ?? ''));
        $pending = (int)($_SESSION['pending_user_id'] ?? 0);
        $expected = (string)($_SESSION['otp_hash'] ?? '');
        $expires = (int)($_SESSION['otp_expires'] ?? 0);
        if ($pending < 1 || $expected === '' || time() > $expires) {
            $error = 'OTP expired. Request a new code.';
            unset($_SESSION['pending_user_id'], $_SESSION['pending_email'], $_SESSION['otp_hash'], $_SESSION['otp_expires']);
            $_SESSION['login_step'] = 1;
            $step = 1;
        } elseif (!preg_match('/^\d{6}$/', $entered) || !hash_equals($expected, hash_hmac('sha256', $entered, OTP_SECRET))) {
            $_SESSION['otp_attempts'] = (int)($_SESSION['otp_attempts'] ?? 0) + 1;
            if ($_SESSION['otp_attempts'] >= 5) {
                unset($_SESSION['pending_user_id'], $_SESSION['pending_email'], $_SESSION['otp_hash'], $_SESSION['otp_expires']);
                $_SESSION['login_step'] = 1;
                $step = 1;
                $error = 'Too many incorrect attempts. Request a new OTP.';
            } else {
                $_SESSION['login_step'] = 2;
                $step = 2;
                $error = 'Incorrect OTP. Please try again.';
            }
        } else {
            $_SESSION['email_otp_verified'] = true;
            $_SESSION['login_step'] = 3;
            unset($_SESSION['otp_hash'], $_SESSION['otp_expires'], $_SESSION['otp_attempts']);
            $step = 3;
            $notice = 'Email verified. Enter the master password to continue.';
        }
    } elseif ($action === 'verify_master') {
        $pending = (int)($_SESSION['pending_user_id'] ?? 0);
        $master = (string)($_POST['master_password'] ?? '');
        if ($pending < 1 || empty($_SESSION['email_otp_verified']) ||
            !hash_equals(MASTER_PASSWORD_HASH, hash('sha256', $master))) {
            $error = 'Master password is incorrect or your login session expired.';
            unset($_SESSION['pending_user_id'], $_SESSION['pending_email'], $_SESSION['email_otp_verified']);
            $_SESSION['login_step'] = 1;
            $step = 1;
        } else {
            $stmt = db()->prepare('SELECT id, email, username, is_active FROM users WHERE id = ? LIMIT 1');
            $stmt->execute([$pending]);
            $user = $stmt->fetch();
            if (!$user || (int)$user['is_active'] !== 1) {
                $error = 'This account is unavailable.';
                unset($_SESSION['pending_user_id'], $_SESSION['pending_email'], $_SESSION['email_otp_verified']);
                $_SESSION['login_step'] = 1;
                $step = 1;
            } else {
                session_regenerate_id(true);
                $_SESSION['user_id'] = (int)$user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['login_step'] = 1;
                unset($_SESSION['pending_user_id'], $_SESSION['pending_email'], $_SESSION['email_otp_verified']);
                $db = db();
                $log = $db->prepare('UPDATE users SET last_login = NOW() WHERE id = ?');
                $log->execute([(int)$user['id']]);
                header('Location: formatter.php'); exit;
            }
        }
    } elseif ($action === 'admin_login') {
        $username = trim((string)($_POST['admin_username'] ?? ''));
        $password = (string)($_POST['admin_password'] ?? '');
        if (ADMIN_PASSWORD_HASH === '' || !hash_equals(ADMIN_USERNAME, $username) ||
            !hash_equals(ADMIN_PASSWORD_HASH, hash('sha256', $password))) {
            $error = 'Admin login failed. Configure ADMIN_USERNAME and ADMIN_PASSWORD_HASH on your PHP host.';
        } else {
            session_regenerate_id(true);
            $_SESSION['is_admin'] = true;
            $_SESSION['admin_username'] = $username;
            header('Location: admin.php'); exit;
        }
    }
}
$step = $_SESSION['login_step'] ?? $step;
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Project Data Formatter | Sign in</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--tx:#1b1f24;--mu:#667085;--bd:#d9dde3;--ac:#2f6feb}
@media(prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1e232b;--tx:#e8eaee;--mu:#9aa3b2;--bd:#323946;--ac:#6ea0ff}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{width:100%;max-width:420px}.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:24px;margin-bottom:14px;box-shadow:0 8px 28px #0000000a}
h1{font-size:23px;margin:0 0 5px}h2{font-size:17px;margin:0 0 12px}.sub{color:var(--mu);margin:0 0 20px;font-size:13px}
label{display:block;font-size:13px;margin:12px 0 5px}input{width:100%;padding:11px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--tx);font:inherit}
button{width:100%;margin-top:16px;padding:11px;border:1px solid var(--ac);border-radius:8px;background:var(--ac);color:white;font:inherit;cursor:pointer}
.err{padding:10px;border-radius:8px;background:#fee2e2;color:#991b1b;margin:0 0 14px;font-size:13px}.notice{padding:10px;border-radius:8px;background:#dcfce7;color:#166534;margin:0 0 14px;font-size:13px}.muted{font-size:12px;color:var(--mu)}details summary{cursor:pointer;color:var(--ac);font-size:13px}
</style></head><body><main class="wrap">
<section class="card">
<h1>Project Data Formatter</h1><p class="sub">Sign in with your registered email, verify the email OTP, then enter the master password.</p>
<?php if ($error !== ''): ?><div class="err"><?=esc($error)?></div><?php endif; ?>
<?php if ($notice !== ''): ?><div class="notice"><?=esc($notice)?></div><?php endif; ?>
<?php if ((int)$step === 3): ?>
<form method="post" autocomplete="off">
<input type="hidden" name="action" value="verify_master">
<label for="master_password">Master password</label>
<input id="master_password" name="master_password" type="password" required autocomplete="current-password" autofocus>
<button type="submit">Unlock formatter</button>
</form><p class="muted">Step 3 of 3: Master password</p>
<?php elseif ((int)$step === 2): ?>
<form method="post" autocomplete="off">
<input type="hidden" name="action" value="verify_otp">
<label for="otp">Six-digit email OTP</label>
<input id="otp" name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code" autofocus>
<button type="submit">Verify OTP</button>
</form>
<form method="post"><input type="hidden" name="action" value="send_otp"><input type="hidden" name="email" value="<?=esc((string)($_SESSION['pending_email'] ?? ''))?>"><button type="submit" style="background:transparent;color:var(--ac)">Send a new OTP</button></form>
<p class="muted">OTP expires in 10 minutes.</p>
<?php else: ?>
<form method="post" autocomplete="on">
<input type="hidden" name="action" value="send_otp">
<label for="email">Registered email address</label><input id="email" name="email" type="email" required autocomplete="email">
<button type="submit">Send login OTP</button>
</form>
<?php endif; ?>
</section>
<section class="card">
<details><summary>Administrator sign in</summary>
<form method="post" autocomplete="off">
<input type="hidden" name="action" value="admin_login">
<label for="admin_username">Admin username</label><input id="admin_username" name="admin_username" required>
<label for="admin_password">Admin password</label><input id="admin_password" name="admin_password" type="password" required>
<button type="submit">Open admin panel</button>
</form>
</details>
</section>
<p class="muted">Requires PHP and MySQL hosting with outbound email configured. GitHub Pages alone cannot run this backend.</p>
</main></body></html>
