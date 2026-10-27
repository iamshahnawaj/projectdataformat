<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/config.php';
if (empty($_SESSION['is_admin'])) { header('Location: index.php'); exit; }
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
$error = ''; $notice = '';
function esc(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); }
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        $error = 'Invalid session token. Refresh and try again.';
    } else {
        $action = $_POST['action'] ?? '';
        try {
            if ($action === 'add_user') {
                $email = strtolower(trim((string)($_POST['email'] ?? '')));
                $username = trim((string)($_POST['username'] ?? ''));
                if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^[A-Za-z0-9_.-]{3,40}$/', $username)) {
                    $error = 'Enter a valid email and a username of 3 to 40 characters (letters, numbers, dot, underscore, hyphen).';
                } else {
                    $stmt = db()->prepare('INSERT INTO users (email, username, is_active, created_at) VALUES (?, ?, 1, NOW())');
                    $stmt->execute([$email, $username]);
                    $notice = 'User created. Share the registered email, username, and master password with the user securely.';
                }
            } elseif ($action === 'toggle_user') {
                $id = (int)($_POST['user_id'] ?? 0);
                $stmt = db()->prepare('UPDATE users SET is_active = IF(is_active=1,0,1) WHERE id = ?');
                $stmt->execute([$id]);
                $notice = 'User status updated.';
            }
        } catch (PDOException $e) {
            $error = ($e->getCode() === '23000') ? 'That email or username is already registered.' : 'Database error. Check database setup and table schema.';
        } catch (Throwable $e) { $error = 'Unable to complete this action.'; }
    }
}
try { $users = db()->query('SELECT id,email,username,is_active,created_at,last_login FROM users ORDER BY id DESC')->fetchAll(); }
catch (Throwable $e) { $users = []; $error = $error ?: 'Database is not configured. Import schema.sql and set database environment variables.'; }
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Panel | Project Data Formatter</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--tx:#1b1f24;--mu:#667085;--bd:#d9dde3;--ac:#2f6feb}*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,sans-serif;padding:24px}
main{max-width:1050px;margin:auto}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:18px;margin:16px 0}h1{margin:0;font-size:24px}h2{font-size:17px;margin:0 0 12px}
input,button{font:inherit;padding:9px 11px;border:1px solid var(--bd);border-radius:8px}input{background:transparent;color:inherit}button{cursor:pointer;background:var(--ac);color:white;border-color:var(--ac)}a{color:var(--ac)}
form.add{display:flex;gap:10px;flex-wrap:wrap}form.add input{flex:1;min-width:180px}
.msg{padding:10px;border-radius:8px;margin:12px 0;background:#dcfce7;color:#166534}.err{padding:10px;border-radius:8px;margin:12px 0;background:#fee2e2;color:#991b1b}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--bd);vertical-align:top}th{font-size:12px;color:var(--mu)}.small{font-size:12px;color:var(--mu)}.status{font-weight:600}
@media(max-width:700px){body{padding:12px}.tablewrap{overflow-x:auto}table{min-width:680px}}
</style></head><body><main>
<div class="top"><div><h1>Admin Panel</h1><div class="small">Signed in as <?=esc((string)($_SESSION['admin_username'] ?? 'admin'))?></div></div><a href="logout.php">Log out</a></div>
<?php if($error): ?><div class="err"><?=esc($error)?></div><?php endif; ?>
<?php if($notice): ?><div class="msg"><?=esc($notice)?></div><?php endif; ?>
<section class="card"><h2>Create user</h2><form class="add" method="post">
<input type="hidden" name="csrf" value="<?=esc($_SESSION['csrf'])?>"><input type="hidden" name="action" value="add_user">
<input type="email" name="email" placeholder="User email address" required>
<input name="username" placeholder="Username (3-40 chars)" pattern="[A-Za-z0-9_.-]{3,40}" required>
<button type="submit">Add user</button></form>
<p class="small">The master password is shared for all active users. User access can be disabled below.</p></section>
<section class="card"><h2>User database (<?=count($users)?>)</h2><div class="tablewrap"><table><thead><tr><th>ID</th><th>Email</th><th>Username</th><th>Status</th><th>Created</th><th>Last login</th><th>Action</th></tr></thead><tbody>
<?php foreach($users as $u): ?><tr><td><?= (int)$u['id'] ?></td><td><?=esc($u['email'])?></td><td><?=esc($u['username'])?></td><td class="status"><?=((int)$u['is_active']===1)?'Active':'Disabled'?></td><td><?=esc((string)$u['created_at'])?></td><td><?=esc((string)($u['last_login'] ?? 'Never'))?></td><td><form method="post"><input type="hidden" name="csrf" value="<?=esc($_SESSION['csrf'])?>"><input type="hidden" name="action" value="toggle_user"><input type="hidden" name="user_id" value="<?=(int)$u['id']?>"><button type="submit"><?=((int)$u['is_active']===1)?'Disable':'Enable'?></button></form></td></tr><?php endforeach; ?>
<?php if(!$users): ?><tr><td colspan="7">No users yet.</td></tr><?php endif; ?>
</tbody></table></div></section></main></body></html>
