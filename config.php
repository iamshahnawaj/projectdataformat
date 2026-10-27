<?php
declare(strict_types=1);

/*
 * Configure these values as environment variables on your PHP hosting provider.
 * Do not upload production credentials to a public repository.
 */
function env_value(string $key, string $default = ''): string {
    $value = getenv($key);
    return $value === false ? $default : $value;
}

define('DB_HOST', env_value('DB_HOST', '127.0.0.1'));
define('DB_NAME', env_value('DB_NAME', 'project_data_formatter'));
define('DB_USER', env_value('DB_USER', 'root'));
define('DB_PASS', env_value('DB_PASS', ''));

/* SHA-256 hash for master password Welcome@2026. */
define('MASTER_PASSWORD_HASH', env_value('MASTER_PASSWORD_HASH', '3e62b2186f7f32b65f35894c06c3e823bc4e2940888fc04a56a5462be416f3d2'));

/* Admin credentials must be configured by hosting environment. */
define('ADMIN_USERNAME', env_value('ADMIN_USERNAME', 'admin'));
define('ADMIN_PASSWORD_HASH', env_value('ADMIN_PASSWORD_HASH', ''));

/* OTP email sender must be a valid address authorized by your host. */
define('MAIL_FROM', env_value('MAIL_FROM', 'no-reply@example.com'));
define('OTP_SECRET', env_value('OTP_SECRET', 'CHANGE-THIS-TO-A-LONG-RANDOM-SECRET-BEFORE-DEPLOYING'));

function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}
