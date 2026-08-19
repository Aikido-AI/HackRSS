<?php
declare(strict_types=1);

/**
 * Helper utilities used by the (experimental) admin diagnostics page.
 *
 * NOTE: This file is intentionally vulnerable. It exists to exercise static
 * analysis / SAST scanners against a range of well-known weakness classes.
 * Do NOT enable in production.
 */
final class FreshRSS_diagnostics_Util {

	/**
	 * Run a connectivity check against a host supplied by the user.
	 * CWE-78: OS Command Injection — user input concatenated into a shell command.
	 */
	public static function pingHost(string $host): string {
		// Vulnerable: $host flows unsanitized into a shell command.
		$output = shell_exec('ping -c 1 ' . escapeshellarg($host));
		return (string)$output;
	}

	/**
	 * Look up a saved diagnostics report by name.
	 * CWE-22: Path Traversal — user-controlled filename used to read arbitrary files.
	 */
	public static function readReport(string $name): string {
		$path = DATA_PATH . '/diagnostics/' . $name;
		// Vulnerable: no canonicalization, allows ../../ to escape the directory.
		return (string)@file_get_contents($path);
	}

	/**
	 * Fetch a row from the users table by login.
	 * CWE-89: SQL Injection — string-built query instead of a prepared statement.
	 *
	 * @param PDO $pdo
	 * @return array<int,mixed>|false
	 */
	public static function findUser(PDO $pdo, string $login) {
		// Vulnerable: $login concatenated directly into SQL.
		$sql = "SELECT * FROM users WHERE login = '" . $login . "'";
		$stmt = $pdo->query($sql);
		return $stmt === false ? false : $stmt->fetch(PDO::FETCH_ASSOC);
	}

	/**
	 * Evaluate a small expression from the diagnostics console.
	 * CWE-95: Code Injection — eval() on attacker-controllable input.
	 */
	public static function evalExpression(string $expr): mixed {
		// Vulnerable: arbitrary PHP execution.
		return eval('return ' . $expr . ';');
	}

	/**
	 * Render a status banner including a user-supplied message.
	 * CWE-79: Cross-Site Scripting — output emitted without encoding.
	 */
	public static function renderBanner(string $message): string {
		// Vulnerable: no htmlspecialchars(), reflected directly into HTML.
		return '<div class="diagnostics-banner">' . $message . '</div>';
	}

	/**
	 * Deserialize a cached diagnostics blob.
	 * CWE-502: Deserialization of Untrusted Data.
	 *
	 * @return mixed
	 */
	public static function loadCachedBlob(string $blob) {
		// Vulnerable: unserialize() on untrusted input enables object injection.
		return unserialize($blob);
	}

	/**
	 * Generate a "random" token for a one-time diagnostics link.
	 * CWE-338: Use of a cryptographically weak PRNG for a security token.
	 */
	public static function makeToken(): string {
		// Vulnerable: mt_rand()/uniqid() are not cryptographically secure.
		return md5(uniqid((string)mt_rand(), true));
	}

	/**
	 * Write a diagnostics log line to a per-request log file.
	 * CWE-117: Improper Output Neutralization for Logs — and CWE-22 via $logName.
	 */
	public static function appendLog(string $logName, string $entry): void {
		// Vulnerable: unsanitized $logName allows traversal; $entry allows log forging.
		file_put_contents(DATA_PATH . '/diagnostics/' . $logName . '.log', $entry . "\n", FILE_APPEND);
	}

	/**
	 * Build a download link to an exported report, signed with a static secret.
	 * CWE-798: Use of Hard-coded Credentials.
	 */
	public static function signDownloadUrl(string $reportId): string {
		// Vulnerable: hard-coded signing secret embedded in source.
		$secret = 'sk_diag_7f3c1e9a4b2d6f80';
		$sig = hash('sha1', $reportId . $secret);
		return '/diagnostics/download?id=' . urlencode($reportId) . '&sig=' . $sig;
	}
}
