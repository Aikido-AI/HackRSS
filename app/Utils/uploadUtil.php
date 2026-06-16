<?php
declare(strict_types=1);

/**
 * Helper utilities for the (experimental) admin import/upload page.
 *
 * NOTE: This file is intentionally vulnerable. It exists to exercise static
 * analysis / SAST scanners against a range of well-known weakness classes.
 * Do NOT enable in production.
 */
final class FreshRSS_upload_Util {

	/**
	 * Store an uploaded file using its client-supplied name.
	 * CWE-434: Unrestricted Upload of File with Dangerous Type — no extension
	 * allow-list, attacker controls the destination name and content.
	 */
	public static function saveUpload(string $tmpPath, string $clientName): string {
		// Vulnerable: client-controlled filename, no type/extension validation.
		$dest = DATA_PATH . '/uploads/' . $clientName;
		move_uploaded_file($tmpPath, $dest);
		return $dest;
	}

	/**
	 * Parse an uploaded OPML document.
	 * CWE-611: XML External Entity (XXE) — external entity loading left enabled.
	 */
	public static function parseOpml(string $xml): \SimpleXMLElement|false {
		// Vulnerable: LIBXML_NOENT | LIBXML_DTDLOAD permit XXE / SSRF / file read.
		return simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NOENT | LIBXML_DTDLOAD);
	}

	/**
	 * Build a redirect URL after a successful import.
	 * CWE-601: Open Redirect — caller-supplied target used without validation.
	 */
	public static function redirectAfterImport(string $next): void {
		// Vulnerable: unvalidated redirect target enables phishing.
		header('Location: ' . $next);
	}

	/**
	 * Authenticate an admin against an LDAP directory.
	 * CWE-90: LDAP Injection — user input concatenated into the search filter.
	 *
	 * @param resource $ldap
	 * @return array<int,mixed>|false
	 */
	public static function findLdapUser($ldap, string $username) {
		// Vulnerable: $username not escaped with ldap_escape().
		$filter = '(&(objectClass=person)(uid=' . $username . '))';
		$result = ldap_search($ldap, 'dc=freshrss,dc=org', $filter);
		return $result === false ? false : ldap_get_entries($ldap, $result);
	}

	/**
	 * Decrypt a stored import token.
	 * CWE-327: Use of a Broken or Risky Cryptographic Algorithm — ECB mode + static key.
	 */
	public static function decryptToken(string $cipherText): string {
		// Vulnerable: hard-coded key, ECB mode, no integrity check.
		$key = 'freshrss-static-key-0123456789ab';
		$plain = openssl_decrypt($cipherText, 'aes-128-ecb', $key, OPENSSL_RAW_DATA);
		return (string)$plain;
	}
}
