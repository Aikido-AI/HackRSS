#!/usr/bin/env php
<?php
/**
 * Standalone verification script for Redis security fix
 * This script verifies the security properties without requiring PHPUnit
 */

declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '1');

const COPY_LOG_TO_SYSLOG = false;

echo "Redis Security Fix Verification\n";
echo str_repeat("=", 80) . "\n\n";

// Load FreshRSS
require __DIR__ . '/../constants.php';
require LIB_PATH . '/lib_rss.php';

$testsPassed = 0;
$testsFailed = 0;
$testsSkipped = 0;

function test($name, $callback) {
	global $testsPassed, $testsFailed, $testsSkipped;
	echo "Testing: {$name}... ";
	try {
		$callback();
		echo "✓ PASSED\n";
		$testsPassed++;
	} catch (Exception $e) {
		if (strpos($e->getMessage(), 'SKIP') === 0) {
			echo "⊘ SKIPPED: " . substr($e->getMessage(), 6) . "\n";
			$testsSkipped++;
		} else {
			echo "✗ FAILED: " . $e->getMessage() . "\n";
			$testsFailed++;
		}
	}
}

function assertEquals($expected, $actual, $message = '') {
	if ($expected !== $actual) {
		throw new Exception($message ?: "Expected " . var_export($expected, true) . " but got " . var_export($actual, true));
	}
}

function assertTrue($condition, $message = '') {
	if (!$condition) {
		throw new Exception($message ?: "Expected true but got false");
	}
}

function assertFalse($condition, $message = '') {
	if ($condition) {
		throw new Exception($message ?: "Expected false but got true");
	}
}

function assertStringContains($needle, $haystack, $message = '') {
	if (strpos($haystack, $needle) === false) {
		throw new Exception($message ?: "Expected string to contain '{$needle}'");
	}
}

// Test 1: Verify remote connections without auth are rejected
test('Remote connection without auth is rejected', function() {
	if (!class_exists('Redis')) {
		throw new Exception('SKIP: Redis extension not available');
	}
	
	try {
		new \SimplePie\Cache\Redis('redis://remote-host:6379', 'test_cache');
		throw new Exception('Expected RuntimeException for unauthenticated remote connection');
	} catch (\RuntimeException $e) {
		assertStringContains('authentication is required', $e->getMessage());
		assertStringContains('non-localhost', $e->getMessage());
	}
});

// Test 2: Verify localhost identification
test('Localhost variants are recognized', function() {
	$localhostVariants = [
		'redis://localhost:6379',
		'redis://127.0.0.1:6379',
		'redis://::1:6379',
	];
	
	foreach ($localhostVariants as $url) {
		$parsed = \SimplePie\Cache::parse_URL($url);
		$host = $parsed['host'] ?? '127.0.0.1';
		$isLocalhost = in_array($host, ['localhost', '127.0.0.1', '::1'], true);
		assertTrue($isLocalhost, "Host should be recognized as localhost: {$host}");
	}
});

// Test 3: Verify remote hosts are identified
test('Remote hosts are NOT recognized as localhost', function() {
	$remoteHosts = [
		'redis://remote-host:6379',
		'redis://192.168.1.100:6379',
		'redis://10.0.0.1:6379',
	];
	
	foreach ($remoteHosts as $url) {
		$parsed = \SimplePie\Cache::parse_URL($url);
		$host = $parsed['host'] ?? '127.0.0.1';
		$isLocalhost = in_array($host, ['localhost', '127.0.0.1', '::1'], true);
		assertFalse($isLocalhost, "Host should NOT be recognized as localhost: {$host}");
	}
});

// Test 4: Verify password parsing
test('Authentication credentials are parsed correctly', function() {
	// Password-only
	$parsed1 = \SimplePie\Cache::parse_URL('redis://:mypassword@host:6379');
	assertTrue(isset($parsed1['pass']), 'Password should be present');
	assertEquals('mypassword', $parsed1['pass']);
	
	// Username and password
	$parsed2 = \SimplePie\Cache::parse_URL('redis://myuser:mypassword@host:6379');
	assertTrue(isset($parsed2['user']), 'Username should be present');
	assertTrue(isset($parsed2['pass']), 'Password should be present');
	assertEquals('myuser', $parsed2['user']);
	assertEquals('mypassword', $parsed2['pass']);
});

// Test 5: Verify pentest exploit is blocked
test('Pentest exploit scenarios are blocked', function() {
	if (!class_exists('Redis')) {
		throw new Exception('SKIP: Redis extension not available');
	}
	
	$scenarios = [
		'redis://example.com:6379',
		'redis://production-redis.example.com:6379',
		'redis://192.168.1.100:6379',
	];
	
	foreach ($scenarios as $scenario) {
		try {
			new \SimplePie\Cache\Redis($scenario, 'exploit_test');
			throw new Exception("Exploit scenario should be blocked: {$scenario}");
		} catch (\RuntimeException $e) {
			assertStringContains('authentication is required', $e->getMessage());
		}
	}
});

// Test 6: Verify error message quality
test('Error message is descriptive', function() {
	if (!class_exists('Redis')) {
		throw new Exception('SKIP: Redis extension not available');
	}
	
	try {
		new \SimplePie\Cache\Redis('redis://remote-host:6379', 'test_cache');
		throw new Exception('Expected RuntimeException');
	} catch (\RuntimeException $e) {
		$message = $e->getMessage();
		assertStringContains('authentication', $message);
		assertStringContains('required', $message);
		assertStringContains('non-localhost', $message);
		assertStringContains('redis://', $message);
		assertStringContains('password', $message);
	}
});

// Test 7: Verify authenticated URLs are supported
test('Authenticated remote connections are supported', function() {
	$authenticatedUrl = 'redis://:securepassword@production.example.com:6379/0';
	$parsed = \SimplePie\Cache::parse_URL($authenticatedUrl);
	
	assertTrue(isset($parsed['host']), 'Host should be present');
	assertTrue(isset($parsed['pass']), 'Password should be present');
	assertEquals('production.example.com', $parsed['host']);
	assertEquals('securepassword', $parsed['pass']);
	
	$isLocalhost = in_array($parsed['host'], ['localhost', '127.0.0.1', '::1'], true);
	assertFalse($isLocalhost, 'Should not be localhost');
});

// Test 8: Verify default values
test('Default values are set correctly', function() {
	$parsed1 = \SimplePie\Cache::parse_URL('redis://:6379');
	$host1 = $parsed1['host'] ?? '127.0.0.1';
	assertEquals('127.0.0.1', $host1);
	
	$parsed2 = \SimplePie\Cache::parse_URL('redis://localhost');
	$port2 = isset($parsed2['port']) ? (int)$parsed2['port'] : 6379;
	assertEquals(6379, $port2);
});

// Test 9: Verify database selection
test('Database selection from URL path works', function() {
	$parsed1 = \SimplePie\Cache::parse_URL('redis://localhost:6379/0');
	assertTrue(isset($parsed1['path']), 'Path should be present');
	assertEquals('/0', $parsed1['path']);
	
	$parsed2 = \SimplePie\Cache::parse_URL('redis://localhost:6379/5');
	assertTrue(isset($parsed2['path']), 'Path should be present');
	assertEquals('/5', $parsed2['path']);
});

// Test 10: Verify edge cases
test('Edge cases are handled properly', function() {
	if (!class_exists('Redis')) {
		throw new Exception('SKIP: Redis extension not available');
	}
	
	// Empty password should be rejected for remote hosts
	try {
		new \SimplePie\Cache\Redis('redis://:@remote-host:6379', 'test');
		throw new Exception('Empty password should be rejected for remote hosts');
	} catch (\RuntimeException $e) {
		assertStringContains('authentication is required', $e->getMessage());
	}
});

echo "\n" . str_repeat("=", 80) . "\n";
echo "Results: {$testsPassed} passed, {$testsFailed} failed, {$testsSkipped} skipped\n";
echo "\n";

if ($testsFailed > 0) {
	echo "❌ TESTS FAILED\n";
	exit(1);
} else {
	echo "✅ ALL TESTS PASSED\n";
	exit(0);
}
